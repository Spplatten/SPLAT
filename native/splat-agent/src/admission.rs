//! Native admission validator (thesis variant B3N): the half that decides, with no syscalls.
//!
//! Before a lease's workload is spawned, still under MAP_WRITES, the daemon asks the kernel two
//! questions: are the programs deciding each lease hook this daemon's own, reading the maps it
//! writes; and do those maps hold exactly the lease that was approved. `admission_collect.rs` reads
//! the raw facts as root. Everything here judges them, so every rule runs under `cargo test`.
//!
//! What the kernel should hold is derived here independently of the lease writer: device numbers
//! from statx's separate major and minor, keys decoded by byte offset, IPv4 octets and ports by
//! hand. A writer that is consistently wrong then disagrees with this file instead of agreeing with
//! itself. A test scans this file for the writer's encoders so that independence cannot lapse.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

// Keys and values are decoded as the program lays them out on the machine it runs on. Every
// supported guest is x86_64; a big-endian build would misread every key, so it does not build.
#[cfg(not(target_endian = "little"))]
compile_error!("the admission validator decodes BPF map bytes as little-endian");

pub const VALIDATOR_ID: &str = "splat-native/1";

// uapi/linux/bpf.h, fixed by the kernel ABI.
pub const BPF_LINK_TYPE_TRACING: u32 = 2;
pub const BPF_LSM_MAC: u32 = 27;
pub const BPF_PROG_TYPE_LSM: u32 = 29;
const BPF_MAP_TYPE_HASH: u32 = 1;

/// Why v1 cannot admit a lease that asks for scratch execution: the child writes that grant after
/// it mounts the overlay, during spawn, so before spawn there is nothing to observe.
pub const SCRATCH_UNOBSERVABLE: &str =
    "the scratch-execution grant is written by the child after its overlay mount, so it cannot be observed before spawn";

/// `--admission-validator`. Off by default until a root run at a milestone has measured it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum AdmissionValidator {
    /// Not consulted.
    Off,
    /// Checked and recorded; the workload runs whatever the verdict.
    Audit,
    /// Checked and recorded; anything but an admission refuses the lease.
    Enforce,
}

impl AdmissionValidator {
    pub fn as_str(self) -> &'static str {
        match self {
            AdmissionValidator::Off => "off",
            AdmissionValidator::Audit => "audit",
            AdmissionValidator::Enforce => "enforce",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Hook {
    BprmCheck,
    FileOpen,
    SocketConnect,
    SocketSendmsg,
    PtraceAccess,
    TaskKill,
    TaskSetsched,
    TaskSetnice,
    TaskSetioprio,
    TaskSetrlimit,
    UnixConnect,
    UnixSend,
    SocketCreate,
}

impl Hook {
    /// Every hook the daemon attaches, in the order its programs appear in lease_lsm.bpf.c.
    pub const ALL: [Hook; 13] = [
        Hook::BprmCheck, Hook::FileOpen, Hook::SocketConnect, Hook::SocketSendmsg, Hook::PtraceAccess,
        Hook::TaskKill, Hook::TaskSetsched, Hook::TaskSetnice, Hook::TaskSetioprio, Hook::TaskSetrlimit,
        Hook::UnixConnect, Hook::UnixSend, Hook::SocketCreate,
    ];

    /// The vmlinux function an LSM program on this hook attaches to.
    pub fn btf_func(self) -> &'static str {
        match self {
            Hook::BprmCheck => "bpf_lsm_bprm_check_security",
            Hook::FileOpen => "bpf_lsm_file_open",
            Hook::SocketConnect => "bpf_lsm_socket_connect",
            Hook::SocketSendmsg => "bpf_lsm_socket_sendmsg",
            Hook::PtraceAccess => "bpf_lsm_ptrace_access_check",
            Hook::TaskKill => "bpf_lsm_task_kill",
            Hook::TaskSetsched => "bpf_lsm_task_setscheduler",
            Hook::TaskSetnice => "bpf_lsm_task_setnice",
            Hook::TaskSetioprio => "bpf_lsm_task_setioprio",
            Hook::TaskSetrlimit => "bpf_lsm_task_setrlimit",
            Hook::UnixConnect => "bpf_lsm_unix_stream_connect",
            Hook::UnixSend => "bpf_lsm_unix_may_send",
            Hook::SocketCreate => "bpf_lsm_socket_create",
        }
    }

    /// The maps this hook's program decides with (lease_lsm.bpf.c). It also references the
    /// counters and the ring buffer, which record and decide nothing.
    ///
    /// The six task hooks decide with the lease map alone: the other half of their rule is the
    /// target's cgroup id, read from the task itself, not from any map. That makes the shared lease
    /// map the whole of what can go wrong with them, and check_bindings already refuses a program
    /// that reads a different one - such a program would find every actor unleased and allow all.
    ///
    /// The three local-IPC hooks are the same case: the peer's cgroup id is read from the peer
    /// socket, the netlink rule from the hook's own arguments.
    pub fn decision_roles(self) -> &'static [Role] {
        match self {
            Hook::BprmCheck => &[Role::LeasedCgroups, Role::AllowedExec, Role::ScratchExec],
            Hook::FileOpen => &[Role::LeasedCgroups, Role::Protected],
            Hook::SocketConnect | Hook::SocketSendmsg => &[Role::LeasedCgroups, Role::AllowedIpv4],
            Hook::PtraceAccess | Hook::TaskKill | Hook::TaskSetsched | Hook::TaskSetnice
            | Hook::TaskSetioprio | Hook::TaskSetrlimit | Hook::UnixConnect | Hook::UnixSend
            | Hook::SocketCreate => &[Role::LeasedCgroups],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    LeasedCgroups,
    AllowedExec,
    ScratchExec,
    Protected,
    AllowedIpv4,
}

/// A decision map as lease_lsm.bpf.c declares it. `kernel_name` is the declared name cut to 15
/// bytes, which is all that `bpf_map_info` carries.
#[derive(Debug)]
pub struct MapSpec {
    pub kernel_name: &'static str,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

const fn hash_map(kernel_name: &'static str, key_size: u32, value_size: u32, max_entries: u32) -> MapSpec {
    MapSpec { kernel_name, map_type: BPF_MAP_TYPE_HASH, key_size, value_size, max_entries, map_flags: 0 }
}

// `leased_cgroups` holds `struct lease_state`: the deadline, then an epoch the program never reads.
const LEASED_CGROUPS: MapSpec = hash_map("leased_cgroups", 8, 16, 256);
const ALLOWED_EXEC: MapSpec = hash_map("allowed_exec_in", 24, 1, 8192);
const SCRATCH_EXEC: MapSpec = hash_map("scratch_exec_de", 8, 4, 256);
const PROTECTED: MapSpec = hash_map("protected_inode", 24, 1, 8192);
const ALLOWED_IPV4: MapSpec = hash_map("allowed_connect", 16, 1, 4096);

impl Role {
    pub fn spec(self) -> &'static MapSpec {
        match self {
            Role::LeasedCgroups => &LEASED_CGROUPS,
            Role::AllowedExec => &ALLOWED_EXEC,
            Role::ScratchExec => &SCRATCH_EXEC,
            Role::Protected => &PROTECTED,
            Role::AllowedIpv4 => &ALLOWED_IPV4,
        }
    }
}

/// An inode as the program keys it: the superblock's `s_dev` in the kernel's `(major << 20) | minor`
/// form, and `i_ino`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Ident {
    pub dev: u32,
    pub ino: u64,
}

/// An IPv4 destination: the address as octets in network order, and the port as a number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    pub octets: [u8; 4],
    pub port: u16,
}

impl Serialize for Endpoint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{}:{}", Ipv4Addr::from(self.octets), self.port))
    }
}

/// What this daemon attached, read once at startup from its own held links and loaded object.
#[derive(Clone, Debug)]
pub struct KernelProfile {
    pub expected: Vec<ExpectedProgram>,
    pub vmlinux_btf_obj_id: u32,
    /// The ids of the maps the lease writer writes, by role, read from its own handles.
    pub writer: BTreeMap<Role, u32>,
}

#[derive(Clone, Debug)]
pub struct ExpectedProgram {
    pub hook: Hook,
    pub link_id: u32,
    pub tag: [u8; 8],
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
}

/// Everything the kernel said for one admission, as raw facts. The collector builds it; the tests
/// fabricate it.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub hooks: Vec<HookObs>,
    pub foreign: Vec<ForeignLink>,
    pub maps: BTreeMap<u32, MapLayout>,
    pub passes: Vec<Capture>,
    /// Why there is no capture, when the collector could not take one.
    pub capture_error: Option<String>,
    /// CLOCK_BOOTTIME, read after the last pass.
    pub boot_now_ns: u64,
    /// The inode of the lease's cgroup directory, which is the cgroup id.
    pub cgroup_ino: u64,
}

#[derive(Clone, Debug)]
pub struct HookObs {
    pub hook: Hook,
    pub link_id: u32,
    pub link_type: u32,
    pub attach_type: u32,
    pub prog_id: u32,
    pub target_obj_id: u32,
    pub target_btf_id: u32,
    pub prog_type: u32,
    pub tag: [u8; 8],
    pub attach_btf_obj_id: u32,
    pub attach_btf_id: u32,
    pub map_ids: Vec<u32>,
}

/// An LSM link on one of our targets that is not one of our links.
#[derive(Clone, Debug)]
pub struct ForeignLink {
    pub link_id: u32,
    pub prog_id: u32,
    pub target_obj_id: u32,
    pub target_btf_id: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapLayout {
    pub id: u32,
    pub name: String,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

/// One pass over the decision maps, holding only this lease's entries, keys sorted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Capture {
    pub lease_value: Option<Vec<u8>>,
    pub scratch_value: Option<Vec<u8>>,
    pub exec_keys: Vec<Vec<u8>>,
    pub protected_keys: Vec<Vec<u8>>,
    pub ipv4_keys: Vec<Vec<u8>>,
}

/// The lease as approved: the request's effective lists, after the ceiling applied.
#[derive(Clone, Debug)]
pub struct Approval {
    pub cgroup_id: u64,
    pub exec_paths: Vec<String>,
    pub protected_paths: Vec<String>,
    pub allow_network: bool,
    pub egress_ips: Vec<String>,
    pub egress_ports: Vec<u32>,
    pub duration_seconds: u32,
    pub scratch_exec: bool,
    /// The working directory, when the lease mounts a copy-on-write overlay on it.
    pub cow_workdir: Option<PathBuf>,
    /// A private identity, whose jail generates its own passwd and group.
    pub private_uid: bool,
}

/// Recorded with the verdict, never a reason to refuse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Note {
    /// The writer skips an exec path that does not exist, so no grant is expected; its exec fails.
    AbsentExecPath { path: String },
    /// The program denies every IPv6 destination, so a v6 address fails closed.
    UnenforceableV6 { ip: String },
    /// The jail shows a different file at this path; its exec fails closed.
    ExecPathOnSubmount { path: String },
    /// The jail replaces this file with generated entries, so the host's copy is not what it sees.
    ShadowedBySyntheticIdentity { path: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Divergence {
    // Program identity.
    HookMissing { hook: Hook },
    LinkInactive { hook: Hook },
    ProgramIdentity { hook: Hook, field: &'static str },
    ForeignProgramOnHook { hook: Hook, link_id: u32, prog_id: u32 },
    // Program-to-map binding.
    MapLayout { role: Role, id: u32, field: &'static str },
    MapBinding { role: Role, hook: Hook, map_id: u32, writer_id: Option<u32> },
    RoleAmbiguous { role: Role, hook: Hook, found: usize },
    LeaseMapNotShared,
    // Lease state.
    CgroupIdentity { expected: u64, observed: u64 },
    LeaseMissing,
    LeaseValueMalformed { len: usize },
    LeaseExpired { deadline_ns: u64, boot_now_ns: u64 },
    DeadlineBeyondApproval { deadline_ns: u64, bound_ns: u64 },
    MalformedEntry { role: Role, key_hex: String, reason: &'static str },
    ExecGrantExcess { ident: Ident },
    ExecGrantMissing { path: String, ident: Ident },
    ProtectionMissing { path: String, ident: Ident },
    ProtectionExtra { ident: Ident },
    ProtectionNotEffectiveInJail { path: String },
    EndpointExcess { endpoint: Endpoint },
    EndpointMissing { endpoint: Endpoint },
    ScratchPresentBeforeChild { value_hex: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Admitted,
    Refused(Vec<Divergence>),
    Indeterminate(Vec<String>),
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Verdict::Admitted => "admitted",
            Verdict::Refused(_) => "refused",
            Verdict::Indeterminate(_) => "indeterminate",
        }
    }

    pub fn admitted(&self) -> bool {
        matches!(self, Verdict::Admitted)
    }

    /// One line, for the frame's `decision` and the daemon's log.
    pub fn summary(&self) -> String {
        match self {
            Verdict::Admitted => "the installed lease is the approved one".to_string(),
            Verdict::Refused(found) => format!(
                "{} divergence(s) between the installed and the approved lease; the first: {}",
                found.len(),
                found.first().and_then(|d| serde_json::to_string(d).ok()).unwrap_or_default()
            ),
            Verdict::Indeterminate(why) => format!("the installed lease could not be confirmed: {}", why.join("; ")),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Report {
    pub verdict: Verdict,
    pub notes: Vec<Note>,
    /// The map each role resolved to in the programs, for the record.
    pub bindings: BTreeMap<Role, u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Resolution {
    Found { ident: Ident, fs_magic: u64, mnt_id: u64 },
    Absent,
    Error(String),
}

pub trait IdentityResolver {
    /// The object at `path`, following symlinks as the writer's stat does.
    fn resolve(&self, path: &Path) -> Resolution;
    fn canonical(&self, path: &Path) -> io::Result<PathBuf>;
}

/// The kernel's `MKDEV`. Refuses a major or minor too wide for it instead of truncating, which would
/// silently name another device.
pub fn kernel_mkdev(major: u32, minor: u32) -> Option<u32> {
    (major < 1 << 12 && minor < 1 << 20).then(|| (major << 20) | minor)
}

/// Filesystems whose stat device is the superblock's `s_dev`, the one the program keys on. btrfs
/// reports a per-subvolume anonymous device and overlayfs can report a lower layer's, so a key
/// derived from stat there may not be the one the kernel looks up. The validator will not vouch
/// for those.
const IDENTITY_SAFE_FS: [(u64, &str); 4] =
    [(0xEF53, "ext4"), (0x5846_5342, "xfs"), (0x0102_1994, "tmpfs"), (0x8584_58F6, "ramfs")];

fn identity_safe(fs_magic: u64) -> Result<(), String> {
    if IDENTITY_SAFE_FS.iter().any(|(magic, _)| *magic == fs_magic) {
        Ok(())
    } else {
        Err(format!("filesystem magic {fs_magic:#x} is not one whose stat device is the kernel's s_dev"))
    }
}

fn le_u64(bytes: &[u8]) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(bytes);
    u64::from_le_bytes(word)
}

fn le_u32(bytes: &[u8]) -> u32 {
    let mut word = [0u8; 4];
    word.copy_from_slice(bytes);
    u32::from_le_bytes(word)
}

/// `struct lease_inode_key`: cgroup id, ino, dev, then four bytes of padding the program always
/// zeroes. A key with nonzero padding can never match a lookup, so it grants or protects nothing.
pub fn decode_inode_key(raw: &[u8], cgid: u64) -> Result<Ident, &'static str> {
    if raw.len() != 24 {
        return Err("key length");
    }
    if le_u64(&raw[0..8]) != cgid {
        return Err("foreign cgroup");
    }
    if raw[20..24] != [0u8; 4] {
        return Err("nonzero pad");
    }
    Ok(Ident { ino: le_u64(&raw[8..16]), dev: le_u32(&raw[16..20]) })
}

/// `struct lease_ipv4_key`: cgroup id, the address as `sin_addr` holds it (network order), the
/// port as `sin_port` holds it (big-endian), then zero padding.
pub fn decode_ipv4_key(raw: &[u8], cgid: u64) -> Result<Endpoint, &'static str> {
    if raw.len() != 16 {
        return Err("key length");
    }
    if le_u64(&raw[0..8]) != cgid {
        return Err("foreign cgroup");
    }
    if raw[14..16] != [0u8; 2] {
        return Err("nonzero pad");
    }
    Ok(Endpoint { octets: [raw[8], raw[9], raw[10], raw[11]], port: u16::from_be_bytes([raw[12], raw[13]]) })
}

/// `struct lease_state`: the deadline on CLOCK_BOOTTIME, then the epoch, which the program ignores.
pub fn decode_deadline(raw: &[u8]) -> Result<u64, &'static str> {
    if raw.len() != 16 {
        return Err("value length");
    }
    Ok(le_u64(&raw[0..8]))
}

/// A scratch grant's value: the overlay superblock's `s_dev`.
pub fn decode_scratch(raw: &[u8]) -> Result<u32, &'static str> {
    if raw.len() != 4 {
        return Err("value length");
    }
    Ok(le_u32(raw))
}

/// One full `get_next_key` walk of a hash map, cut to this lease's keys and sorted. None when the
/// walk met a key twice: another lease's teardown deleted the key it stood on, the kernel restarted
/// it from the head, and what it skipped is unknown.
pub fn lease_keys(walk: &[Vec<u8>], cgid: u64) -> Option<Vec<Vec<u8>>> {
    let prefix = cgid.to_le_bytes();
    let mut seen = BTreeSet::new();
    let mut kept = Vec::new();
    for key in walk {
        if !seen.insert(key.as_slice()) {
            return None;
        }
        if key.len() >= 8 && key[..8] == prefix {
            kept.push(key.clone());
        }
    }
    kept.sort();
    Some(kept)
}

/// Are the programs on our hooks the ones this daemon attached at startup, and is nobody
/// else's program on the same hooks? A later program on the same trampoline receives our return
/// value and may return 0; whether that can override our denial is not established, so a foreign
/// program is refused rather than reasoned about.
pub fn check_programs(p: &KernelProfile, s: &Snapshot) -> Vec<Divergence> {
    let mut found = Vec::new();
    for want in &p.expected {
        let hook = want.hook;
        let Some(o) = s.hooks.iter().find(|o| o.hook == hook) else {
            found.push(Divergence::HookMissing { hook });
            continue;
        };
        if o.prog_id == 0 {
            found.push(Divergence::LinkInactive { hook });
            continue;
        }
        let checks = [
            ("linkId", o.link_id == want.link_id),
            ("linkType", o.link_type == BPF_LINK_TYPE_TRACING),
            ("attachType", o.attach_type == BPF_LSM_MAC),
            ("type", o.prog_type == BPF_PROG_TYPE_LSM),
            ("tag", o.tag == want.tag),
            (
                "attachTarget",
                o.target_obj_id == p.vmlinux_btf_obj_id
                    && o.target_btf_id == want.attach_btf_id
                    && o.attach_btf_obj_id == want.attach_btf_obj_id
                    && o.attach_btf_id == want.attach_btf_id,
            ),
        ];
        for (field, ok) in checks {
            if !ok {
                found.push(Divergence::ProgramIdentity { hook, field });
            }
        }
    }
    let ours: BTreeSet<u32> = p.expected.iter().map(|e| e.link_id).collect();
    for f in s.foreign.iter().filter(|f| !ours.contains(&f.link_id)) {
        let target = p.expected.iter()
            .find(|e| f.target_obj_id == p.vmlinux_btf_obj_id && f.target_btf_id == e.attach_btf_id);
        if let Some(e) = target {
            found.push(Divergence::ForeignProgramOnHook { hook: e.hook, link_id: f.link_id, prog_id: f.prog_id });
        }
    }
    found
}

#[derive(Debug, Default)]
pub struct Bindings {
    pub ids: BTreeMap<Role, u32>,
    pub divergences: Vec<Divergence>,
    /// Map ids a program references whose layout could not be read.
    pub unreadable: Vec<u32>,
}

/// Does each program decide with the maps the writer writes, laid out as declared, and do all of them
/// share one lease map? A program reading another `leased_cgroups` finds no lease there and allows
/// everything. The decoy-map research fault is caught here: the writer's exec map is not the one
/// the exec program reads.
pub fn check_bindings(p: &KernelProfile, s: &Snapshot) -> Bindings {
    let mut b = Bindings::default();
    // Every program shares the lease map, so one layout fault would otherwise be reported once per program.
    let push = |found: &mut Vec<Divergence>, d: Divergence| {
        if !found.contains(&d) {
            found.push(d);
        }
    };
    let mut lease_maps = BTreeSet::new();
    for o in s.hooks.iter().filter(|o| o.prog_id != 0) {
        for id in &o.map_ids {
            if !s.maps.contains_key(id) && !b.unreadable.contains(id) {
                b.unreadable.push(*id);
            }
        }
        for &role in o.hook.decision_roles() {
            let spec = role.spec();
            let named: Vec<&MapLayout> = o.map_ids.iter()
                .filter_map(|id| s.maps.get(id))
                .filter(|m| m.name == spec.kernel_name)
                .collect();
            let [m] = named.as_slice() else {
                push(&mut b.divergences, Divergence::RoleAmbiguous { role, hook: o.hook, found: named.len() });
                continue;
            };
            let fields = [
                ("type", m.map_type == spec.map_type),
                ("keySize", m.key_size == spec.key_size),
                ("valueSize", m.value_size == spec.value_size),
                ("maxEntries", m.max_entries == spec.max_entries),
                ("flags", m.map_flags == spec.map_flags),
            ];
            for (field, ok) in fields {
                if !ok {
                    push(&mut b.divergences, Divergence::MapLayout { role, id: m.id, field });
                }
            }
            let writer_id = p.writer.get(&role).copied();
            if writer_id != Some(m.id) {
                push(&mut b.divergences, Divergence::MapBinding { role, hook: o.hook, map_id: m.id, writer_id });
            }
            if role == Role::LeasedCgroups {
                lease_maps.insert(m.id);
            }
            b.ids.entry(role).or_insert(m.id);
        }
    }
    if lease_maps.len() > 1 {
        b.divergences.push(Divergence::LeaseMapNotShared);
    }
    b
}

/// The capture to judge: at least two passes, the last two identical.
pub fn stable_capture(s: &Snapshot) -> Result<&Capture, String> {
    if let Some(why) = &s.capture_error {
        return Err(why.clone());
    }
    match s.passes.as_slice() {
        [.., a, b] if a == b => Ok(b),
        [.., _, _] => Err("the last two passes over the policy maps disagree".to_string()),
        _ => Err("one pass over the policy maps is not a capture; two must agree".to_string()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseView {
    Absent,
    Malformed,
    Live { deadline_ns: u64 },
    Expired { deadline_ns: u64 },
}

#[derive(Clone, Debug)]
pub struct Interpretation {
    pub lease: LeaseView,
    pub exec: BTreeSet<Ident>,
    pub scratch_dev: Option<u32>,
    pub protected: BTreeSet<Ident>,
    pub ipv4: BTreeSet<Endpoint>,
}

fn decode_all<T: Ord>(
    keys: &[Vec<u8>],
    role: Role,
    decode: impl Fn(&[u8]) -> Result<T, &'static str>,
    found: &mut Vec<Divergence>,
) -> BTreeSet<T> {
    let mut set = BTreeSet::new();
    for key in keys {
        match decode(key) {
            Ok(value) => {
                set.insert(value);
            }
            Err(reason) => found.push(Divergence::MalformedEntry { role, key_hex: crate::auth::hex(key), reason }),
        }
    }
    set
}

/// What the program will decide for this cgroup, given these bytes. Malformed entries are inert,
/// as they are to the program, and reported.
pub fn interpret(c: &Capture, cgid: u64, boot_now_ns: u64) -> (Interpretation, Vec<Divergence>) {
    let mut found = Vec::new();
    let lease = match c.lease_value.as_deref() {
        None => LeaseView::Absent,
        Some(raw) => match decode_deadline(raw) {
            // `>=`, as the program compares: a lease is over AT its deadline.
            Ok(deadline_ns) if boot_now_ns >= deadline_ns => LeaseView::Expired { deadline_ns },
            Ok(deadline_ns) => LeaseView::Live { deadline_ns },
            Err(_) => {
                found.push(Divergence::LeaseValueMalformed { len: raw.len() });
                LeaseView::Malformed
            }
        },
    };
    let scratch_dev = match c.scratch_value.as_deref().map(decode_scratch) {
        None => None,
        Some(Ok(dev)) => Some(dev),
        Some(Err(reason)) => {
            found.push(Divergence::MalformedEntry {
                role: Role::ScratchExec,
                key_hex: crate::auth::hex(&cgid.to_le_bytes()),
                reason,
            });
            None
        }
    };
    let exec = decode_all(&c.exec_keys, Role::AllowedExec, |k| decode_inode_key(k, cgid), &mut found);
    let protected = decode_all(&c.protected_keys, Role::Protected, |k| decode_inode_key(k, cgid), &mut found);
    let ipv4 = decode_all(&c.ipv4_keys, Role::AllowedIpv4, |k| decode_ipv4_key(k, cgid), &mut found);
    (Interpretation { lease, exec, scratch_dev, protected, ipv4 }, found)
}

/// What the kernel should hold for this approval, derived without the writer.
#[derive(Clone, Debug, Default)]
pub struct Expected {
    /// Each expected exec grant, with the first path that named it.
    pub exec: BTreeMap<Ident, String>,
    pub protected: BTreeMap<Ident, String>,
    pub ipv4: BTreeSet<Endpoint>,
    pub max_duration_ns: u64,
    pub notes: Vec<Note>,
    /// Refusals that come from the approval itself, not from the maps.
    pub refusals: Vec<Divergence>,
}

/// Resolves every approved path and address as the program will meet it. Anything it cannot
/// resolve with confidence makes the result indeterminate (Err), never a guess.
pub fn expect(a: &Approval, r: &dyn IdentityResolver) -> Result<Expected, Vec<String>> {
    let mut e = Expected::default();
    let mut unknown = Vec::new();

    // The jail binds each real system directory without its submounts (MS_BIND, no MS_REC). A file
    // on a submount below one is therefore not the file the jail shows at that path. A symlinked
    // directory (merged /usr) is recreated as a link, so it is not a bind of its own.
    let mut bound: Vec<(&Path, u64)> = Vec::new();
    for dir in crate::jail::SYSTEM_DIRS {
        let dir = Path::new(dir);
        if !r.canonical(dir).is_ok_and(|c| c.as_path() == dir) {
            continue;
        }
        match r.resolve(dir) {
            Resolution::Found { mnt_id, .. } => bound.push((dir, mnt_id)),
            Resolution::Absent => {}
            Resolution::Error(why) => unknown.push(format!("jail directory {}: {why}", dir.display())),
        }
    }
    let submounted = |path: &str, mnt_id: u64| -> bool {
        let Ok(canonical) = r.canonical(Path::new(path)) else { return false };
        bound.iter().any(|(dir, dir_mnt)| canonical.starts_with(dir) && *dir_mnt != mnt_id)
    };

    for path in &a.exec_paths {
        match r.resolve(Path::new(path)) {
            Resolution::Found { ident, fs_magic, mnt_id } => {
                if let Err(why) = identity_safe(fs_magic) {
                    unknown.push(format!("exec path {path}: {why}"));
                    continue;
                }
                e.exec.entry(ident).or_insert_with(|| path.clone());
                if submounted(path, mnt_id) {
                    e.notes.push(Note::ExecPathOnSubmount { path: path.clone() });
                }
            }
            Resolution::Absent => e.notes.push(Note::AbsentExecPath { path: path.clone() }),
            Resolution::Error(why) => unknown.push(format!("exec path {path}: {why}")),
        }
    }

    for path in &a.protected_paths {
        match r.resolve(Path::new(path)) {
            Resolution::Found { ident, fs_magic, mnt_id } => {
                if let Err(why) = identity_safe(fs_magic) {
                    unknown.push(format!("protected path {path}: {why}"));
                    continue;
                }
                e.protected.entry(ident).or_insert_with(|| path.clone());
                // The kernel protects the host's file; the jail shows the workload a different one,
                // unprotected. The deny-list fails open there, so this refuses.
                if submounted(path, mnt_id) {
                    e.refusals.push(Divergence::ProtectionNotEffectiveInJail { path: path.clone() });
                }
                let generated = r.canonical(Path::new(path))
                    .is_ok_and(|c| c == Path::new("/etc/passwd") || c == Path::new("/etc/group"));
                if a.private_uid && generated {
                    e.notes.push(Note::ShadowedBySyntheticIdentity { path: path.clone() });
                }
            }
            // The writer refuses a protected path it cannot resolve, so one gone now moved under us.
            Resolution::Absent => unknown.push(format!("protected path {path} no longer exists")),
            Resolution::Error(why) => unknown.push(format!("protected path {path}: {why}")),
        }
    }

    // Overlay inodes do not keep host (dev, ino), so a policy path under a copy-on-write working
    // directory names an inode the workload never meets.
    if let Some(workdir) = &a.cow_workdir {
        match r.canonical(workdir) {
            Ok(root) => {
                for path in a.exec_paths.iter().chain(&a.protected_paths) {
                    if r.canonical(Path::new(path)).is_ok_and(|c| c.starts_with(&root)) {
                        unknown.push(format!("{path} lies under the copy-on-write working directory"));
                    }
                }
            }
            Err(err) => unknown.push(format!("copy-on-write working directory {}: {err}", workdir.display())),
        }
    }

    if a.allow_network {
        // Stricter than the writer's parser, which also takes leading zeros and a '+': those
        // forms are indeterminate here, not guessed at.
        let mut addresses = Vec::new();
        for ip in &a.egress_ips {
            if let Ok(v4) = ip.parse::<Ipv4Addr>() {
                addresses.push(v4.octets());
            } else if ip.parse::<Ipv6Addr>().is_ok() {
                e.notes.push(Note::UnenforceableV6 { ip: ip.clone() });
            } else {
                unknown.push(format!("egress address {ip:?} is neither IPv4 nor IPv6"));
            }
        }
        let mut ports = Vec::new();
        for &port in &a.egress_ports {
            match u16::try_from(port) {
                Ok(port) => ports.push(port),
                Err(_) => unknown.push(format!("egress port {port} does not fit in 16 bits")),
            }
        }
        for octets in &addresses {
            for &port in &ports {
                e.ipv4.insert(Endpoint { octets: *octets, port });
            }
        }
    }

    let seconds = a.duration_seconds.clamp(crate::deadline::MIN_LEASE_SECONDS, crate::deadline::MAX_LEASE_SECONDS);
    e.max_duration_ns = u64::from(seconds) * 1_000_000_000;

    if unknown.is_empty() { Ok(e) } else { Err(unknown) }
}

/// The approval against the interpretation, in both directions. Exact sets: a missing grant or an
/// extra protection fails closed, but still shows the writer is wrong, which is what this checks.
pub fn compare(e: &Expected, i: &Interpretation, boot_now_ns: u64) -> Vec<Divergence> {
    let mut found = Vec::new();
    match i.lease {
        LeaseView::Absent => found.push(Divergence::LeaseMissing),
        LeaseView::Malformed => {}
        LeaseView::Expired { deadline_ns } => found.push(Divergence::LeaseExpired { deadline_ns, boot_now_ns }),
        // The writer set its registration time plus the clamped duration, and registration came
        // before now, so a correct deadline can never exceed now plus that duration.
        LeaseView::Live { deadline_ns } => {
            let bound_ns = boot_now_ns.saturating_add(e.max_duration_ns);
            if deadline_ns > bound_ns {
                found.push(Divergence::DeadlineBeyondApproval { deadline_ns, bound_ns });
            }
        }
    }
    for ident in i.exec.iter().filter(|x| !e.exec.contains_key(x)) {
        found.push(Divergence::ExecGrantExcess { ident: *ident });
    }
    for (ident, path) in e.exec.iter().filter(|(x, _)| !i.exec.contains(x)) {
        found.push(Divergence::ExecGrantMissing { path: path.clone(), ident: *ident });
    }
    for (ident, path) in e.protected.iter().filter(|(x, _)| !i.protected.contains(x)) {
        found.push(Divergence::ProtectionMissing { path: path.clone(), ident: *ident });
    }
    for ident in i.protected.iter().filter(|x| !e.protected.contains_key(x)) {
        found.push(Divergence::ProtectionExtra { ident: *ident });
    }
    for endpoint in i.ipv4.difference(&e.ipv4) {
        found.push(Divergence::EndpointExcess { endpoint: *endpoint });
    }
    for endpoint in e.ipv4.difference(&i.ipv4) {
        found.push(Divergence::EndpointMissing { endpoint: *endpoint });
    }
    // Before spawn the entry must be absent: the writer refused a stale one, and the child that
    // writes it has not run.
    if let Some(dev) = i.scratch_dev {
        found.push(Divergence::ScratchPresentBeforeChild { value_hex: crate::auth::hex(&dev.to_le_bytes()) });
    }
    found
}

/// Every check, every divergence collected. Indeterminate wins only when nothing was refused.
pub fn validate(p: &KernelProfile, a: &Approval, s: &Snapshot, r: &dyn IdentityResolver) -> Report {
    let mut refused = check_programs(p, s);
    let bindings = check_bindings(p, s);
    refused.extend(bindings.divergences);
    let mut unknown: Vec<String> = bindings.unreadable.iter()
        .map(|id| format!("map {id}, referenced by a lease program, could not be read"))
        .collect();
    if s.cgroup_ino != a.cgroup_id {
        refused.push(Divergence::CgroupIdentity { expected: a.cgroup_id, observed: s.cgroup_ino });
    }
    let mut notes = Vec::new();
    match stable_capture(s) {
        Err(why) => unknown.push(why),
        Ok(capture) => {
            let (interpretation, malformed) = interpret(capture, a.cgroup_id, s.boot_now_ns);
            refused.extend(malformed);
            match expect(a, r) {
                Err(why) => unknown.extend(why),
                Ok(expected) => {
                    refused.extend(expected.refusals.iter().cloned());
                    refused.extend(compare(&expected, &interpretation, s.boot_now_ns));
                    notes = expected.notes;
                }
            }
        }
    }
    if a.scratch_exec {
        unknown.push(SCRATCH_UNOBSERVABLE.to_string());
    }
    let verdict = if !refused.is_empty() {
        Verdict::Refused(refused)
    } else if !unknown.is_empty() {
        Verdict::Indeterminate(unknown)
    } else {
        Verdict::Admitted
    };
    Report { verdict, notes, bindings: bindings.ids }
}

/// A digest of what the kernel said, independent of the order it said it in: the programs, the
/// maps they reference, and the last capture.
pub fn snapshot_sha256(s: &Snapshot) -> String {
    let mut text = String::new();
    let mut hooks: Vec<&HookObs> = s.hooks.iter().collect();
    hooks.sort_by_key(|h| h.hook);
    for h in hooks {
        let mut map_ids = h.map_ids.clone();
        map_ids.sort_unstable();
        let _ = writeln!(text, "hook {:?} link {} prog {} tag {} maps {map_ids:?}",
                         h.hook, h.link_id, h.prog_id, crate::auth::hex(&h.tag));
    }
    let mut foreign: Vec<(u32, u32)> = s.foreign.iter().map(|f| (f.link_id, f.prog_id)).collect();
    foreign.sort_unstable();
    let _ = writeln!(text, "foreign {foreign:?}");
    for m in s.maps.values() {
        let _ = writeln!(text, "map {} {} {} {} {} {} {}",
                         m.id, m.name, m.map_type, m.key_size, m.value_size, m.max_entries, m.map_flags);
    }
    if let Some(c) = s.passes.last() {
        let value = |v: &Option<Vec<u8>>| v.as_deref().map_or_else(|| "-".to_string(), crate::auth::hex);
        let _ = writeln!(text, "lease {}", value(&c.lease_value));
        let _ = writeln!(text, "scratch {}", value(&c.scratch_value));
        for (label, keys) in [("exec", &c.exec_keys), ("protected", &c.protected_keys), ("ipv4", &c.ipv4_keys)] {
            let mut hexed: Vec<String> = keys.iter().map(|k| crate::auth::hex(k)).collect();
            hexed.sort();
            let _ = writeln!(text, "{label} {}", hexed.join(","));
        }
    }
    crate::auth::hex(&Sha256::digest(text.as_bytes()))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramSummary {
    pub hook: Hook,
    pub link_id: u32,
    pub prog_id: u32,
    pub tag: String,
}

pub fn programs(s: &Snapshot) -> Vec<ProgramSummary> {
    s.hooks.iter()
        .map(|h| ProgramSummary { hook: h.hook, link_id: h.link_id, prog_id: h.prog_id, tag: crate::auth::hex(&h.tag) })
        .collect()
}

/// Sizes for the record. The capture costs O(every entry in the three hash maps), not O(this
/// lease), because a hash map has no prefix query, so map occupancy is recorded beside lease size.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub exec: usize,
    pub protected: usize,
    pub ipv4: usize,
    pub map_occupancy: BTreeMap<Role, usize>,
}

/// One admission check, ready to record.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub report: Report,
    pub snapshot_sha256: Option<String>,
    pub programs: Vec<ProgramSummary>,
    pub counts: Counts,
    pub attempts: u32,
    pub collect_ns: u64,
    pub decide_ns: u64,
}

impl Outcome {
    pub fn indeterminate(why: impl Into<String>) -> Self {
        Outcome {
            report: Report { verdict: Verdict::Indeterminate(vec![why.into()]), notes: Vec::new(), bindings: BTreeMap::new() },
            snapshot_sha256: None,
            programs: Vec::new(),
            counts: Counts::default(),
            attempts: 0,
            collect_ns: 0,
            decide_ns: 0,
        }
    }

    /// The ADMISSION frame. Unsigned in v1: the signed outcome text is fixed at 15 fields that
    /// three implementations rebuild, and this does not change it. `source` tells it apart from the
    /// external gate's frame.
    pub fn frame(&self, mode: AdmissionValidator, bpf_source_sha256: &str) -> serde_json::Value {
        let (reasons, indeterminate) = match &self.report.verdict {
            Verdict::Refused(found) => (serde_json::json!(found), serde_json::json!([])),
            Verdict::Indeterminate(why) => (serde_json::json!([]), serde_json::json!(why)),
            Verdict::Admitted => (serde_json::json!([]), serde_json::json!([])),
        };
        serde_json::json!({
            "type": "ADMISSION",
            "source": "native",
            "validator": VALIDATOR_ID,
            "mode": mode.as_str(),
            "enforced": mode == AdmissionValidator::Enforce,
            "admitted": self.report.verdict.admitted(),
            "verdict": self.report.verdict.label(),
            "decision": self.report.verdict.summary(),
            "reasons": reasons,
            "indeterminate": indeterminate,
            "notes": self.report.notes,
            "bpfSourceSha256": bpf_source_sha256,
            "programs": self.programs,
            "mapIds": self.report.bindings,
            "snapshotSha256": self.snapshot_sha256,
            "counts": self.counts,
            "attempts": self.attempts,
            "timingNs": {"collect": self.collect_ns, "decide": self.decide_ns, "total": self.collect_ns.saturating_add(self.decide_ns)},
        })
    }

    /// The EXIT frame's `admission` field: unsigned, mirrored as `effectivePolicySha256` is.
    pub fn exit_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "validator": VALIDATOR_ID,
            "verdict": self.report.verdict.label(),
            "snapshotSha256": self.snapshot_sha256,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const CG: u64 = 4242;
    const SEC: u64 = 1_000_000_000;
    const NOW: u64 = 1_000 * SEC;
    const TAG: [u8; 8] = *b"leasetag";
    const VMLINUX: u32 = 1;
    const COUNTERS: u32 = 90;
    /// 8:32 in the kernel's form: the device the fixtures' root filesystem sits on.
    const SDA2: u32 = (8 << 20) | 32;
    const EXT4: u64 = 0xEF53;
    const SH: Ident = Ident { dev: SDA2, ino: 1001 };
    const SHADOW: Ident = Ident { dev: SDA2, ino: 2002 };
    const SERVER: [u8; 4] = [93, 184, 216, 34];
    const ROLES: [Role; 5] = [Role::LeasedCgroups, Role::AllowedExec, Role::ScratchExec, Role::Protected, Role::AllowedIpv4];
    const HOOKS: [Hook; 13] = Hook::ALL;

    fn id_of(role: Role) -> u32 {
        match role {
            Role::LeasedCgroups => 10,
            Role::AllowedExec => 11,
            Role::ScratchExec => 12,
            Role::Protected => 13,
            Role::AllowedIpv4 => 14,
        }
    }

    fn profile() -> KernelProfile {
        KernelProfile {
            expected: HOOKS.iter().enumerate().map(|(i, &hook)| ExpectedProgram {
                hook,
                link_id: i as u32 + 1,
                tag: TAG,
                attach_btf_obj_id: VMLINUX,
                attach_btf_id: 100 + i as u32,
            }).collect(),
            vmlinux_btf_obj_id: VMLINUX,
            writer: ROLES.iter().map(|&r| (r, id_of(r))).collect(),
        }
    }

    fn hooks() -> Vec<HookObs> {
        HOOKS.iter().enumerate().map(|(i, &hook)| {
            let mut map_ids: Vec<u32> = hook.decision_roles().iter().map(|&r| id_of(r)).collect();
            map_ids.push(COUNTERS);
            map_ids.sort_unstable();
            HookObs {
                hook,
                link_id: i as u32 + 1,
                link_type: BPF_LINK_TYPE_TRACING,
                attach_type: BPF_LSM_MAC,
                prog_id: 40 + i as u32,
                target_obj_id: VMLINUX,
                target_btf_id: 100 + i as u32,
                prog_type: BPF_PROG_TYPE_LSM,
                tag: TAG,
                attach_btf_obj_id: VMLINUX,
                attach_btf_id: 100 + i as u32,
                map_ids,
            }
        }).collect()
    }

    fn layout(role: Role, id: u32) -> MapLayout {
        let s = role.spec();
        MapLayout {
            id,
            name: s.kernel_name.to_string(),
            map_type: s.map_type,
            key_size: s.key_size,
            value_size: s.value_size,
            max_entries: s.max_entries,
            map_flags: s.map_flags,
        }
    }

    fn maps() -> BTreeMap<u32, MapLayout> {
        let mut maps: BTreeMap<u32, MapLayout> = ROLES.iter().map(|&r| (id_of(r), layout(r, id_of(r)))).collect();
        maps.insert(COUNTERS, MapLayout {
            id: COUNTERS, name: "counters".into(), map_type: 2, key_size: 4, value_size: 8, max_entries: 2, map_flags: 0,
        });
        maps
    }

    // Keys built by byte offset, as the program lays them out, never through lease.rs.
    fn inode_key(cgid: u64, dev: u32, ino: u64) -> Vec<u8> {
        let mut key = cgid.to_le_bytes().to_vec();
        key.extend_from_slice(&ino.to_le_bytes());
        key.extend_from_slice(&dev.to_le_bytes());
        key.extend_from_slice(&[0; 4]);
        key
    }

    fn ipv4_key(cgid: u64, octets: [u8; 4], port: u16) -> Vec<u8> {
        let mut key = cgid.to_le_bytes().to_vec();
        key.extend_from_slice(&octets);
        key.extend_from_slice(&port.to_be_bytes());
        key.extend_from_slice(&[0; 2]);
        key
    }

    fn lease_value(deadline_ns: u64) -> Vec<u8> {
        let mut value = deadline_ns.to_le_bytes().to_vec();
        value.extend_from_slice(&1u64.to_le_bytes());
        value
    }

    fn capture() -> Capture {
        Capture {
            lease_value: Some(lease_value(NOW + 30 * SEC)),
            scratch_value: None,
            exec_keys: vec![inode_key(CG, SH.dev, SH.ino)],
            protected_keys: vec![inode_key(CG, SHADOW.dev, SHADOW.ino)],
            ipv4_keys: vec![ipv4_key(CG, SERVER, 443)],
        }
    }

    fn snapshot_of(c: Capture) -> Snapshot {
        Snapshot {
            hooks: hooks(),
            foreign: Vec::new(),
            maps: maps(),
            passes: vec![c.clone(), c],
            capture_error: None,
            boot_now_ns: NOW,
            cgroup_ino: CG,
        }
    }

    fn approval() -> Approval {
        Approval {
            cgroup_id: CG,
            exec_paths: vec!["/bin/sh".into()],
            protected_paths: vec!["/etc/shadow".into()],
            allow_network: true,
            egress_ips: vec!["93.184.216.34".into()],
            egress_ports: vec![443],
            duration_seconds: 30,
            scratch_exec: false,
            cow_workdir: None,
            private_uid: false,
        }
    }

    #[derive(Default)]
    struct FakeResolver {
        found: HashMap<PathBuf, Resolution>,
    }

    impl FakeResolver {
        fn with(mut self, path: &str, r: Resolution) -> Self {
            self.found.insert(path.into(), r);
            self
        }
    }

    impl IdentityResolver for FakeResolver {
        fn resolve(&self, path: &Path) -> Resolution {
            self.found.get(path).cloned().unwrap_or(Resolution::Absent)
        }
        fn canonical(&self, path: &Path) -> io::Result<PathBuf> {
            if self.found.contains_key(path) { Ok(path.to_path_buf()) } else { Err(io::ErrorKind::NotFound.into()) }
        }
    }

    fn found(ident: Ident, mnt_id: u64) -> Resolution {
        Resolution::Found { ident, fs_magic: EXT4, mnt_id }
    }

    fn resolver() -> FakeResolver {
        FakeResolver::default()
            .with("/bin/sh", found(SH, 1))
            .with("/etc/shadow", found(SHADOW, 1))
            .with("/etc", found(Ident { dev: SDA2, ino: 3 }, 1))
            .with("/usr", found(Ident { dev: SDA2, ino: 4 }, 1))
    }

    fn run(s: &Snapshot, a: &Approval, r: &FakeResolver) -> Report {
        validate(&profile(), a, s, r)
    }

    fn check(c: Capture) -> Report {
        run(&snapshot_of(c), &approval(), &resolver())
    }

    fn refusals(report: &Report) -> Vec<Divergence> {
        match &report.verdict {
            Verdict::Refused(found) => found.clone(),
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    fn indeterminate(report: &Report) -> Vec<String> {
        match &report.verdict {
            Verdict::Indeterminate(why) => why.clone(),
            other => panic!("expected an indeterminate verdict, got {other:?}"),
        }
    }

    #[test]
    fn a_correct_lease_admits() {
        let report = check(capture());
        assert_eq!(report.verdict, Verdict::Admitted, "{report:?}");
        assert!(report.notes.is_empty());
        assert_eq!(report.bindings, profile().writer);
    }

    #[test]
    fn the_dev_encoding_defect_is_refused_in_both_directions() {
        // The 2026-09-02 defect: inodes keyed with glibc's st_dev, 0x0820 for 8:32, where the
        // program looks up the kernel's (8 << 20) | 32.
        let glibc = 0x0820;
        let mut c = capture();
        c.exec_keys = vec![inode_key(CG, glibc, SH.ino)];
        c.protected_keys = vec![inode_key(CG, glibc, SHADOW.ino)];
        let found = refusals(&check(c));
        assert!(found.contains(&Divergence::ExecGrantMissing { path: "/bin/sh".into(), ident: SH }));
        assert!(found.contains(&Divergence::ExecGrantExcess { ident: Ident { dev: glibc, ino: SH.ino } }));
        assert!(found.contains(&Divergence::ProtectionMissing { path: "/etc/shadow".into(), ident: SHADOW }));
        assert!(found.contains(&Divergence::ProtectionExtra { ident: Ident { dev: glibc, ino: SHADOW.ino } }));
    }

    #[test]
    fn the_dev_encoding_defect_is_invisible_on_anonymous_devices() {
        // 0:45 encodes identically in both forms, so the same defect admits there. That is the
        // edge of what this check can see, recorded instead of hidden.
        let anon = kernel_mkdev(0, 45).unwrap();
        assert_eq!(anon, 45);
        let tmpfs = |ino| Resolution::Found { ident: Ident { dev: anon, ino }, fs_magic: 0x0102_1994, mnt_id: 1 };
        let r = FakeResolver::default().with("/bin/sh", tmpfs(SH.ino)).with("/etc/shadow", tmpfs(SHADOW.ino));
        let mut c = capture();
        c.exec_keys = vec![inode_key(CG, 45, SH.ino)];
        c.protected_keys = vec![inode_key(CG, 45, SHADOW.ino)];
        assert_eq!(run(&snapshot_of(c), &approval(), &r).verdict, Verdict::Admitted);
    }

    #[test]
    fn kernel_mkdev_matches_the_kernel_formula() {
        assert_eq!(kernel_mkdev(8, 32), Some(0x0080_0020));
        assert_eq!(kernel_mkdev(0, 45), Some(45));
        assert_eq!(kernel_mkdev(259, 1), Some(0x1030_0001));
        assert_eq!(kernel_mkdev(4096, 0), None);
        assert_eq!(kernel_mkdev(0, 1 << 20), None);
    }

    #[test]
    fn the_decoy_exec_map_is_refused_as_a_binding() {
        // --research-fault decoy-exec-map: grants go to a map no program reads, so the exec
        // program's own map is empty.
        let mut p = profile();
        p.writer.insert(Role::AllowedExec, 99);
        let mut c = capture();
        c.exec_keys.clear();
        let found = refusals(&validate(&p, &approval(), &snapshot_of(c), &resolver()));
        assert!(found.contains(&Divergence::MapBinding {
            role: Role::AllowedExec, hook: Hook::BprmCheck, map_id: 11, writer_id: Some(99),
        }));
        assert!(found.contains(&Divergence::ExecGrantMissing { path: "/bin/sh".into(), ident: SH }));
    }

    #[test]
    fn an_excess_exec_grant_is_refused() {
        let mut c = capture();
        c.exec_keys.push(inode_key(CG, SDA2, 7777));
        assert_eq!(refusals(&check(c)), vec![Divergence::ExecGrantExcess { ident: Ident { dev: SDA2, ino: 7777 } }]);
    }

    #[test]
    fn a_missing_exec_grant_is_refused() {
        let mut c = capture();
        c.exec_keys.clear();
        assert_eq!(refusals(&check(c)), vec![Divergence::ExecGrantMissing { path: "/bin/sh".into(), ident: SH }]);
    }

    #[test]
    fn a_missing_protection_is_refused() {
        let mut c = capture();
        c.protected_keys.clear();
        assert_eq!(refusals(&check(c)), vec![Divergence::ProtectionMissing { path: "/etc/shadow".into(), ident: SHADOW }]);
    }

    #[test]
    fn an_extra_protection_is_refused() {
        let mut c = capture();
        c.protected_keys.push(inode_key(CG, SDA2, 3003));
        assert_eq!(refusals(&check(c)), vec![Divergence::ProtectionExtra { ident: Ident { dev: SDA2, ino: 3003 } }]);
    }

    #[test]
    fn a_deadline_beyond_the_approval_is_refused_and_the_bound_itself_admits() {
        let mut c = capture();
        c.lease_value = Some(lease_value(NOW + 30 * SEC + 1));
        assert_eq!(refusals(&check(c)), vec![Divergence::DeadlineBeyondApproval {
            deadline_ns: NOW + 30 * SEC + 1, bound_ns: NOW + 30 * SEC,
        }]);
        let mut c = capture();
        c.lease_value = Some(lease_value(NOW + 30 * SEC));
        assert_eq!(check(c).verdict, Verdict::Admitted);
    }

    #[test]
    fn expiry_includes_equality() {
        for deadline_ns in [NOW, 0] {
            let mut c = capture();
            c.lease_value = Some(lease_value(deadline_ns));
            assert_eq!(refusals(&check(c)), vec![Divergence::LeaseExpired { deadline_ns, boot_now_ns: NOW }]);
        }
    }

    #[test]
    fn a_short_request_is_bounded_by_the_writers_floor() {
        let mut a = approval();
        a.duration_seconds = 1;
        let mut c = capture();
        c.lease_value = Some(lease_value(NOW + 5 * SEC));
        assert_eq!(run(&snapshot_of(c), &a, &resolver()).verdict, Verdict::Admitted);
    }

    #[test]
    fn a_scratch_grant_present_before_the_child_ran_is_refused() {
        let mut c = capture();
        c.scratch_value = Some(0x2au32.to_le_bytes().to_vec());
        assert_eq!(refusals(&check(c)), vec![Divergence::ScratchPresentBeforeChild {
            value_hex: crate::auth::hex(&0x2au32.to_le_bytes()),
        }]);
    }

    #[test]
    fn an_approved_scratch_grant_is_indeterminate_in_v1() {
        let mut a = approval();
        a.scratch_exec = true;
        assert_eq!(indeterminate(&run(&snapshot_of(capture()), &a, &resolver())), vec![SCRATCH_UNOBSERVABLE.to_string()]);
    }

    #[test]
    fn a_foreign_program_on_any_hook_is_refused() {
        for (i, hook) in HOOKS.into_iter().enumerate() {
            let mut s = snapshot_of(capture());
            s.foreign.push(ForeignLink { link_id: 77, prog_id: 78, target_obj_id: VMLINUX, target_btf_id: 100 + i as u32 });
            assert_eq!(refusals(&run(&s, &approval(), &resolver())),
                       vec![Divergence::ForeignProgramOnHook { hook, link_id: 77, prog_id: 78 }]);
        }
    }

    #[test]
    fn a_foreign_program_on_another_hook_is_ignored() {
        let mut s = snapshot_of(capture());
        s.foreign.push(ForeignLink { link_id: 77, prog_id: 78, target_obj_id: VMLINUX, target_btf_id: 555 });
        assert_eq!(run(&s, &approval(), &resolver()).verdict, Verdict::Admitted);
    }

    #[test]
    fn an_inactive_or_missing_hook_is_refused() {
        let mut s = snapshot_of(capture());
        s.hooks[1].prog_id = 0;
        s.hooks.pop();
        let found = refusals(&run(&s, &approval(), &resolver()));
        assert!(found.contains(&Divergence::LinkInactive { hook: Hook::FileOpen }));
        assert!(found.contains(&Divergence::HookMissing { hook: Hook::SocketCreate }));
    }

    #[test]
    fn every_hook_has_its_own_function_and_the_task_and_ipc_hooks_decide_on_the_lease_map_alone() {
        let functions: BTreeSet<&str> = Hook::ALL.iter().map(|h| h.btf_func()).collect();
        assert_eq!(functions.len(), Hook::ALL.len());
        for hook in &Hook::ALL[4..] {
            assert_eq!(hook.decision_roles(), &[Role::LeasedCgroups], "{hook:?}");
        }
    }

    #[test]
    fn a_task_hook_reading_another_lease_map_is_refused() {
        // A signal program that finds no lease there treats every actor as unleased: no isolation.
        let mut s = snapshot_of(capture());
        s.maps.insert(20, layout(Role::LeasedCgroups, 20));
        let task_kill = s.hooks.iter_mut().find(|o| o.hook == Hook::TaskKill).unwrap();
        task_kill.map_ids.retain(|&id| id != 10);
        task_kill.map_ids.push(20);
        let found = refusals(&run(&s, &approval(), &resolver()));
        assert!(found.contains(&Divergence::LeaseMapNotShared));
        assert!(found.contains(&Divergence::MapBinding {
            role: Role::LeasedCgroups, hook: Hook::TaskKill, map_id: 20, writer_id: Some(10),
        }));
    }

    #[test]
    fn each_program_identity_field_is_checked() {
        let cases: [(&str, fn(&mut HookObs)); 6] = [
            ("tag", |h| h.tag = *b"othertag"),
            ("type", |h| h.prog_type = 26),
            ("linkType", |h| h.link_type = 1),
            ("attachType", |h| h.attach_type = 26),
            ("linkId", |h| h.link_id = 9),
            ("attachTarget", |h| h.attach_btf_id = 999),
        ];
        for (field, mutate) in cases {
            let mut s = snapshot_of(capture());
            mutate(&mut s.hooks[0]);
            assert_eq!(refusals(&run(&s, &approval(), &resolver())),
                       vec![Divergence::ProgramIdentity { hook: Hook::BprmCheck, field }], "{field}");
        }
    }

    #[test]
    fn each_map_layout_field_is_checked_once_however_many_programs_share_the_map() {
        let cases: [(&str, fn(&mut MapLayout)); 5] = [
            ("type", |m| m.map_type = 2),
            ("keySize", |m| m.key_size = 9),
            ("valueSize", |m| m.value_size = 8),
            ("maxEntries", |m| m.max_entries = 1),
            ("flags", |m| m.map_flags = 1),
        ];
        for (field, mutate) in cases {
            let mut s = snapshot_of(capture());
            mutate(s.maps.get_mut(&id_of(Role::LeasedCgroups)).unwrap());
            assert_eq!(refusals(&run(&s, &approval(), &resolver())),
                       vec![Divergence::MapLayout { role: Role::LeasedCgroups, id: 10, field }], "{field}");
        }
    }

    #[test]
    fn a_renamed_map_leaves_its_role_unbound() {
        let mut s = snapshot_of(capture());
        s.maps.get_mut(&11).unwrap().name = "decoy".into();
        assert_eq!(refusals(&run(&s, &approval(), &resolver())),
                   vec![Divergence::RoleAmbiguous { role: Role::AllowedExec, hook: Hook::BprmCheck, found: 0 }]);
    }

    #[test]
    fn a_program_reading_another_lease_map_is_refused() {
        // That program finds no lease there and allows everything.
        let mut s = snapshot_of(capture());
        s.maps.insert(20, layout(Role::LeasedCgroups, 20));
        let file_open = &mut s.hooks[1];
        file_open.map_ids.retain(|&id| id != 10);
        file_open.map_ids.push(20);
        let found = refusals(&run(&s, &approval(), &resolver()));
        assert!(found.contains(&Divergence::LeaseMapNotShared));
        assert!(found.contains(&Divergence::MapBinding {
            role: Role::LeasedCgroups, hook: Hook::FileOpen, map_id: 20, writer_id: Some(10),
        }));
    }

    #[test]
    fn two_maps_with_one_role_are_ambiguous() {
        let mut s = snapshot_of(capture());
        s.maps.insert(21, layout(Role::AllowedExec, 21));
        s.hooks[0].map_ids.push(21);
        assert_eq!(refusals(&run(&s, &approval(), &resolver())),
                   vec![Divergence::RoleAmbiguous { role: Role::AllowedExec, hook: Hook::BprmCheck, found: 2 }]);
    }

    #[test]
    fn an_unreadable_referenced_map_is_indeterminate() {
        let mut s = snapshot_of(capture());
        s.maps.remove(&COUNTERS);
        assert_eq!(indeterminate(&run(&s, &approval(), &resolver())).len(), 1);
    }

    #[test]
    fn a_nonzero_inode_pad_is_malformed_and_inert() {
        let mut key = inode_key(CG, SH.dev, SH.ino);
        key[23] = 1;
        let mut c = capture();
        c.exec_keys = vec![key.clone()];
        let found = refusals(&check(c));
        assert!(found.contains(&Divergence::MalformedEntry {
            role: Role::AllowedExec, key_hex: crate::auth::hex(&key), reason: "nonzero pad",
        }));
        assert!(found.contains(&Divergence::ExecGrantMissing { path: "/bin/sh".into(), ident: SH }));
    }

    #[test]
    fn a_nonzero_ipv4_pad_is_malformed_and_inert() {
        let mut key = ipv4_key(CG, SERVER, 443);
        key[15] = 1;
        let mut c = capture();
        c.ipv4_keys = vec![key.clone()];
        let found = refusals(&check(c));
        assert!(found.contains(&Divergence::MalformedEntry {
            role: Role::AllowedIpv4, key_hex: crate::auth::hex(&key), reason: "nonzero pad",
        }));
        assert!(found.contains(&Divergence::EndpointMissing { endpoint: Endpoint { octets: SERVER, port: 443 } }));
    }

    #[test]
    fn a_short_key_is_malformed() {
        let mut c = capture();
        let short = inode_key(CG, SH.dev, SH.ino)[..23].to_vec();
        c.exec_keys = vec![short.clone()];
        assert!(refusals(&check(c)).contains(&Divergence::MalformedEntry {
            role: Role::AllowedExec, key_hex: crate::auth::hex(&short), reason: "key length",
        }));
    }

    #[test]
    fn two_passes_that_disagree_are_indeterminate() {
        let mut s = snapshot_of(capture());
        s.passes[1].exec_keys.clear();
        assert_eq!(indeterminate(&run(&s, &approval(), &resolver())).len(), 1);
    }

    #[test]
    fn one_pass_is_not_a_capture() {
        let mut s = snapshot_of(capture());
        s.passes.truncate(1);
        assert_eq!(indeterminate(&run(&s, &approval(), &resolver())).len(), 1);
    }

    #[test]
    fn a_missing_lease_entry_is_refused() {
        let mut c = capture();
        c.lease_value = None;
        assert_eq!(refusals(&check(c)), vec![Divergence::LeaseMissing]);
    }

    #[test]
    fn a_lease_value_of_the_old_eight_byte_layout_is_malformed() {
        let mut c = capture();
        c.lease_value = Some((NOW + 30 * SEC).to_le_bytes().to_vec());
        assert_eq!(refusals(&check(c)), vec![Divergence::LeaseValueMalformed { len: 8 }]);
    }

    #[test]
    fn endpoints_are_compared_in_both_directions() {
        let mut c = capture();
        c.ipv4_keys.push(ipv4_key(CG, [10, 0, 0, 1], 443));
        assert_eq!(refusals(&check(c)),
                   vec![Divergence::EndpointExcess { endpoint: Endpoint { octets: [10, 0, 0, 1], port: 443 } }]);
        let mut c = capture();
        c.ipv4_keys.clear();
        assert_eq!(refusals(&check(c)),
                   vec![Divergence::EndpointMissing { endpoint: Endpoint { octets: SERVER, port: 443 } }]);
    }

    #[test]
    fn a_port_written_in_host_byte_order_is_caught() {
        // 443 written as BB 01 reads, as sin_port does, as 47873.
        let mut c = capture();
        c.ipv4_keys = vec![ipv4_key(CG, SERVER, 443u16.swap_bytes())];
        let found = refusals(&check(c));
        assert!(found.contains(&Divergence::EndpointExcess { endpoint: Endpoint { octets: SERVER, port: 47873 } }));
        assert!(found.contains(&Divergence::EndpointMissing { endpoint: Endpoint { octets: SERVER, port: 443 } }));
    }

    #[test]
    fn an_address_written_in_the_wrong_byte_order_is_caught() {
        let reversed = [34, 216, 184, 93];
        let mut c = capture();
        c.ipv4_keys = vec![ipv4_key(CG, reversed, 443)];
        let found = refusals(&check(c));
        assert!(found.contains(&Divergence::EndpointExcess { endpoint: Endpoint { octets: reversed, port: 443 } }));
        assert!(found.contains(&Divergence::EndpointMissing { endpoint: Endpoint { octets: SERVER, port: 443 } }));
    }

    #[test]
    fn endpoints_on_a_lease_without_network_are_excess() {
        let mut a = approval();
        a.allow_network = false;
        assert_eq!(refusals(&run(&snapshot_of(capture()), &a, &resolver())),
                   vec![Divergence::EndpointExcess { endpoint: Endpoint { octets: SERVER, port: 443 } }]);
    }

    #[test]
    fn two_paths_to_one_inode_expect_one_grant() {
        let mut a = approval();
        a.exec_paths.push("/usr/bin/sh".into());
        let r = resolver().with("/usr/bin/sh", found(SH, 1));
        assert_eq!(run(&snapshot_of(capture()), &a, &r).verdict, Verdict::Admitted);
    }

    #[test]
    fn an_absent_exec_path_expects_no_grant_and_says_so() {
        let mut a = approval();
        a.exec_paths.push("/opt/missing".into());
        let report = run(&snapshot_of(capture()), &a, &resolver());
        assert_eq!(report.verdict, Verdict::Admitted);
        assert_eq!(report.notes, vec![Note::AbsentExecPath { path: "/opt/missing".into() }]);
    }

    #[test]
    fn a_protected_path_that_no_longer_resolves_is_indeterminate() {
        let mut a = approval();
        a.protected_paths.push("/etc/gone".into());
        assert_eq!(indeterminate(&run(&snapshot_of(capture()), &a, &resolver())).len(), 1);
    }

    #[test]
    fn egress_the_kernel_cannot_key_is_indeterminate_or_noted() {
        let mut a = approval();
        a.egress_ips.push("example.com".into());
        assert_eq!(indeterminate(&run(&snapshot_of(capture()), &a, &resolver())).len(), 1);

        let mut a = approval();
        a.egress_ports.push(70_000);
        assert_eq!(indeterminate(&run(&snapshot_of(capture()), &a, &resolver())).len(), 1);

        // The program denies every IPv6 destination, so v6 fails closed and is only noted.
        let mut a = approval();
        a.egress_ips.push("2001:db8::1".into());
        let report = run(&snapshot_of(capture()), &a, &resolver());
        assert_eq!(report.verdict, Verdict::Admitted);
        assert_eq!(report.notes, vec![Note::UnenforceableV6 { ip: "2001:db8::1".into() }]);
    }

    #[test]
    fn a_filesystem_whose_stat_device_may_differ_is_indeterminate() {
        for magic in [0x9123_683E_u64, 0x794C_7630] {
            let r = resolver().with("/bin/sh", Resolution::Found { ident: SH, fs_magic: magic, mnt_id: 1 });
            assert_eq!(indeterminate(&run(&snapshot_of(capture()), &approval(), &r)).len(), 1, "{magic:#x}");
        }
    }

    #[test]
    fn a_policy_path_under_the_cow_workdir_is_indeterminate() {
        let tool = Ident { dev: SDA2, ino: 6 };
        let mut a = approval();
        a.cow_workdir = Some("/work".into());
        a.exec_paths.push("/work/tool".into());
        let r = resolver().with("/work", found(Ident { dev: SDA2, ino: 5 }, 1)).with("/work/tool", found(tool, 1));
        let mut c = capture();
        c.exec_keys.push(inode_key(CG, tool.dev, tool.ino));
        assert_eq!(indeterminate(&run(&snapshot_of(c), &a, &r)).len(), 1);
    }

    #[test]
    fn a_protected_file_on_a_submount_the_jail_does_not_carry_is_refused() {
        let r = resolver().with("/etc/shadow", found(SHADOW, 7));
        assert_eq!(refusals(&run(&snapshot_of(capture()), &approval(), &r)),
                   vec![Divergence::ProtectionNotEffectiveInJail { path: "/etc/shadow".into() }]);
    }

    #[test]
    fn a_private_identity_notes_its_generated_passwd() {
        let passwd = Ident { dev: SDA2, ino: 4004 };
        let mut a = approval();
        a.private_uid = true;
        a.protected_paths.push("/etc/passwd".into());
        let r = resolver().with("/etc/passwd", found(passwd, 1));
        let mut c = capture();
        c.protected_keys.push(inode_key(CG, passwd.dev, passwd.ino));
        let report = run(&snapshot_of(c), &a, &r);
        assert_eq!(report.verdict, Verdict::Admitted);
        assert_eq!(report.notes, vec![Note::ShadowedBySyntheticIdentity { path: "/etc/passwd".into() }]);
    }

    #[test]
    fn a_cgroup_that_is_not_the_leases_is_refused() {
        let mut s = snapshot_of(capture());
        s.cgroup_ino = CG + 1;
        assert_eq!(refusals(&run(&s, &approval(), &resolver())),
                   vec![Divergence::CgroupIdentity { expected: CG, observed: CG + 1 }]);
    }

    #[test]
    fn the_walk_keeps_this_lease_and_detects_a_restart() {
        let mine = inode_key(CG, SDA2, 1);
        let other = inode_key(CG + 1, SDA2, 1);
        assert_eq!(lease_keys(&[other.clone(), mine.clone()], CG), Some(vec![mine.clone()]));
        assert_eq!(lease_keys(&[mine.clone(), other, mine], CG), None);
    }

    #[test]
    fn the_snapshot_hash_ignores_order_and_sees_content() {
        let a = snapshot_of(capture());
        let mut more = a.clone();
        for pass in &mut more.passes {
            pass.exec_keys.push(inode_key(CG, SDA2, 1));
        }
        let mut reordered = more.clone();
        reordered.hooks.reverse();
        for pass in &mut reordered.passes {
            pass.exec_keys.reverse();
        }
        assert_eq!(snapshot_sha256(&more), snapshot_sha256(&reordered));
        assert_ne!(snapshot_sha256(&a), snapshot_sha256(&more));
    }

    #[test]
    fn every_divergence_is_reported_not_just_the_first() {
        let mut p = profile();
        p.writer.insert(Role::AllowedExec, 99);
        let mut c = capture();
        c.ipv4_keys.push(ipv4_key(CG, [10, 0, 0, 1], 80));
        let found = refusals(&validate(&p, &approval(), &snapshot_of(c), &resolver()));
        assert!(found.iter().any(|d| matches!(d, Divergence::MapBinding { .. })));
        assert!(found.iter().any(|d| matches!(d, Divergence::EndpointExcess { .. })));
    }

    #[test]
    fn the_frame_says_what_was_enforced_and_why() {
        let admitted = Outcome { report: check(capture()), ..Outcome::indeterminate("unused") };
        let frame = admitted.frame(AdmissionValidator::Audit, "abc");
        assert_eq!(frame["type"], "ADMISSION");
        assert_eq!(frame["source"], "native");
        assert_eq!(frame["admitted"], true);
        assert_eq!(frame["enforced"], false);
        assert_eq!(frame["verdict"], "admitted");
        assert_eq!(frame["mapIds"]["allowedExec"], 11);

        let mut c = capture();
        c.exec_keys.clear();
        let refused = Outcome { report: check(c), ..Outcome::indeterminate("unused") };
        let frame = refused.frame(AdmissionValidator::Enforce, "abc");
        assert_eq!(frame["admitted"], false);
        assert_eq!(frame["enforced"], true);
        assert_eq!(frame["reasons"][0]["kind"], "execGrantMissing");
        assert_eq!(frame["reasons"][0]["path"], "/bin/sh");
        assert_eq!(refused.exit_summary()["verdict"], "refused");
    }

    #[test]
    fn the_validator_does_not_borrow_the_writers_encoders() {
        let files = [("admission.rs", include_str!("admission.rs")), ("admission_collect.rs", include_str!("admission_collect.rs"))];
        for (name, source) in files {
            let body = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in ["kernel_dev_from_st_dev", "inode_key_for_path", "lease_map_keys", "bytes_of",
                              "LeaseInodeKey", "LeaseIpv4Key", "ipv4_to_be_u32", "RESEARCH_DEV_ENCODING_FAULT", "ActiveLease"] {
                assert!(!body.contains(forbidden), "{name} uses the writer's {forbidden}");
            }
        }
    }
}
