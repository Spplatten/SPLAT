//! Native admission validator: the half that asks the kernel. Enumerating links and opening maps
//! by id need CAP_SYS_ADMIN, so nothing here runs under `cargo test` except the identity resolver.
//! It gathers raw facts and `admission.rs` judges them. Its first real run is the root probe at
//! the next milestone.
//!
//! The iterators libbpf-rs offers over links, programs and maps end silently on EPERM or any other
//! error, which would read as "nothing foreign attached". Every walk here is a raw call whose
//! failure becomes an indeterminate verdict instead.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, ensure, Context, Result};
use libbpf_rs::libbpf_sys as sys;
use libbpf_rs::skel::Skel;

use crate::admission::{
    self, Approval, Capture, Counts, ExpectedProgram, ForeignLink, Hook, HookObs, Ident, IdentityResolver,
    KernelProfile, MapLayout, Outcome, Resolution, Role, Snapshot,
};
use crate::lease_lsm::LeaseLsmSkel;

/// Capture attempts before a lease is called indeterminate, each two full passes. Under MAP_WRITES
/// only another lease's teardown, which cannot take the lock, can make them disagree.
const MAX_ATTEMPTS: u32 = 3;

/// The map each role is captured from, found in the program that decides with it: what the kernel
/// enforces, not what the writer holds handles to.
const CAPTURE_FROM: [(Role, Hook); 5] = [
    (Role::LeasedCgroups, Hook::BprmCheck),
    (Role::AllowedExec, Hook::BprmCheck),
    (Role::ScratchExec, Hook::BprmCheck),
    (Role::Protected, Hook::FileOpen),
    (Role::AllowedIpv4, Hook::SocketConnect),
];

pub struct Collector {
    profile: KernelProfile,
    /// This daemon's own links, duplicated at startup. Never `skel.progs`: on pin reuse those
    /// are loaded but unattached copies.
    links: Vec<(Hook, OwnedFd)>,
}

impl Collector {
    /// Reads this daemon's links and loaded programs once. `writer` holds the ids of the maps the
    /// lease writer writes, by role, the research decoy included.
    pub fn new(skel: &LeaseLsmSkel<'_>, writer: BTreeMap<Role, u32>) -> Result<Self> {
        let held = [
            (Hook::BprmCheck, skel.links.splat_bprm_check.as_ref(), skel.progs.splat_bprm_check.as_fd()),
            (Hook::FileOpen, skel.links.splat_file_open.as_ref(), skel.progs.splat_file_open.as_fd()),
            (Hook::SocketConnect, skel.links.splat_socket_connect.as_ref(), skel.progs.splat_socket_connect.as_fd()),
            (Hook::SocketSendmsg, skel.links.splat_socket_sendmsg.as_ref(), skel.progs.splat_socket_sendmsg.as_fd()),
            (Hook::PtraceAccess, skel.links.splat_ptrace_access.as_ref(), skel.progs.splat_ptrace_access.as_fd()),
            (Hook::TaskKill, skel.links.splat_task_kill.as_ref(), skel.progs.splat_task_kill.as_fd()),
            (Hook::TaskSetsched, skel.links.splat_task_setsched.as_ref(), skel.progs.splat_task_setsched.as_fd()),
            (Hook::TaskSetnice, skel.links.splat_task_setnice.as_ref(), skel.progs.splat_task_setnice.as_fd()),
            (Hook::TaskSetioprio, skel.links.splat_task_setioprio.as_ref(), skel.progs.splat_task_setioprio.as_fd()),
            (Hook::TaskSetrlimit, skel.links.splat_task_setrlimit.as_ref(), skel.progs.splat_task_setrlimit.as_fd()),
        ];
        // A program added to lease_lsm.bpf.c but not to this list would be attached and never
        // checked, so a foreign program on its hook would pass every admission unseen.
        ensure!(held.iter().map(|h| h.0).eq(Hook::ALL) && skel.object().progs().count() == held.len(),
                "the validator's hook list does not cover every program this daemon attaches");
        let vmlinux = vmlinux_btf_obj_id()?;
        let btf = VmlinuxBtf::load()?;
        let mut expected = Vec::new();
        let mut links = Vec::new();
        for (hook, link, program) in held {
            let link = link.with_context(|| format!("this daemon holds no {hook:?} link"))?;
            let fd = link.as_fd().try_clone_to_owned().context("duplicate a lease hook link")?;
            let info = link_info(fd.as_raw_fd()).with_context(|| format!("read the {hook:?} link"))?;
            // SAFETY: every member of this union is plain integers; the tracing member is the one a
            // tracing link fills, and the check below refuses any other link type.
            let tracing = unsafe { info.__bindgen_anon_1.tracing };
            ensure!(info.type_ == sys::BPF_LINK_TYPE_TRACING && tracing.attach_type == sys::BPF_LSM_MAC && info.prog_id != 0,
                    "the {hook:?} link is not an active BPF-LSM attachment");
            ensure!(tracing.target_obj_id == vmlinux,
                    "the {hook:?} link targets BTF object {}, not vmlinux ({vmlinux})", tracing.target_obj_id);
            let name = btf.func_name(tracing.target_btf_id)?;
            ensure!(name == hook.btf_func(), "the {hook:?} link is attached to {name}, not {}", hook.btf_func());
            // The tag of this binary's own program. On pin reuse, `reopen` already required the
            // pinned program's tag to equal it.
            let (program, _) = crate::pinning::prog_info(program)?;
            expected.push(ExpectedProgram {
                hook,
                link_id: info.id,
                tag: program.tag,
                attach_btf_obj_id: program.attach_btf_obj_id,
                attach_btf_id: program.attach_btf_id,
            });
            links.push((hook, fd));
        }
        Ok(Self { profile: KernelProfile { expected, vmlinux_btf_obj_id: vmlinux, writer }, links })
    }

    /// What every lease would meet before any request arrives, such as another loader's program on
    /// these hooks. Logged at startup, not fatal: the same facts decide each lease at admission.
    pub fn startup_findings(&self) -> Result<Vec<String>> {
        let (s, _) = self.observe()?;
        let bindings = admission::check_bindings(&self.profile, &s);
        let mut findings: Vec<String> = admission::check_programs(&self.profile, &s).iter()
            .chain(&bindings.divergences)
            .map(|d| serde_json::to_string(d).unwrap_or_default())
            .collect();
        findings.extend(bindings.unreadable.iter().map(|id| format!("map {id} cannot be read")));
        Ok(findings)
    }

    /// One admission: observe, capture, judge. Never fails; anything unread is an indeterminate
    /// verdict, which `enforce` refuses.
    pub fn validate(&self, approval: &Approval, cgroup_path: &Path) -> Outcome {
        let started = Instant::now();
        let observed = self.observe().and_then(|(mut s, fds)| {
            let captured = capture(&s, &fds, approval.cgroup_id)?;
            s.passes = captured.passes;
            s.capture_error = captured.error;
            s.boot_now_ns = crate::lease::boot_clock_ns()?;
            s.cgroup_ino = std::fs::metadata(cgroup_path)
                .with_context(|| format!("stat {}", cgroup_path.display()))?.ino();
            Ok((s, captured.attempts, captured.occupancy))
        });
        let collect_ns = elapsed_ns(started);
        let (s, attempts, map_occupancy) = match observed {
            Ok(observed) => observed,
            Err(e) => {
                let mut outcome = Outcome::indeterminate(format!("{e:#}"));
                outcome.collect_ns = collect_ns;
                return outcome;
            }
        };
        let decided = Instant::now();
        let report = admission::validate(&self.profile, approval, &s, &HostResolver);
        let decide_ns = elapsed_ns(decided);
        let last = s.passes.last();
        Outcome {
            snapshot_sha256: Some(admission::snapshot_sha256(&s)),
            programs: admission::programs(&s),
            counts: Counts {
                exec: last.map_or(0, |c| c.exec_keys.len()),
                protected: last.map_or(0, |c| c.protected_keys.len()),
                ipv4: last.map_or(0, |c| c.ipv4_keys.len()),
                map_occupancy,
            },
            report,
            attempts,
            collect_ns,
            decide_ns,
        }
    }

    /// The programs behind our links, every foreign LSM link on our targets, and the layout of each
    /// map our programs reference, with a read-only descriptor for each.
    fn observe(&self) -> Result<(Snapshot, BTreeMap<u32, OwnedFd>)> {
        let mut s = Snapshot::default();
        for (hook, fd) in &self.links {
            let info = link_info(fd.as_raw_fd()).with_context(|| format!("read the {hook:?} link"))?;
            // SAFETY: as in `new`; a link that is no longer tracing is reported, not trusted.
            let tracing = unsafe { info.__bindgen_anon_1.tracing };
            let mut obs = HookObs {
                hook: *hook,
                link_id: info.id,
                link_type: info.type_,
                attach_type: tracing.attach_type,
                prog_id: info.prog_id,
                target_obj_id: tracing.target_obj_id,
                target_btf_id: tracing.target_btf_id,
                prog_type: 0,
                tag: [0; 8],
                attach_btf_obj_id: 0,
                attach_btf_id: 0,
                map_ids: Vec::new(),
            };
            if info.prog_id != 0 {
                let program = libbpf_rs::Program::fd_from_id(info.prog_id)
                    .with_context(|| format!("open program {}", info.prog_id))?;
                let (p, map_ids) = crate::pinning::prog_info(program.as_fd())?;
                obs.prog_type = p.type_;
                obs.tag = p.tag;
                obs.attach_btf_obj_id = p.attach_btf_obj_id;
                obs.attach_btf_id = p.attach_btf_id;
                obs.map_ids = map_ids;
            }
            s.hooks.push(obs);
        }
        s.foreign = self.foreign_links()?;
        let mut fds = BTreeMap::new();
        let ids: BTreeSet<u32> = s.hooks.iter().flat_map(|h| h.map_ids.iter().copied()).collect();
        for id in ids {
            let fd = open_map_read_only(id).with_context(|| format!("open map {id} read-only"))?;
            let info = libbpf_rs::MapInfo::new(fd.as_fd()).with_context(|| format!("read map {id}"))?.info;
            let name = info.name.iter().take_while(|&&c| c != 0).map(|&c| c as u8 as char).collect();
            s.maps.insert(id, MapLayout {
                id,
                name,
                map_type: info.type_,
                key_size: info.key_size,
                value_size: info.value_size,
                max_entries: info.max_entries,
                map_flags: info.map_flags,
            });
            fds.insert(id, fd);
        }
        Ok((s, fds))
    }

    /// Every LSM link on one of our targets that is not ours, from the kernel's whole link
    /// list. Other distributions share this WSL kernel, and their orphaned links count.
    fn foreign_links(&self) -> Result<Vec<ForeignLink>> {
        let ours: BTreeSet<u32> = self.profile.expected.iter().map(|e| e.link_id).collect();
        let targets: BTreeSet<u32> = self.profile.expected.iter().map(|e| e.attach_btf_id).collect();
        let mut found = Vec::new();
        let mut id = 0u32;
        loop {
            let mut next = 0u32;
            // SAFETY: `next` is a valid u32 the kernel writes.
            match retry(|| unsafe { sys::bpf_link_get_next_id(id, &mut next) }) {
                0 => id = next,
                rc if rc == -libc::ENOENT => return Ok(found),
                rc => return Err(io::Error::from_raw_os_error(-rc)).context("enumerate BPF links"),
            }
            if ours.contains(&id) {
                continue;
            }
            // SAFETY: plain syscall wrapper; a non-negative result is a descriptor we now own.
            let fd = unsafe { sys::bpf_link_get_fd_by_id(id) };
            if fd == -libc::ENOENT {
                continue; // released between the two calls
            }
            if fd < 0 {
                return Err(io::Error::from_raw_os_error(-fd)).with_context(|| format!("open BPF link {id}"));
            }
            // SAFETY: a descriptor the kernel just returned, owned by nothing else.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let info = link_info(fd.as_raw_fd()).with_context(|| format!("read BPF link {id}"))?;
            if info.type_ != sys::BPF_LINK_TYPE_TRACING {
                continue;
            }
            // SAFETY: a tracing link fills the tracing member, as checked above.
            let tracing = unsafe { info.__bindgen_anon_1.tracing };
            if tracing.attach_type == sys::BPF_LSM_MAC
                && tracing.target_obj_id == self.profile.vmlinux_btf_obj_id
                && targets.contains(&tracing.target_btf_id)
            {
                found.push(ForeignLink {
                    link_id: info.id,
                    prog_id: info.prog_id,
                    target_obj_id: tracing.target_obj_id,
                    target_btf_id: tracing.target_btf_id,
                });
            }
        }
    }
}

struct Captured {
    passes: Vec<Capture>,
    error: Option<String>,
    attempts: u32,
    occupancy: BTreeMap<Role, usize>,
}

/// Up to MAX_ATTEMPTS pairs of passes over the decision maps the programs read, until a pair
/// agrees. Buffers are sized from the declared layout, so a map of any other type or size is not
/// read at all: the kernel would write past them.
fn capture(s: &Snapshot, fds: &BTreeMap<u32, OwnedFd>, cgroup_id: u64) -> Result<Captured> {
    let mut roles = BTreeMap::new();
    for (role, hook) in CAPTURE_FROM {
        let spec = role.spec();
        let named: Vec<&MapLayout> = s.hooks.iter()
            .filter(|h| h.hook == hook)
            .flat_map(|h| h.map_ids.iter())
            .filter_map(|id| s.maps.get(id))
            .filter(|m| m.name == spec.kernel_name)
            .collect();
        match named.as_slice() {
            [m] if m.map_type == spec.map_type && m.key_size == spec.key_size && m.value_size == spec.value_size => {
                roles.insert(role, fds[&m.id].as_raw_fd());
            }
            _ => {
                return Ok(Captured {
                    passes: Vec::new(),
                    error: Some(format!("the {role:?} map the programs decide with has no single declared-layout match")),
                    attempts: 0,
                    occupancy: BTreeMap::new(),
                });
            }
        }
    }
    let mut passes = Vec::new();
    let mut occupancy = BTreeMap::new();
    let mut attempts = 0;
    for attempt in 1..=MAX_ATTEMPTS {
        attempts = attempt;
        let (Some((a, _)), Some((b, seen))) = (pass(&roles, cgroup_id)?, pass(&roles, cgroup_id)?) else {
            passes.clear();
            continue;
        };
        let agree = a == b;
        passes = vec![a, b];
        occupancy = seen;
        if agree {
            break;
        }
    }
    let error = passes.is_empty().then(|| "a concurrent teardown restarted every walk of the policy maps".to_string());
    Ok(Captured { passes, error, attempts, occupancy })
}

/// One pass: this lease's two point entries, and its keys from a full walk of each keyed map. None
/// when a walk restarted.
fn pass(roles: &BTreeMap<Role, RawFd>, cgroup_id: u64) -> Result<Option<(Capture, BTreeMap<Role, usize>)>> {
    let mut occupancy = BTreeMap::new();
    let mut keys = Vec::new();
    for role in [Role::AllowedExec, Role::Protected, Role::AllowedIpv4] {
        let spec = role.spec();
        let Some(walked) = walk(roles[&role], spec.key_size as usize, spec.max_entries as usize)? else { return Ok(None) };
        occupancy.insert(role, walked.len());
        let Some(kept) = admission::lease_keys(&walked, cgroup_id) else { return Ok(None) };
        keys.push(kept);
    }
    let [exec_keys, protected_keys, ipv4_keys]: [Vec<Vec<u8>>; 3] =
        keys.try_into().map_err(|_| anyhow::anyhow!("three keyed maps were walked"))?;
    let point = cgroup_id.to_le_bytes();
    let capture = Capture {
        lease_value: lookup(roles[&Role::LeasedCgroups], &point, Role::LeasedCgroups.spec().value_size as usize)?,
        scratch_value: lookup(roles[&Role::ScratchExec], &point, Role::ScratchExec.spec().value_size as usize)?,
        exec_keys,
        protected_keys,
        ipv4_keys,
    };
    Ok(Some((capture, occupancy)))
}

/// One full `get_next_key` walk. None when it ran past what the map can hold, which only a restart
/// from the head under a concurrent delete produces; `lease_keys` catches a shorter restart.
fn walk(fd: RawFd, key_size: usize, max_entries: usize) -> Result<Option<Vec<Vec<u8>>>> {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut next = vec![0u8; key_size];
        let prev = keys.last().map_or(std::ptr::null(), |k| k.as_ptr().cast());
        // SAFETY: `prev` is null or a key of `key_size` bytes, and the kernel writes `key_size`
        // bytes into `next`; `capture` checked that size against the map's own layout.
        match retry(|| unsafe { sys::bpf_map_get_next_key(fd, prev, next.as_mut_ptr().cast()) }) {
            0 => {}
            rc if rc == -libc::ENOENT => return Ok(Some(keys)),
            rc => return Err(io::Error::from_raw_os_error(-rc)).context("walk a policy map"),
        }
        keys.push(next);
        if keys.len() > max_entries {
            return Ok(None);
        }
    }
}

fn lookup(fd: RawFd, key: &[u8], value_size: usize) -> Result<Option<Vec<u8>>> {
    let mut value = vec![0u8; value_size];
    // SAFETY: the key and value buffers are the map's own sizes, checked in `capture`.
    match retry(|| unsafe { sys::bpf_map_lookup_elem(fd, key.as_ptr().cast(), value.as_mut_ptr().cast()) }) {
        0 => Ok(Some(value)),
        rc if rc == -libc::ENOENT => Ok(None),
        rc => Err(io::Error::from_raw_os_error(-rc)).context("look up a lease entry"),
    }
}

/// libbpf returns a negative errno; a signal is not an answer.
fn retry(mut call: impl FnMut() -> i32) -> i32 {
    loop {
        let rc = call();
        if rc != -libc::EINTR {
            return rc;
        }
    }
}

fn link_info(fd: RawFd) -> io::Result<sys::bpf_link_info> {
    let mut info = sys::bpf_link_info::default();
    let mut len = std::mem::size_of::<sys::bpf_link_info>() as u32;
    // SAFETY: the kernel writes at most `len` bytes into `info`; its pointer members are zero, so
    // it copies no names or address arrays anywhere.
    let rc = unsafe { sys::bpf_obj_get_info_by_fd(fd, (&mut info as *mut sys::bpf_link_info).cast(), &mut len) };
    if rc < 0 { Err(io::Error::from_raw_os_error(-rc)) } else { Ok(info) }
}

/// Read-only, so the validator cannot write the policy it judges even by mistake.
fn open_map_read_only(id: u32) -> io::Result<OwnedFd> {
    let opts = sys::bpf_get_fd_by_id_opts {
        sz: std::mem::size_of::<sys::bpf_get_fd_by_id_opts>() as _,
        open_flags: sys::BPF_F_RDONLY as u32,
        ..Default::default()
    };
    // SAFETY: `opts` is a valid, sized options struct.
    let fd = unsafe { sys::bpf_map_get_fd_by_id_opts(id, &opts) };
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(-fd));
    }
    // SAFETY: a descriptor the kernel just returned, owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The id of the kernel's own BTF object, which every LSM link targets.
fn vmlinux_btf_obj_id() -> Result<u32> {
    let mut id = 0u32;
    loop {
        let mut next = 0u32;
        // SAFETY: `next` is a valid u32 the kernel writes.
        match retry(|| unsafe { sys::bpf_btf_get_next_id(id, &mut next) }) {
            0 => id = next,
            rc if rc == -libc::ENOENT => bail!("the kernel has no BTF object named vmlinux"),
            rc => return Err(io::Error::from_raw_os_error(-rc)).context("enumerate BTF objects"),
        }
        // SAFETY: plain syscall wrapper; a non-negative result is a descriptor we now own.
        let fd = unsafe { sys::bpf_btf_get_fd_by_id(id) };
        if fd == -libc::ENOENT {
            continue;
        }
        if fd < 0 {
            return Err(io::Error::from_raw_os_error(-fd)).with_context(|| format!("open BTF object {id}"));
        }
        // SAFETY: a descriptor the kernel just returned, owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut name = [0u8; 64];
        let mut info = sys::bpf_btf_info { name: name.as_mut_ptr() as u64, name_len: name.len() as u32, ..Default::default() };
        let mut len = std::mem::size_of::<sys::bpf_btf_info>() as u32;
        // SAFETY: the kernel writes the info struct and at most `name_len` bytes of name.
        let rc = unsafe { sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), (&mut info as *mut sys::bpf_btf_info).cast(), &mut len) };
        if rc < 0 {
            return Err(io::Error::from_raw_os_error(-rc)).with_context(|| format!("read BTF object {id}"));
        }
        let is_vmlinux = CStr::from_bytes_until_nul(&name).is_ok_and(|n| n.to_bytes() == b"vmlinux");
        if info.kernel_btf == 1 && is_vmlinux {
            return Ok(info.id);
        }
    }
}

/// The kernel's BTF, to name the functions our links are attached to.
struct VmlinuxBtf(*mut sys::btf);

impl VmlinuxBtf {
    fn load() -> Result<Self> {
        // SAFETY: returns an owned object or null with errno set.
        let btf = unsafe { sys::btf__load_vmlinux_btf() };
        if btf.is_null() {
            return Err(io::Error::last_os_error()).context("load the kernel's BTF");
        }
        Ok(Self(btf))
    }

    fn func_name(&self, id: u32) -> Result<String> {
        // SAFETY: `self.0` is a live BTF object; the result is null or points into it.
        let t = unsafe { sys::btf__type_by_id(self.0, id) };
        ensure!(!t.is_null(), "BTF type {id} does not exist");
        // SAFETY: non-null, and valid while `self` lives.
        let t = unsafe { &*t };
        // BTF_INFO_KIND: bits 24-28 of `info`.
        ensure!((t.info >> 24) & 0x1f == sys::BTF_KIND_FUNC, "BTF type {id} is not a function");
        // SAFETY: as above; the name is a NUL-terminated string inside the BTF object.
        let name = unsafe { sys::btf__name_by_offset(self.0, t.name_off) };
        ensure!(!name.is_null(), "BTF type {id} has no name");
        // SAFETY: non-null and NUL-terminated, valid while `self` lives.
        Ok(unsafe { CStr::from_ptr(name) }.to_string_lossy().into_owned())
    }
}

impl Drop for VmlinuxBtf {
    fn drop(&mut self) {
        // SAFETY: owned since `load`, freed once.
        unsafe { sys::btf__free(self.0) }
    }
}

fn elapsed_ns(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// Resolves a path the way the program will meet the file: device from statx's separate major and
/// minor, joined in the kernel's form, never from a packed `st_dev`.
pub struct HostResolver;

impl IdentityResolver for HostResolver {
    fn resolve(&self, path: &Path) -> Resolution {
        let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
            return Resolution::Error("the path contains a NUL byte".to_string());
        };
        // O_PATH follows symlinks, as the writer's stat does, and opens nothing for reading; the
        // daemon's own cgroup is unleased, so file_open does not police it either way.
        // SAFETY: a valid NUL-terminated path.
        let raw = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            let err = io::Error::last_os_error();
            return if err.raw_os_error() == Some(libc::ENOENT) {
                Resolution::Absent
            } else {
                Resolution::Error(format!("open: {err}"))
            };
        }
        // SAFETY: a descriptor `open` just returned, owned by nothing else.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // One descriptor for every question, so the identity and the filesystem type describe the
        // same object. Swapping the path after this is a window the writer shares.
        // SAFETY: zeroed is a valid statx; the kernel fills it.
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        // SAFETY: an empty path with AT_EMPTY_PATH names the descriptor itself.
        let rc = unsafe {
            libc::statx(fd.as_raw_fd(), c"".as_ptr(), libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
                        libc::STATX_INO | libc::STATX_MNT_ID, &mut stx)
        };
        if rc != 0 {
            return Resolution::Error(format!("statx: {}", io::Error::last_os_error()));
        }
        let Some(dev) = admission::kernel_mkdev(stx.stx_dev_major, stx.stx_dev_minor) else {
            return Resolution::Error(format!("device {}:{} does not fit the kernel's encoding", stx.stx_dev_major, stx.stx_dev_minor));
        };
        let mnt_id = if stx.stx_mask & libc::STATX_MNT_ID != 0 {
            stx.stx_mnt_id
        } else {
            match fdinfo_mnt_id(fd.as_raw_fd()) {
                Ok(id) => id,
                Err(e) => return Resolution::Error(format!("mount id: {e}")),
            }
        };
        // SAFETY: zeroed is a valid statfs; the kernel fills it.
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: a live descriptor and a valid out pointer.
        if unsafe { libc::fstatfs(fd.as_raw_fd(), &mut fs) } != 0 {
            return Resolution::Error(format!("fstatfs: {}", io::Error::last_os_error()));
        }
        Resolution::Found { ident: Ident { dev, ino: stx.stx_ino }, fs_magic: fs.f_type as u64, mnt_id }
    }

    fn canonical(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }
}

/// Kernels without STATX_MNT_ID still say it in fdinfo.
fn fdinfo_mnt_id(fd: RawFd) -> io::Result<u64> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "fdinfo carries no mnt_id"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_resolver_reads_a_real_file_without_root() {
        let path = std::env::temp_dir().join(format!("splat_admission_{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let md = std::fs::metadata(&path).unwrap();
        let resolved = HostResolver.resolve(&path);
        std::fs::remove_file(&path).unwrap();
        let Resolution::Found { ident, mnt_id, .. } = resolved else { panic!("{resolved:?}") };
        // statx's separate major and minor against libc's decoding of the packed st_dev: two
        // derivations of one device that must agree.
        let st_dev = md.dev();
        let expected = admission::kernel_mkdev(libc::major(st_dev), libc::minor(st_dev)).unwrap();
        assert_eq!(ident, Ident { dev: expected, ino: md.ino() });
        assert!(mnt_id > 0);
        assert_eq!(HostResolver.resolve(&path), Resolution::Absent);
    }
}
