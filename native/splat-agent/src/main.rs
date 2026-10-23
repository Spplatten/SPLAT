use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::fd::{AsFd, OwnedFd};
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBufferBuilder};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

mod auth;
mod ceiling;
mod cgroup;
mod cow;
mod execution;
mod execution_policy;
mod identities;
mod jail;
mod lease;
mod outcome;
mod receipts;
mod pinning;
mod secret_memory;
mod secret_recovery;
mod secrets;
mod violation;
mod workload;
mod workspace;

/// The protocol this daemon speaks: its handshake, and the EXECUTE_TOOL envelope inside it.
///
/// Version 1 carried `arguments` as a single string, which the daemon then split on whitespace.
/// That is not a parse, it is a guess: MCP's run_code shipped `-c '<code>'` and the split handed
/// python the literal `'print(123)'` - a string expression that evaluates, prints nothing and
/// exits 0. Any argument containing a space tore in half. There is no way to repair a v1 request
/// here, because the information needed to split it correctly was destroyed before it was sent.
///
/// Version 2 fixed that, and put the token itself in every request - so a caller handed it to
/// whatever answered on this port, and while this daemon was not listening, anything in the guest
/// could. Version 3 opens each connection with a handshake in which both sides prove they hold the
/// token without sending it: see `open_session`.
const PROTOCOL_VERSION: u64 = 3;

/// Daemon-wide ceilings. A request may ask for less; it can never ask for more.
const MAX_MEMORY_BYTES_CEILING: u64 = 256 * 1024 * 1024;
const MAX_CPU_PERCENT_CEILING: u32 = 50;
const MAX_PIDS_CEILING: u32 = 100;

mod lease_lsm {
    include!(concat!(env!("OUT_DIR"), "/lease_lsm.skel.rs"));
}

use auth::PeerAuth;
use ceiling::Ceiling;
use cgroup::EphemeralCgroup;
use lease::{bytes_of, lease_map_keys, BpfMapSync, LeaseConfig, LeaseManager};
use violation::{RawViolationEvent, ViolationEvent};

/// Drops the calling (forked, pre-exec) process to an unprivileged identity.
///
/// Async-signal-safe: raw libc calls, no allocation and no locks, because this runs in the forked
/// child of a multithreaded process. Returning Err fails the spawn, so a tool whose privilege could
/// not be dropped never executes - the same fail-closed shape as the cgroup join above it.
fn drop_privileges(uid: u32, gid: u32) -> std::io::Result<()> {
    execution::no_new_privileges()?;
    unsafe {
        // A daemon that is not root forks a child that is not root, so the invariant already holds
        // and there is nothing to transition from - setgroups and setresuid would simply return
        // EPERM and refuse every spawn. The property being protected is "the workload is not root",
        // not "the workload is uid 65534".
        if libc::geteuid() != 0 && libc::getuid() != 0 {
            return Ok(());
        }

        // Supplementary groups survive setuid, so a workload could keep group membership the
        // target account never had. Clear them while still privileged enough to do so.
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::setresgid(gid, gid, gid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // setresuid, not setuid: it sets the saved-set-user-id too, so the workload cannot call
        // seteuid(0) and climb back. A plain setuid from root does that as a side effect, but
        // being explicit is the difference between relying on it and stating it.
        if libc::setresuid(uid, uid, uid) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Belt and braces: if any of the three somehow left root reachable, refuse the exec.
        if libc::geteuid() == 0 || libc::getuid() == 0 {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}

/// The effective uid of a running pid, read from /proc/<pid>/status.
fn effective_uid_of(pid: u32) -> Result<Option<u32>> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("read /proc/{pid}/status"))?;

    for l in status.lines() {
        if let Some(rest) = l.strip_prefix("Uid:") {
            // "Uid:\treal\teffective\tsaved\tfs"
            let mut it = rest.split_whitespace();
            let _real = it.next();
            return Ok(it.next().and_then(|v| v.parse::<u32>().ok()));
        }
    }
    Ok(None)
}

/// Reads a JSON array of strings from a request, distinguishing "absent" from "empty".
///
/// That distinction is the whole point: an absent key means the caller expressed no policy and a
/// default applies, while an empty array means the caller explicitly permitted nothing. Collapsing
/// them would turn "deny everything" into "use the defaults".
fn string_list(v: &serde_json::Value, key: &str) -> Option<Vec<String>> {
    v.get(key)?
        .as_array()
        .and_then(|a| a.iter().map(|e| e.as_str().map(str::to_string)).collect())
}

#[derive(Parser, Debug)]
#[command(author, version, about = "SPLAT Layer-2 Resident eBPF Daemon")]
struct Args {
    // Loopback by default: this RPC executes leased processes, so it must never be reachable
    // beyond the host<->guest channel. WSL2 localhost-forwarding still reaches a guest 127.0.0.1
    // bind from the Windows host, whereas 0.0.0.0 exposes the containment control plane on the
    // guest's network interfaces - and on the LAN under mirrored-networking mode - as an
    // unauthenticated way to run commands inside the sandbox.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: String,

    // The ONE switch that admits the daemon is not enforcing. Without it, a daemon that cannot
    // load its BPF-LSM programs exits instead of serving: a resident process that accepts
    // EXECUTE_TOOL while its hooks are absent is not a degraded sandbox, it is a remote shell that
    // reports containment it does not have.
    #[arg(long, default_value = "false")]
    mock_bpf: bool,

    /// Root-owned 0600 file holding the shared secret every EXECUTE_TOOL must present.
    ///
    /// Created on first run. There is no way to turn authentication off: a daemon that runs
    /// commands as root while treating "opened a loopback socket" as authority is not a sandbox.
    #[arg(long, default_value = "/etc/splat/agent.token")]
    auth_token_file: String,

    /// Root-owned 0600 RSA key the daemon signs each lease's outcome with (roadmap 2.5).
    ///
    /// Created on first run. Unlike the auth token, a key that cannot be established is not fatal:
    /// the daemon goes on containing, its EXIT frames carry no signature, and the host records the
    /// outcome as unsigned. Containment and attribution are different promises, and losing the
    /// second is no reason to stop keeping the first.
    #[arg(long, default_value = outcome::DEFAULT_KEY_PATH)]
    outcome_key_file: String,

    /// Private durable cache for recovering signed bound outcomes after transport loss.
    #[arg(long, default_value = "/var/lib/splat/receipts")]
    receipt_root: String,

    /// Legacy identity for mock execution; enforcing leases use the reserved per-lease pool.
    ///
    /// The daemon needs root to load BPF programs and write the cgroup tree; the WORKLOAD needs
    /// none of that. It used to inherit the daemon's uid 0, so every containment claim rested on
    /// three LSM hooks holding against a root process - with the cgroup controls, host mounts and
    /// every unprotected file still reachable underneath them.
    #[arg(long, default_value_t = 65534)]
    workload_uid: u32,

    /// Legacy mock-execution gid, excluded from the private lease identity pool.
    #[arg(long, default_value_t = 65534)]
    workload_gid: u32,

    /// The operator's ceiling on every lease: a root-owned policy that bounds what any request may
    /// name, whoever holds the token. Absent, the daemon runs without one and says so; present but
    /// untrustworthy, the daemon refuses to start.
    #[arg(long, default_value = ceiling::DEFAULT_PATH)]
    policy_file: String,

    /// Where a governed mission's workspace is made when its lease asks for one (`ephemeralWorkspace`):
    /// the working directory must lie directly under this root, is created owned by the workload
    /// before the lease runs, and is removed when it ends. Nothing outside this root is ever created.
    #[arg(long, default_value = DEFAULT_MISSIONS_ROOT)]
    missions_root: String,

    /// Opt-in secret broker inside an existing root-owned 0700 directory. Never enabled in mock mode.
    #[arg(long)]
    secret_socket: Option<std::path::PathBuf>,

    /// Operator-reserved UID/GID range shared by ordinary leases and pending secret grants.
    #[arg(long = "lease-uid-start", visible_alias = "secret-uid-start", default_value_t = 200000)]
    secret_uid_start: u32,
    #[arg(long = "lease-uid-count", visible_alias = "secret-uid-count", default_value_t = 256)]
    secret_uid_count: u32,

    /// Issue a grant using public binding metadata from this file and secret bytes from stdin.
    #[arg(long, requires = "secret_socket")]
    issue_secret: Option<std::path::PathBuf>,
}

/// See `Args::missions_root`. The bridge's `LinuxLeaseSubstrate` names the same default.
const DEFAULT_MISSIONS_ROOT: &str = "/var/lib/splat/missions";

/// What the daemon can actually observe about its own substrate.
///
/// Every field here used to be a hardcoded `true` in the HEALTH_RESPONSE, alongside a fixed kernel
/// string. The Windows health reader consumes these booleans and has no independent way to check
/// them, so the one signal that was supposed to say "containment is live" said it unconditionally.
struct SubstrateHealth {
    bpf_lsm_active: bool,
    cgroup_v2_active: bool,
    overlayfs_supported: bool,
    kernel_version: String,
}

impl SubstrateHealth {
    fn observe(enforcing: bool) -> Self {
        Self {
            // Not "the kernel supports BPF-LSM" but "this daemon has live map handles", which is
            // the only form of the claim a caller can act on.
            bpf_lsm_active: enforcing,
            cgroup_v2_active: Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
            overlayfs_supported: std::fs::read_to_string("/proc/filesystems")
                .map(|s| s.lines().any(|l| l.split_whitespace().last() == Some("overlay")))
                .unwrap_or(false),
            kernel_version: std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
        }
    }
}

/// Owned duplicates of the skeleton's lease maps.
///
/// The generated skeleton hands out `MapMut<'obj>`, which borrows the BPF object and so cannot be
/// stored in a struct that outlives it — the four E0106 errors this replaced. `MapHandle` owns a
/// dup'd file descriptor instead, freeing the lease driver from the skeleton's lifetime entirely.
/// No `Mutex` either: every `MapCore` operation takes `&self`, and the kernel serialises map
/// updates itself, so the lock only ever added contention and a poisoning failure mode.
struct LiveBpfSync {
    leased_cgroups: MapHandle,
    protected_inodes: MapHandle,
    allowed_exec_inodes: MapHandle,
    scratch_exec_devs: MapHandle,
    allowed_connect_ipv4: MapHandle,
    /// The program's two counters: the next sequence number, and the denials it could not record.
    counters: MapHandle,
    /// cgroup id -> denials the kernel counted for that lease. What an EXIT frame's claim of a
    /// complete receipt is measured against.
    violation_counts: MapHandle,
}

/// Index of the dropped-denials word in the `counters` map; mirrors `COUNTER_DROPPED` in the program.
const COUNTER_DROPPED: u32 = 1;

impl BpfMapSync for LiveBpfSync {
    fn add_lease(&self, lease: &lease::ActiveLease) -> Result<()> {
        // A failed earlier cleanup must refuse a recycled cgroup, including a new lease that
        // did NOT opt in. Otherwise a recycled overlay device number could inherit permission.
        if self.scratch_exec_devs.lookup(&lease.cgroup_id.to_ne_bytes(), MapFlags::ANY)?.is_some() {
            bail!("stale scratch execution grant for cgroup {}", lease.cgroup_id);
        }
        let one: u8 = 1;
        // The value is the lease's deadline on CLOCK_BOOTTIME, struct lease_state in the program. The
        // kernel refuses everything the lease does past it, so expiry holds with no daemon alive.
        self.leased_cgroups
            .update(&lease.cgroup_id.to_ne_bytes(), &lease.deadline_boot_ns.to_ne_bytes(), MapFlags::ANY)
            .context("update leased_cgroups")?;

        // Every policy entry is scoped to this lease's cgroup. Writing the bare resource key here
        // is what let one mission's allow-list become every mission's.
        let keys = lease_map_keys(lease);

        for key in &keys.protected {
            self.protected_inodes
                .update(bytes_of(key), &[one], MapFlags::ANY)
                .context("update protected_inodes")?;
        }

        for key in &keys.allowed_exec {
            self.allowed_exec_inodes
                .update(bytes_of(key), &[one], MapFlags::ANY)
                .context("update allowed_exec_inodes")?;
        }

        for key in &keys.allowed_ipv4 {
            self.allowed_connect_ipv4
                .update(bytes_of(key), &[one], MapFlags::ANY)
                .context("update allowed_connect_ipv4")?;
        }

        Ok(())
    }

    fn remove_lease(&self, lease: &lease::ActiveLease) -> Result<()> {
        let _ = self.scratch_exec_devs.delete(&lease.cgroup_id.to_ne_bytes());
        // Teardown is best-effort by design: a key that is already gone is the desired end state,
        // and a revoke must not abort partway and leave the rest of the lease live in the kernel.
        // Scoped deletes: another lease holding the same resource keeps its own entry. The bare
        // resource key removed the shared one, so revoking A could unprotect a file B still had.
        let keys = lease_map_keys(lease);
        let _ = self.leased_cgroups.delete(&lease.cgroup_id.to_ne_bytes());
        for key in &keys.protected {
            let _ = self.protected_inodes.delete(bytes_of(key));
        }
        for key in &keys.allowed_exec {
            let _ = self.allowed_exec_inodes.delete(bytes_of(key));
        }
        for key in &keys.allowed_ipv4 {
            let _ = self.allowed_connect_ipv4.delete(bytes_of(key));
        }
        Ok(())
    }

    fn scratch_exec_map(&self) -> Result<OwnedFd> {
        self.scratch_exec_devs.as_fd().try_clone_to_owned().context("duplicate scratch execution map")
    }

    fn dropped_events(&self) -> u64 {
        // A counter that cannot be read is reported as nothing dropped, and said so: the alternative,
        // failing the lease over a diagnostic, would refuse work the kernel is containing fine.
        match self.counters.lookup(&COUNTER_DROPPED.to_ne_bytes(), MapFlags::ANY) {
            Ok(Some(word)) if word.len() >= 8 => u64::from_ne_bytes(word[..8].try_into().unwrap_or([0; 8])),
            Ok(_) => 0,
            Err(e) => {
                warn!("Could not read the dropped-denials counter: {e}");
                0
            }
        }
    }

    fn violations_for(&self, cgroup_id: u64) -> Option<u64> {
        // A missing key is a lease the kernel has denied nothing to: zero, not unknown. A read that
        // FAILS is unknown, and says so by returning None - the EXIT frame then reports that it
        // could not check its own completeness rather than asserting it.
        match self.violation_counts.lookup(&cgroup_id.to_ne_bytes(), MapFlags::ANY) {
            Ok(Some(word)) if word.len() >= 8 => {
                Some(u64::from_ne_bytes(word[..8].try_into().unwrap_or([0; 8])))
            }
            Ok(Some(_)) => None,
            Ok(None) => Some(0),
            Err(e) => {
                warn!("Could not read the denial count for cgroup {cgroup_id}: {e}");
                None
            }
        }
    }

    fn forget_violations(&self, cgroup_id: u64) {
        // Best-effort, like every other teardown here: a key already gone is the end state wanted,
        // and a revoke must not abort partway. Left behind, it would be inherited by whatever the
        // kernel next gives that cgroup id.
        let _ = self.violation_counts.delete(&cgroup_id.to_ne_bytes());
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if let Some(metadata) = &args.issue_secret {
        return secrets::submit(args.secret_socket.as_deref().expect("required by clap"), metadata);
    }
    if args.secret_socket.is_some() && args.mock_bpf {
        bail!("secret delivery requires enforcing BPF; --mock-bpf is incompatible");
    }

    info!("Starting SPLAT Resident eBPF Containment Daemon on {}", args.listen);

    let (viol_tx, _viol_rx) = broadcast::channel::<ViolationEvent>(128);
    let mut bpf_sync: Option<Arc<dyn BpfMapSync>> = None;

    let is_root = unsafe { libc::geteuid() } == 0;
    let _instance_lock = if is_root { Some(pinning::lock_instance()?) } else { None };
    if !is_root {
        warn!("Running unprivileged. In-kernel BPF-LSM hooks require CAP_BPF / CAP_SYS_ADMIN.");
    } else if !args.mock_bpf {
        info!("Initializing in-kernel BPF-LSM capability lease skeleton...");
        let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
        match pinning::load(open_object) {
            Ok(skel) => {
                info!("BPF-LSM programs attached successfully.");
                let skel = Box::leak(Box::new(skel));

                // Spawn background ringbuffer drain thread
                let ringbuf_viol_tx = viol_tx.clone();
                let violations_map = &skel.maps.violations;
                let mut rb = RingBufferBuilder::new();
                if let Ok(_) = rb.add(violations_map, move |data: &[u8]| {
                    if data.len() >= std::mem::size_of::<RawViolationEvent>() {
                        let raw = unsafe { &*(data.as_ptr() as *const RawViolationEvent) };
                        let event = ViolationEvent::from_raw(raw);
                        // The kernel's own stamp and number, not only the text: a denial made while no
                        // daemon ran waits in the pinned ring buffer and is drained here after restart,
                        // and this line is then the only record of when the kernel decided.
                        info!("Kernel -EPERM violation (cgroup {}, hook {:#x}, ktime {} ns, seq {}): {}",
                              event.cgroup_id, event.hook, event.ktime_ns, event.seq, event.detail_text);
                        let _ = ringbuf_viol_tx.send(event);
                    }
                    0
                }) {
                    if let Ok(built_rb) = rb.build() {
                        // The drain must outlive every lease. This loop used to end on the
                        // first poll error, so one EINTR - one signal - silently stopped
                        // every VIOLATION frame for the rest of the daemon's life while the
                        // hooks went on denying: enforcement intact, evidence gone.
                        std::thread::spawn(move || loop {
                            match built_rb.poll(Duration::from_millis(100)) {
                                Ok(()) => {}
                                Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => {}
                                Err(e) => {
                                    error!("Ring buffer poll failed: {e}; violations are delayed until it recovers.");
                                    std::thread::sleep(Duration::from_millis(100));
                                }
                            }
                        });
                        info!("BPF ringbuffer violation monitor active.");
                    }
                }

                // Dup each map fd out of the skeleton. Any failure here means the daemon
                // cannot enforce leases, so it must not silently fall through to a state
                // where missions run believing they are contained.
                match (
                    MapHandle::try_from(&skel.maps.leased_cgroups),
                    MapHandle::try_from(&skel.maps.protected_inodes),
                    MapHandle::try_from(&skel.maps.allowed_exec_inodes),
                    MapHandle::try_from(&skel.maps.scratch_exec_devs),
                    MapHandle::try_from(&skel.maps.allowed_connect_ipv4),
                    MapHandle::try_from(&skel.maps.counters),
                    MapHandle::try_from(&skel.maps.violation_counts),
                ) {
                    (
                        Ok(leased_cgroups),
                        Ok(protected_inodes),
                        Ok(allowed_exec_inodes),
                        Ok(scratch_exec_devs),
                        Ok(allowed_connect_ipv4),
                        Ok(counters),
                        Ok(violation_counts),
                    ) => {
                        bpf_sync = Some(Arc::new(LiveBpfSync {
                            leased_cgroups,
                            protected_inodes,
                            allowed_exec_inodes,
                            scratch_exec_devs,
                            allowed_connect_ipv4,
                            counters,
                            violation_counts,
                        }));
                        info!("Lease maps bound; kernel enforcement is live.");
                    }
                    _ => error!(
                        "Could not duplicate the BPF lease map descriptors. Leases will NOT \
                         be enforced in-kernel; refusing to report containment."
                    ),
                }
            }
            Err(e) => warn!("Failed to establish pinned BPF-LSM enforcement: {e:#}"),
        }
    }

    // FAIL CLOSED. A failed pin validation may leave old hooks alive, but this daemon has no
    // verified policy handles and must not admit new workloads. --mock-bpf explicitly opts out.
    if bpf_sync.is_none() && !args.mock_bpf {
        error!(
            "Refusing to start: BPF-LSM enforcement could not be verified{}. Check the kernel and pin-set error above; --mock-bpf explicitly runs without containment.",
            if is_root { "" } else { " (not running as root)" }
        );
        std::process::exit(1);
    }

    // Establish who is allowed to talk to this daemon before it starts listening. Same posture as
    // the enforcement gate above: if the credential cannot be established, do not serve.
    let peer_auth = match PeerAuth::load_or_create(Path::new(&args.auth_token_file)) {
        Ok(a) => Arc::new(a),
        Err(e) => {
            error!(
                "Refusing to start: could not establish the peer authentication token at {}: {e:#}",
                args.auth_token_file
            );
            std::process::exit(1);
        }
    };

    // The key each lease's outcome is signed with. Best-effort on purpose - see outcome.rs - so a
    // guest that cannot hold a key still contains, and says its outcomes are unsigned rather than
    // refusing to run them.
    let outcome_signer: Option<Arc<outcome::OutcomeSigner>> =
        outcome::OutcomeSigner::load_or_create(Path::new(&args.outcome_key_file)).map(Arc::new);
    let receipt_store = match receipts::Store::open(Path::new(&args.receipt_root)) {
        Ok(store) => Some(store),
        Err(error) => { error!("Bound execution unavailable: receipt cache: {error:#}"); None }
    };

    // The ceiling, before anything is served. Its absence is loud because it is the one thing
    // that makes a stolen token worth less than the daemon's whole authority.
    let lease_ceiling: Option<Arc<Ceiling>> = match Ceiling::load(Path::new(&args.policy_file)) {
        Ok(Some(c)) => {
            info!(
                "Lease ceiling loaded from {}{}",
                args.policy_file,
                if c.bounds_egress() { "" } else { " (egress not bounded by it)" }
            );
            Some(Arc::new(c))
        }
        Ok(None) => {
            warn!(
                "No lease ceiling at {}: the token alone authorizes what a lease may name. \
                 `splat-mcp provision --apply` writes one.",
                args.policy_file
            );
            None
        }
        Err(e) => {
            error!("Refusing to start: the lease ceiling at {} cannot be trusted: {e:#}", args.policy_file);
            std::process::exit(1);
        }
    };

    if args.workload_uid == 0 || args.workload_gid == 0 {
        error!(
            "Refusing to start: --workload-uid/--workload-gid resolve to root ({}/{}). A leased \
             tool that runs as root is not leased.",
            args.workload_uid, args.workload_gid
        );
        std::process::exit(1);
    }

    let workload_ids = WorkloadIdentity { uid: args.workload_uid, gid: args.workload_gid };
    // Compared against the absolute working directory of every lease that asks for a workspace, so a
    // relative root would match nothing and every such lease would be refused with a misleading reason.
    if !Path::new(&args.missions_root).is_absolute() {
        bail!("--missions-root must be an absolute path; got {:?}", args.missions_root);
    }
    let missions_root: Arc<str> = Arc::from(args.missions_root.trim_end_matches('/'));

    // Pins keep policy alive after a crash, but userspace deadlines are gone. Drain orphans before
    // serving again. The pin loader already drained enforcing leases before clearing stale maps;
    // this also covers a mock daemon's leftovers.
    match EphemeralCgroup::reap_orphans(Path::new(cgroup::BASE_PATH)) {
        Ok(drained) if drained.is_empty() => {}
        Ok(drained) => warn!(
            "Ended {} orphaned lease(s) a previous daemon left running: {drained:?}",
            drained.len()
        ),
        Err(e) => {
            error!("Refusing to start: an orphaned lease cgroup could not be drained: {e:#}");
            std::process::exit(1);
        }
    }
    cow::reap_leftovers(Path::new(cow::SCRATCH_BASE))?;
    // The skeletons of their jails go the same way; only empty directories and links are removed.
    match jail::reap_leftover_roots(Path::new(jail::ROOTS_BASE)) {
        Ok(0) => {}
        Ok(n) => warn!("Removed {n} jail skeleton(s) a previous daemon left under {}", jail::ROOTS_BASE),
        Err(e) => warn!("Could not sweep {}: {e:#}", jail::ROOTS_BASE),
    }

    let lease_manager = LeaseManager::new(bpf_sync);

    // Recovery precedes reuse: a dead daemon may have left private workspaces owned by this range.
    // Mock mode never claims this boundary, and a full pool never falls back to the legacy UID.
    let identities = if is_root && lease_manager.is_enforcing() {
        Some(identities::IdentityPool::reserved(
            args.secret_uid_start, args.secret_uid_count, args.workload_uid, args.workload_gid)?)
    } else { None };
    let workspace_recovery = identities.as_ref().map(|_|
        secret_recovery::Registry::recover(Path::new(missions_root.as_ref()))).transpose()?;

    let secret_broker = if let Some(path) = &args.secret_socket {
        if !is_root || !lease_manager.is_enforcing() {
            bail!("secret delivery requires a root daemon with enforcing BPF");
        }
        let broker = secrets::Broker::new(identities.as_ref().expect("enforcing identity pool").clone())
            .with_recovery(workspace_recovery.as_ref().expect("enforcing workspace recovery").clone());
        let listener = secrets::bind(path)?;
        tokio::spawn(secrets::serve(listener, broker.clone()));
        Some(broker)
    } else { None };

    // systemd stops this daemon with SIGTERM, and the workloads it leased are not in its own cgroup,
    // so they would outlive the stop. End them with their pinned policy still installed, then exit
    // cleanly; the unit restarts only on failure.
    tokio::spawn(async move {
        let mut terminate = signal(SignalKind::terminate()).expect("install the SIGTERM handler");
        let mut interrupt = signal(SignalKind::interrupt()).expect("install the SIGINT handler");
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        match EphemeralCgroup::reap_orphans(Path::new(cgroup::BASE_PATH)) {
            Ok(drained) if drained.is_empty() => info!("Stopping; no lease was running."),
            Ok(drained) => warn!("Stopping; ended {} leased workload(s) still running: {drained:?}", drained.len()),
            Err(e) => error!("Stopping, but a leased workload could not be drained; its pinned policy remains: {e:#}"),
        }
        std::process::exit(0);
    });

    // Background expiration reaper
    let reaper_mgr = lease_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            for l in reaper_mgr.take_expired() {
                // Order is the whole point. Deleting the map entries first would leave a live
                // process in a cgroup the hooks no longer recognise, and every hook returns allow
                // for an unlisted cgroup - so the previous reaper did not end an overrunning
                // workload, it FREED it. Kill inside the still-installed policy, then withdraw it.
                match EphemeralCgroup::kill_tree(&l.cgroup_path) {
                    Ok(0) => info!("Expired lease for mission {} (cg {}); nothing was still running", l.mission_id, l.cgroup_id),
                    Ok(n) => warn!(
                        "Expired lease for mission {} (cg {}): killed {n} process(es) that outlived it",
                        l.mission_id, l.cgroup_id
                    ),
                    Err(e) => {
                        // A surviving process keeps its lease so that it stays contained, and the
                        // lease goes back into the table so the next tick tries again. It used to
                        // be dropped from the table here with its policy still installed, which
                        // left the map entries to leak for the daemon's lifetime and the survivor
                        // to nobody's attention but this log line.
                        error!(
                            "Expired lease for mission {} (cg {}) could NOT be drained: {e:#}. Holding its policy installed and retrying next tick.",
                            l.mission_id, l.cgroup_id
                        );
                        reaper_mgr.hold_expired(l);
                        continue;
                    }
                }

                // Only withdraw the policy once the cgroup is empty.
                reaper_mgr.release_expired(&l);
            }
        }
    });

    let addr: SocketAddr = args.listen.parse().context("parse listen address")?;
    let listener = TcpListener::bind(addr).await.context("bind TCP listener")?;
    info!("SPLAT eBPF daemon listening and ready for requests at {addr}");

    let clients = Arc::new(tokio::sync::Semaphore::new(128));

    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let Ok(client_slot) = clients.clone().try_acquire_owned() else { continue; };
                info!("Accepted connection from {peer}");
                let mgr = lease_manager.clone();
                let viol_tx_clone = viol_tx.clone();
                let auth = peer_auth.clone();
                let ceiling_for_client = lease_ceiling.clone();
                let missions_root_for_client = missions_root.clone();
                let signer_for_client = outcome_signer.clone();
                let receipts_for_client = receipt_store.clone();
                let broker_for_client = secret_broker.clone();
                let identities_for_client = identities.clone();
                let recovery_for_client = workspace_recovery.clone();
                tokio::spawn(async move {
                    let _client_slot = client_slot;
                    if let Err(e) = handle_client(socket, mgr, viol_tx_clone, auth, workload_ids, ceiling_for_client, missions_root_for_client, signer_for_client, receipts_for_client, broker_for_client, identities_for_client, recovery_for_client).await {
                        error!("Client session error: {e:#}");
                    }
                });
            }
            Err(e) => {
                warn!("Accept failed: {e}");
            }
        }
    }
}

/// The unprivileged identity a leased tool is dropped to before it execs.
#[derive(Clone, Copy)]
struct WorkloadIdentity {
    uid: u32,
    gid: u32,
}

/// The largest request frame this daemon will hold in memory, not counting the newline.
///
/// `read_line` grows a String until it meets one, and this loop ran it BEFORE the auth check - so
/// anything that could open the socket could make a root process allocate without bound simply by
/// never sending a newline. 1 MiB is orders of magnitude above the largest real envelope (a lease
/// with its argv and its path lists) and far below anything this host would notice.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Reads one newline-delimited frame into `line`, refusing one that would grow past
/// [`MAX_FRAME_BYTES`]. Returns the number of bytes read; 0 means the peer is done.
///
/// The cap is read through `take`, so an oversized frame is never accumulated: the reader stops one
/// byte past the limit and that byte is what proves the frame was too long. A frame of exactly the
/// limit still parses, because the extra byte it stops on is the delimiter.
async fn read_frame(reader: &mut (impl AsyncBufRead + Unpin), line: &mut String) -> Result<usize> {
    line.clear();
    let read = reader.take(MAX_FRAME_BYTES as u64 + 1).read_line(line).await?;
    if read > MAX_FRAME_BYTES && !line.ends_with('\n') {
        bail!("a request frame may not exceed {MAX_FRAME_BYTES} bytes");
    }

    Ok(read)
}

/// The most of a tool's output one STDOUT or STDERR frame carries.
///
/// The pumps used to `read_line` into a String, which grows until it meets a newline - so a tool that
/// printed one long line, or no newline at all, grew a root process's memory by the size of its output
/// before a byte of it was forwarded. A line longer than this arrives as several frames, which the
/// bridge concatenates; nothing in the protocol promised one frame per line.
const MAX_OUTPUT_CHUNK_BYTES: usize = 64 * 1024;

/// Forwards one of the child's output streams as `kind` frames of at most [`MAX_OUTPUT_CHUNK_BYTES`]
/// each, never holding more than that in memory.
///
/// Frames carry text, so a chunk boundary must not fall inside a multi-byte character: the tail of an
/// incomplete one waits for the next read. A sequence that is not UTF-8 at all is replaced, as it
/// always was, rather than held for a completion that never comes.
async fn pump_output(reader: impl AsyncRead + Unpin, kind: &'static str, tx: mpsc::Sender<serde_json::Value>) {
    let mut reader = BufReader::new(reader);
    let mut buf: Vec<u8> = Vec::with_capacity(MAX_OUTPUT_CHUNK_BYTES);
    loop {
        // Room left after any held-back tail, so a frame never exceeds the cap even by that tail.
        let room = (MAX_OUTPUT_CHUNK_BYTES - buf.len()) as u64;
        match (&mut reader).take(room).read_until(b'\n', &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }

        let held_back = match std::str::from_utf8(&buf) {
            Ok(_) => 0,
            // error_len() is None only for a sequence cut short by the end of the buffer.
            Err(e) if e.error_len().is_none() => buf.len() - e.valid_up_to(),
            Err(_) => 0,
        };
        let emit = buf.len() - held_back;
        if emit > 0 {
            let text = String::from_utf8_lossy(&buf[..emit]).into_owned();
            if tx.send(serde_json::json!({ "type": kind, "data": text })).await.is_err() {
                return;
            }
            buf.drain(..emit);
        }
    }

    if !buf.is_empty() {
        let text = String::from_utf8_lossy(&buf).into_owned();
        let _ = tx.send(serde_json::json!({ "type": kind, "data": text })).await;
    }
}

/// One VIOLATION frame, as the bridge reads it. `timestampMs` is this daemon's clock at the moment the
/// event was drained from the ring buffer; the kernel record carries no time of its own.
fn violation_frame(v: &ViolationEvent) -> serde_json::Value {
    serde_json::json!({
        "type": "VIOLATION",
        "cgroupId": v.cgroup_id,
        "pid": v.pid,
        "hook": v.hook,
        "detail": v.detail,
        "detailText": v.detail_text,
        "comm": v.comm,
        "timestampMs": v.timestamp_ms,
        "ktimeNs": v.ktime_ns,
        "seq": v.seq
    })
}

fn step_violation_frame(v: &ViolationEvent, secret_step: bool) -> serde_json::Value {
    let mut frame = violation_frame(v);
    if secret_step {
        // A process can put its input into its own name; audit frames must not echo that channel.
        frame["comm"] = serde_json::Value::String("[withheld]".into());
    }
    frame
}

/// Opens protocol 3's session: reads the caller's HELLO and answers it with this daemon's proof that it
/// holds the token, or refuses and returns None. Nothing else is read from a connection before this.
async fn open_session(
    reader: &mut (impl AsyncBufRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    line: &mut String,
    peer_auth: &PeerAuth,
) -> Result<Option<auth::Session>> {
    let refusal = match read_frame(reader, line).await {
        Ok(0) => return Ok(None),
        Ok(_) => match hello_nonce(line.trim()) {
            Ok((client_nonce, prove_frames)) => {
                let session = auth::Session { client_nonce, server_nonce: auth::random_bytes()?, prove_frames };
                let mut challenge = serde_json::json!({
                    "type": "CHALLENGE",
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverNonce": auth::hex(&session.server_nonce),
                    "serverProof": auth::hex(&peer_auth.daemon_proof(&session.client_nonce, &session.server_nonce, prove_frames)),
                });
                if prove_frames {
                    // Said in the frame AND bound into the proof above by its label: a relay that
                    // dropped this field would leave a proof the caller checks under the other label
                    // and refuses, rather than a connection that quietly went unproven.
                    challenge["framesProven"] = serde_json::Value::Bool(true);
                }
                writer.write_all(format!("{challenge}\n").as_bytes()).await?;
                return Ok(Some(session));
            }
            Err(reason) => reason,
        },
        Err(e) => e.to_string(),
    };

    warn!("Refused a connection at its handshake: {refusal}");
    let err_resp = serde_json::json!({
        "type": "STDERR",
        "data": format!("SPLAT refused the request: {refusal}.\n")
    });
    let _ = writer.write_all(format!("{err_resp}\n").as_bytes()).await;
    Ok(None)
}

/// The client nonce from a protocol 3 HELLO, and whether the caller asked for this daemon's frames
/// to be proven - or why the frame is not a HELLO. A caller that does not ask is one older than the
/// field, and is answered unwrapped; the field is how a bridge and a daemon of different ages agree.
fn hello_nonce(frame: &str) -> std::result::Result<([u8; auth::NONCE_BYTES], bool), String> {
    let hello: serde_json::Value =
        serde_json::from_str(frame).map_err(|e| format!("the first frame is not JSON ({e})"))?;

    // A protocol 2 caller opens with a request carrying the token in the clear. By the time it is read
    // here it has been sent; refusing it is what makes sending it pointless.
    if hello.get("type").and_then(|t| t.as_str()) != Some("HELLO") {
        return Err(format!(
            "this daemon speaks protocol {PROTOCOL_VERSION}, which opens with a HELLO and never carries the \
             token itself. A caller that sends the token with its request speaks protocol 2 and must be updated"
        ));
    }

    let version = hello.get("protocolVersion").and_then(|v| v.as_u64()).unwrap_or(0);
    if version != PROTOCOL_VERSION {
        return Err(format!(
            "protocol version {version} is not supported; this daemon speaks version {PROTOCOL_VERSION}"
        ));
    }

    let client_nonce = hello
        .get("clientNonce")
        .and_then(|n| n.as_str())
        .and_then(auth::from_hex)
        .ok_or_else(|| format!("a HELLO carries its clientNonce as {} hex digits", auth::NONCE_BYTES * 2))?;
    let prove_frames = hello.get("proveFrames").and_then(|p| p.as_bool()).unwrap_or(false);
    Ok((client_nonce, prove_frames))
}

/// Every frame this daemon sends on one connection after the CHALLENGE, proven when the caller asked.
///
/// Protocol 3 proved every request and none of the answers: VIOLATION, STDOUT and EXIT reached the
/// bridge, and through it the ledger, on the strength of the handshake alone. On loopback that was
/// defensible; before anything leaves the host it has to be symmetric. A caller that sent
/// `proveFrames` in its HELLO is answered with each frame wrapped as
/// `{"type":"PROVEN","proof":<hex>,"frame":<the frame, as a string>}`, proven over both nonces, the
/// frame's number on this connection and its exact bytes - the request proof's shape, in the other
/// direction. One that did not ask is answered as before, so a bridge older than the daemon keeps
/// working, and reports the frames as unproven rather than believing them proven.
struct FrameSink<W> {
    writer: W,
    proving: Option<(Arc<PeerAuth>, [u8; auth::NONCE_BYTES], [u8; auth::NONCE_BYTES])>,
    sequence: u64,
}

impl<W: AsyncWrite + Unpin> FrameSink<W> {
    fn new(writer: W, session: &auth::Session, peer_auth: &Arc<PeerAuth>) -> Self {
        Self {
            writer,
            proving: session
                .prove_frames
                .then(|| (peer_auth.clone(), session.client_nonce, session.server_nonce)),
            sequence: 0,
        }
    }

    /// One frame on its own line, wrapped and proven when this connection asked for it.
    async fn send(&mut self, frame: &serde_json::Value) -> std::io::Result<()> {
        let line = match &self.proving {
            Some((peer_auth, client_nonce, server_nonce)) => {
                // Proven over the frame's bytes exactly as they travel, carried as a string, so the
                // bridge checks the proof over those bytes before it parses any of them.
                let bytes = frame.to_string();
                let proof = peer_auth.frame_proof(client_nonce, server_nonce, self.sequence, bytes.as_bytes());
                self.sequence += 1;
                serde_json::json!({ "type": "PROVEN", "proof": auth::hex(&proof), "frame": bytes }).to_string()
            }
            None => frame.to_string(),
        };
        tokio::time::timeout(Duration::from_secs(5), self.writer.write_all(format!("{line}\n").as_bytes()))
            .await.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "frame write timed out"))?
    }
}

/// The request inside an AUTHENTICATED frame, once its proof holds for this session and for its place
/// on it - or why it does not.
fn authenticated_request(
    frame: &str,
    session: &auth::Session,
    peer_auth: &PeerAuth,
    sequence: u64,
) -> std::result::Result<serde_json::Value, String> {
    let envelope: serde_json::Value =
        serde_json::from_str(frame).map_err(|e| format!("a frame is not JSON ({e})"))?;
    if envelope.get("type").and_then(|t| t.as_str()) != Some("AUTHENTICATED") {
        return Err("after the handshake, every request travels in an AUTHENTICATED frame".to_string());
    }

    let request = envelope
        .get("request")
        .and_then(|r| r.as_str())
        .ok_or_else(|| "an AUTHENTICATED frame carries its request as a string".to_string())?;
    let proof = envelope
        .get("proof")
        .and_then(|p| p.as_str())
        .and_then(auth::from_hex)
        .ok_or_else(|| format!("an AUTHENTICATED frame carries its proof as {} hex digits", auth::NONCE_BYTES * 2))?;

    // Over the request's bytes exactly as they arrived, before any of them is parsed.
    if !peer_auth.verifies(&session.client_nonce, &session.server_nonce, sequence, request.as_bytes(), &proof) {
        return Err("the request's proof does not match this daemon's token".to_string());
    }

    serde_json::from_str(request).map_err(|e| format!("its request is not valid JSON ({e})"))
}

async fn handle_client(
    socket: TcpStream,
    lease_mgr: LeaseManager,
    viol_tx: broadcast::Sender<ViolationEvent>,
    peer_auth: Arc<PeerAuth>,
    workload: WorkloadIdentity,
    lease_ceiling: Option<Arc<Ceiling>>,
    missions_root: Arc<str>,
    outcome_signer: Option<Arc<outcome::OutcomeSigner>>,
    receipt_store: Option<receipts::Store>,
    secret_broker: Option<secrets::Broker>,
    identities: Option<identities::IdentityPool>,
    workspace_recovery: Option<secret_recovery::Registry>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // Protocol 3: the caller's HELLO, and this daemon's proof that it holds the token, before anything
    // else is read. Protocol 2 put the token itself in every request, so a caller handed it to whatever
    // answered on this port - and while this daemon was not listening, anything in the guest could.
    let Some(session) = tokio::time::timeout(Duration::from_secs(10),
        open_session(&mut buf_reader, &mut writer, &mut line, &peer_auth)).await.context("handshake timed out")?? else {
        return Ok(());
    };
    let _secret_session = match &secret_broker {
        Some(broker) if session.prove_frames => Some(broker.register(&session)?),
        _ => None,
    };
    // From here every frame this daemon sends goes through the sink, which proves each one when the
    // caller asked - refusals included, because a refusal is a frame the caller acts on.
    let mut out = FrameSink::new(writer, &session, &peer_auth);
    let mut sequence: u64 = 0;

    loop {
        match tokio::time::timeout(Duration::from_secs(30), read_frame(&mut buf_reader, &mut line))
            .await.context("idle session timed out")? {
            Ok(0) => break, // Peer closed.
            Ok(_) => {}
            Err(e) => {
                // Say so, then hang up. The rest of an oversized frame is still in the stream, and
                // reading on from the middle of it would turn one refused request into a series of
                // accepted ones assembled out of its tail. A legitimate caller reconnects.
                warn!("Closing connection: {e}");
                let err_resp = serde_json::json!({
                    "type": "STDERR",
                    "data": format!("SPLAT refused the request: {e}.\n")
                });
                let _ = out.send(&err_resp).await;
                break;
            }
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        // Every frame after the handshake is one request and its proof. One that does not prove itself
        // ends the connection: nothing in it can be believed, including where the next frame begins.
        let parsed: serde_json::Value = match authenticated_request(trimmed, &session, &peer_auth, sequence) {
            Ok(request) => request,
            Err(reason) => {
                warn!("Closing connection: {reason}");
                let err_resp = serde_json::json!({
                    "type": "STDERR",
                    "data": format!("SPLAT refused the request: {reason}.\n")
                });
                let _ = out.send(&err_resp).await;
                break;
            }
        };
        sequence += 1;

        let req_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match req_type {
            "HEALTH_CHECK" => {
                // Answered only inside a session, like everything else: it carries the kernel version,
                // the live lease count and `enforcing`, which tells a stranger exactly when this daemon
                // will run work it cannot contain.

                let health = SubstrateHealth::observe(lease_mgr.is_enforcing());
                let resp = serde_json::json!({
                    "type": "HEALTH_RESPONSE",
                    "bpfLsmActive": health.bpf_lsm_active,
                    "cgroupV2Active": health.cgroup_v2_active,
                    "overlayFsSupported": health.overlayfs_supported,
                    "kernelVersion": health.kernel_version,
                    // Named separately from the three booleans because it is the one a caller must
                    // gate on: false means this daemon will run work it cannot contain.
                    "enforcing": lease_mgr.is_enforcing(),
                    "activeLeaseCount": lease_mgr.get_active_count(),
                    // Whether a ceiling bounds every lease here; without one the token alone
                    // authorizes whatever a request names.
                    "ceiling": lease_ceiling.is_some(),
                    "explicitEnvironment": true,
                    "secretStdinSupported": secret_broker.is_some() && lease_mgr.is_enforcing(),
                    "boundReceiptLookup": receipt_store.is_some() && outcome_signer.is_some() && lease_mgr.is_enforcing()
                });
                out.send(&resp).await?;
            }

            "RECEIPT_LOOKUP" => {
                // Lookup authenticates a fresh session and requires the original exact binding.
                // Missing/expired evidence never authorizes executing the mission again.
                let response = match (&receipt_store, parsed["missionId"].as_str(),
                    parsed["executionContext"].as_str(), parsed["executionPolicySha256"].as_str()) {
                    (Some(store), Some(mission), Some(context), Some(policy)) if session.prove_frames =>
                        store.lookup(mission, context, policy)?,
                    _ => serde_json::json!({"type":"RECEIPT_RESPONSE", "status":"unavailable"}),
                };
                out.send(&response).await?;
            }

            "EXECUTE_TOOL" | "EXECUTE_POLICY" | "EXECUTE_AGENT" | "EXECUTE_BOUND" => {
                // The session proved the caller before a single field of this was read. It names a
                // command for a root daemon to run, and until the caller is known none of it is a
                // request, only an offer.

                let mission_id = parsed.get("missionId").and_then(|v| v.as_str()).unwrap_or("default");
                let command = parsed.get("command").and_then(|v| v.as_str()).unwrap_or("/bin/sh");
                // One contract, checked before anything else is read. A caller that does not name
                // a version is a v1 caller whose arguments cannot be reconstructed.
                let protocol_version = parsed.get("protocolVersion").and_then(|v| v.as_u64()).unwrap_or(1);
                if protocol_version != PROTOCOL_VERSION {
                    warn!("Rejected an EXECUTE_TOOL at protocol version {protocol_version}");
                    let err_chunk = serde_json::json!({
                        "type": "STDERR",
                        "data": format!(
                            "SPLAT refused the request: protocol version {protocol_version} is not supported. \
                             This daemon speaks version {PROTOCOL_VERSION}, which requires an explicit argv array.\n")
                    });
                    out.send(&err_chunk).await?;
                    let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                    out.send(&exit_chunk).await?;
                    line.clear();
                    continue;
                }

                // argv verbatim. Absent is distinct from empty: empty means "no arguments", which
                // is a legitimate request, while absent means the caller did not speak v2.
                let argv: Vec<String> = match string_list(&parsed, "argv") {
                    Some(arguments) => arguments,
                    _ => {
                        warn!("Rejected an EXECUTE_TOOL with no argv array");
                        let err_chunk = serde_json::json!({
                            "type": "STDERR",
                            "data": "SPLAT refused the request: argv must be an array of strings. \
                                     A pre-quoted argument string cannot be split back into arguments.\n"
                        });
                        out.send(&err_chunk).await?;
                        let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                        out.send(&exit_chunk).await?;
                        line.clear();
                        continue;
                    }
                };
                let work_dir = parsed.get("workingDirectory").and_then(|v| v.as_str()).unwrap_or("/tmp");
                let duration_sec = parsed.get("leaseDurationSeconds").and_then(|v| v.as_u64()).unwrap_or(30) as u32;
                let ephemeral_workspace = parsed.get("ephemeralWorkspace").and_then(|v| v.as_bool()).unwrap_or(false);
                let execution_context = match outcome::validate_context(&parsed, lease_mgr.is_enforcing(), outcome_signer.is_some()) {
                    Ok(context) => context,
                    Err(error) => {
                        out.send(&serde_json::json!({"type":"STDERR", "data":format!("SPLAT refused execution context: {error}.\n")})).await?;
                        out.send(&serde_json::json!({"type":"EXIT", "exitCode":-1})).await?;
                        continue;
                    }
                };

                // Parse and compile before provisioning anything; legacy requests cannot silently
                // discard a policy, and a development daemon cannot claim this additional boundary.
                let execution_policy = match execution_policy::from_request(&parsed, lease_mgr.is_enforcing()) {
                    Ok(policy) => policy.map(Arc::new),
                    Err(error) => {
                        out.send(&serde_json::json!({"type":"STDERR", "data":format!("SPLAT refused executionPolicy: {error}.\n")})).await?;
                        out.send(&serde_json::json!({"type":"EXIT", "exitCode":-1})).await?;
                        continue;
                    }
                };

                let environment = match execution::environment(&parsed) {
                    Ok(environment) => environment,
                    Err(_) => {
                        out.send(&serde_json::json!({"type":"STDERR", "data":"SPLAT refused the declared environment.\n"})).await?;
                        out.send(&serde_json::json!({"type":"EXIT", "exitCode":-1})).await?;
                        continue;
                    }
                };
                if let Some(context) = execution_context {
                    let reserved = receipt_store.as_ref().context("receipt cache unavailable")
                        .and_then(|store| store.reserve(mission_id, context,
                            execution_policy.as_ref().map_or("none", |p| p.sha256.as_str())));
                    if let Err(error) = reserved {
                        out.send(&serde_json::json!({"type":"STDERR", "data":format!("SPLAT refused bound admission: {error}.\n")})).await?;
                        out.send(&serde_json::json!({"type":"EXIT", "exitCode":-1})).await?;
                        continue;
                    }
                }
                // Arguments may contain caller data; the service journal is not a transcript.
                info!("Executing tool for mission {mission_id}");

                // 0. Refuse policy this daemon cannot enforce.
                //
                // A field parsed into the lease and then never acted on is worse than an absent
                // feature: the caller reads its request back as accepted. Both of these were in
                // exactly that state - readOnlyFs was parsed into LeaseConfig and consulted by
                // nothing, and overlayFs was sent by the bridge on every compiled template and
                // consumed by nothing at all. The supported matrix lives in SUPPORTED_POLICY.md;
                // anything outside it is refused here rather than accepted and dropped.
                let mut unsupported: Vec<&str> = Vec::new();

                // readOnlyFs is real now: every jailed workload has a read-only root, and the flag
                // makes its working directory read-only too. What cannot honour it is a daemon that
                // jails nothing - the openly non-enforcing dev path - and that one still refuses.
                let read_only_fs = parsed.get("readOnlyFs").and_then(|v| v.as_bool()).unwrap_or(false);
                if read_only_fs && !lease_mgr.is_enforcing() {
                    unsupported.push(
                        "readOnlyFs: this daemon is not enforcing, so no mount namespace is established \
                         for the workload and a read-only root cannot be imposed on it",
                    );
                }

                // The mission id names a cgroup and a jail root. A path separator or a '..' in it
                // would name something else.
                if !mission_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
                    unsupported.push("missionId: only letters, digits, '-', '_' and '.' can name a lease");
                }

                // A workspace this daemon makes is made only directly under its missions root, and
                // its name is one safe path component: a lease that asks for one anywhere else asks
                // this daemon to create a directory it did not decide to, and is refused.
                if ephemeral_workspace && !workspace::is_mission_workspace(&missions_root, work_dir) {
                    unsupported.push(
                        "ephemeralWorkspace: a workspace is made only directly under this daemon's \
                         missions root, named by one path component",
                    );
                }

                let enable_cow = parsed
                    .get("overlayFs")
                    .and_then(|v| v.get("enableCow"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if enable_cow && !lease_mgr.is_enforcing() {
                    unsupported.push(
                        "overlayFs.enableCow: this daemon is not enforcing, so no workload mount namespace is established",
                    );
                }
                let scratch_exec_value = parsed.get("overlayFs").and_then(|v| v.get("allowScratchExec"));
                let allow_scratch_exec = scratch_exec_value.and_then(|v| v.as_bool()).unwrap_or(false);
                if scratch_exec_value.is_some_and(|v| !v.is_boolean()) {
                    unsupported.push("overlayFs.allowScratchExec: must be a boolean");
                }
                if allow_scratch_exec && !enable_cow {
                    unsupported.push("overlayFs.allowScratchExec: requires overlayFs.enableCow");
                }
                if enable_cow && !Path::new(work_dir).is_dir() && !ephemeral_workspace {
                    unsupported.push("overlayFs.enableCow: workingDirectory must exist; no fallback lowerdir is permitted");
                }

                if !unsupported.is_empty() {
                    error!("Refusing to execute for mission {mission_id}: unsupported policy requested");
                    let err_chunk = serde_json::json!({
                        "type": "STDERR",
                        "data": format!(
                            "SPLAT refused the request: this daemon does not enforce {}. \
                             Accepting it would report a containment it does not provide.\n",
                            unsupported.join("; ")
                        )
                    });
                    out.send(&err_chunk).await?;
                    let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                    out.send(&exit_chunk).await?;
                    line.clear();
                    continue;
                }

                // 0.4 Every dimension of the lease must be DECLARED, never inherited.
                //
                // An absent key used to take a default this daemon chose: 127.0.0.1 and ports 80 and
                // 443 for egress, and /bin/sh, /bin/ping and /usr/bin/curl for exec. So a caller that
                // forgot a field - or never had one - was handed a lease wider than anything it asked
                // for, and the kernel then enforced that faithfully. Nobody had decided; a default
                // had. An EMPTY list is still honoured as "nothing permitted", because that is a
                // decision. What is refused is the missing key, which is the absence of one.
                let allow_network = parsed.get("allowNetwork").and_then(|v| v.as_bool()).unwrap_or(false);
                let mut undeclared: Vec<&str> = Vec::new();
                if string_list(&parsed, "allowedExecPaths").is_none() {
                    undeclared.push("allowedExecPaths");
                }
                if allow_network {
                    if string_list(&parsed, "allowedEgressIps").is_none() {
                        undeclared.push("allowedEgressIps");
                    }
                    if parsed.get("allowedEgressPorts").and_then(|v| v.as_array()).is_none() {
                        undeclared.push("allowedEgressPorts");
                    }
                }

                if !undeclared.is_empty() {
                    error!("Refusing to execute for mission {mission_id}: undeclared lease policy");
                    let err_chunk = serde_json::json!({
                        "type": "STDERR",
                        "data": format!(
                            "SPLAT refused the request: this lease declares no {}. A missing field is \
                             not a default here - the daemon will not decide what a lease permits.\n",
                            undeclared.join(", nor ")
                        )
                    });
                    out.send(&err_chunk).await?;
                    let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                    out.send(&exit_chunk).await?;
                    line.clear();
                    continue;
                }

                // 0.45 The ceiling. Everything the request names has now been declared; whether the
                // operator allows it on this host is a separate question, answered in the guest
                // where a stolen token cannot reach around it.
                let exec_list = string_list(&parsed, "allowedExecPaths").unwrap_or_default();
                let egress_ip_list = string_list(&parsed, "allowedEgressIps").unwrap_or_default();
                let egress_port_list: Vec<u32> = parsed
                    .get("allowedEgressPorts")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().filter_map(|p| p.as_u64().map(|n| n as u32)).collect())
                    .unwrap_or_default();
                if let Some(c) = &lease_ceiling {
                    let ask = ceiling::Ask {
                        exec_paths: &exec_list,
                        allow_network: allow_network,
                        egress_ips: &egress_ip_list,
                        egress_ports: &egress_port_list,
                    };
                    if let Err(reason) = c.check(&ask).and_then(|_| c.check_scratch_exec(allow_scratch_exec)) {
                        error!("Refusing to execute for mission {mission_id}: outside the lease ceiling: {reason}");
                        let err_chunk = serde_json::json!({
                            "type": "STDERR",
                            "data": format!(
                                "SPLAT refused the request: outside this host's lease ceiling: {reason}. The ceiling \
                                 is the operator's, in the guest, and the token does not raise it.\n"
                            )
                        });
                        out.send(&err_chunk).await?;
                        let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                        out.send(&exit_chunk).await?;
                        line.clear();
                        continue;
                    }
                }
                let duration_sec = lease_ceiling.as_ref().map_or(duration_sec, |c| c.clamp_duration(duration_sec));

                let mut step_secret = if parsed.get("secretGrant").is_some() {
                    let acquired = match &secret_broker {
                        Some(broker) if session.prove_frames && lease_mgr.is_enforcing() =>
                            broker.take(&session, &parsed, Instant::now()),
                        _ => Err(anyhow::anyhow!("secret delivery is unavailable")),
                    };
                    match acquired {
                        Ok(secret) => Some(secret),
                        Err(_) => {
                            out.send(&serde_json::json!({"type":"STDERR", "data":"SPLAT refused the secret grant.\n"})).await?;
                            out.send(&serde_json::json!({"type":"EXIT", "exitCode":-1})).await?;
                            continue;
                        }
                    }
                } else { None };
                let secret_step = step_secret.is_some();
                let mut ordinary_workload = if !secret_step {
                    if let Some(pool) = &identities {
                        match pool.acquire() {
                            Ok(identity) => Some(workload::Workload::new(identity,
                                workspace_recovery.as_ref().expect("enforcing workspace recovery").clone())),
                            Err(_) => {
                                out.send(&serde_json::json!({"type":"STDERR", "data":"SPLAT refused execution: private lease identity capacity is unavailable.\n"})).await?;
                                out.send(&serde_json::json!({"type":"EXIT", "exitCode":-1})).await?;
                                continue;
                            }
                        }
                    } else { None }
                } else { None };
                let private_uid = step_secret.as_ref().map(|secret| secret.identity.id())
                    .or_else(|| ordinary_workload.as_ref().map(|ordinary| ordinary.identity.id()));
                let workload = private_uid.map_or(workload, |uid| WorkloadIdentity { uid, gid: uid });

                // 0.47 The mission's workspace, made here where root can make one and the workload
                // cannot: owned by the workload, mode 0700, removed when the lease ends. Made after the
                // ceiling admitted the lease and before the cgroup exists, so a refused lease leaves
                // no directory and a made directory always has a lease to be removed with.
                let workspace_created = if ephemeral_workspace {
                    match workspace::create(Path::new(work_dir), workload.uid, workload.gid) {
                        Ok(created) => created,
                        Err(e) => {
                            error!("Refusing to execute for mission {mission_id}: the workspace could not be made: {e:#}");
                            let err_chunk = serde_json::json!({
                                "type": "STDERR",
                                "data": format!("SPLAT refused to execute: the mission's workspace could not be made ({e}).\n")
                            });
                            out.send(&err_chunk).await?;
                            let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                            out.send(&exit_chunk).await?;
                            line.clear();
                            continue;
                        }
                    }
                } else {
                    false
                };

                if let Some(secret) = &mut step_secret {
                    if workspace_created { secret.register_workspace(Path::new(work_dir))?; }
                }
                if let Some(ordinary) = &mut ordinary_workload {
                    if workspace_created { ordinary.register_workspace(Path::new(work_dir))?; }
                }

                // 0.5 Resolve the clamps.
                //
                // The cgroup used to be provisioned from three constants here while the request's
                // own limits were parsed thirty lines below and then never applied to any
                // controller, so a caller asking for 64 MiB received 256 and was told it had been
                // accepted. Clamps come from the caller but only downwards: a lease is a grant, not
                // a negotiation, and letting a request raise its own ceiling makes the clamp
                // advisory.
                let cgroup_limits = {
                    let l = parsed.get("limits");
                    let get_u64 = |k: &str, ceiling: u64| {
                        l.and_then(|v| v.get(k))
                            .and_then(|v| v.as_u64())
                            .map(|n| n.min(ceiling))
                            .unwrap_or(ceiling)
                    };
                    // The daemon's constants, lowered further by the ceiling where it sets a limit.
                    let (memory_cap, cpu_cap, pids_cap) = match &lease_ceiling {
                        Some(c) => (
                            c.memory_ceiling(MAX_MEMORY_BYTES_CEILING),
                            c.cpu_ceiling(MAX_CPU_PERCENT_CEILING),
                            c.pids_ceiling(MAX_PIDS_CEILING),
                        ),
                        None => (MAX_MEMORY_BYTES_CEILING, MAX_CPU_PERCENT_CEILING, MAX_PIDS_CEILING),
                    };
                    cgroup::CgroupLimits {
                        max_memory_bytes: get_u64("maxMemoryBytes", memory_cap),
                        max_cpu_percent: get_u64("maxCpuPercent", cpu_cap as u64) as u32,
                        max_pids: get_u64("maxPids", pids_cap as u64) as u32,
                    }
                };

                // 1. Provision Ephemeral Cgroup.
                //
                // When the daemon is enforcing, a cgroup we could not create is a cgroup we cannot
                // police, so the request is refused rather than run in the host's own cgroup. The
                // previous fallback logged a warning and executed anyway under a fabricated
                // cgroup_id of 1 - uncontained, while the caller was told the tool had run.
                // create() now also refuses when a controller did not take its clamp, so
                // "provisioned" and "clamped" are one outcome rather than two.
                let (cg, cgroup_is_real) = match EphemeralCgroup::create(mission_id, cgroup_limits) {
                    Ok(c) => (c, true),
                    Err(e) if lease_mgr.is_enforcing() => {
                        error!("Refusing to execute for mission {mission_id}: cgroup creation failed: {e}");
                        // A workspace made for a mission that never ran is removed with the refusal,
                        // and the EXIT frame says so: the caller's teardown reads it, not the daemon's
                        // log. Three refused missions left theirs behind on 2026-09-24.
                        let workspace_removed = workspace_created && workload::remove_workspace(ordinary_workload.as_mut(), Path::new(work_dir));
                        let err_chunk = serde_json::json!({
                            "type": "STDERR",
                            "data": format!("SPLAT refused to execute: no lease could be provisioned ({e}).\n")
                        });
                        out.send(&err_chunk).await?;
                        let mut exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                        if workspace_created {
                            exit_chunk["workspaceRemoved"] = serde_json::json!(workspace_removed);
                        }
                        out.send(&exit_chunk).await?;
                        line.clear();
                        continue;
                    }
                    Err(e) => {
                        // Not enforcing anyway (mock / unprivileged): the daemon has already said so
                        // at startup, so running uncontained here is honest rather than misleading.
                        warn!("Could not create cgroup: {e}. Not enforcing; running in standard process namespace.");
                        (
                            EphemeralCgroup {
                                path: std::path::PathBuf::from("/tmp"),
                                cgroup_id: 1,
                                effective: cgroup_limits,
                            },
                            false,
                        )
                    }
                };

                let lease_cfg = LeaseConfig {
                    mission_id: mission_id.to_string(),
                    working_directory: work_dir.to_string(),
                    allow_network,
                    // The caller's declared policy is the lease. These were hardcoded, so a governed
                    // template could name its one approved destination and the kernel would never
                    // hear about it - the 1:1:1 rule held on the Windows side and evaporated here.
                    // Empty only where the switch is off and the keys were therefore not required:
                    // an absent key with the network on was refused above.
                    allowed_egress_ips: string_list(&parsed, "allowedEgressIps").unwrap_or_default(),
                    allowed_egress_ports: parsed
                        .get("allowedEgressPorts")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|p| p.as_u64().map(|n| n as u32)).collect())
                        .unwrap_or_default(),
                    // Honoured by the jail: the working directory is bound read-only.
                    read_only_fs,
                    // Union, never replacement: a caller may add protected paths but must not be
                    // able to unprotect the ones this daemon always guards.
                    protected_paths: {
                        let mut paths = vec!["/etc/shadow".to_string(), "/etc/sudoers".to_string()];
                        // The ceiling's always-protected paths, before the caller's.
                        for always in lease_ceiling.iter().flat_map(|c| c.protected_paths()) {
                            if !paths.contains(always) {
                                paths.push(always.clone());
                            }
                        }
                        for extra in string_list(&parsed, "protectedPaths").unwrap_or_default() {
                            if !paths.contains(&extra) {
                                paths.push(extra);
                            }
                        }
                        paths
                    },
                    // The controller's list, and nothing else. The daemon used to append the requested
                    // command to its own allow-list and add /bin/sh, /bin/ping and /usr/bin/curl to
                    // every lease regardless of need - so a caller wrote its own policy, and every
                    // mission could reach a shell whether or not it asked. An explicit list from an
                    // authenticated controller is a policy; a list the daemon assembled from the
                    // request is a restatement of the request. Absent is refused above, not defaulted.
                    allowed_exec_paths: string_list(&parsed, "allowedExecPaths").unwrap_or_default(),
                    lease_duration_seconds: duration_sec,
                    // Resolved above, before the cgroup existed, and already read back out of the
                    // controllers - so this records what the kernel holds, not what was requested.
                    limits: lease::LeaseLimits {
                        max_memory_bytes: cg.effective.max_memory_bytes,
                        max_cpu_percent: cg.effective.max_cpu_percent,
                        max_pids: cg.effective.max_pids,
                    },
                };

                // A lease whose exec policy excludes the command it was created to run is
                // incoherent: the kernel would refuse the exec and the caller would read a bare
                // "Operation not permitted" as a daemon fault. Say so here instead.
                if !lease_cfg.allowed_exec_paths.iter().any(|p| p == command) {
                    error!("Refusing to execute for mission {mission_id}: '{command}' is not in this lease's allowedExecPaths");
                    let workspace_removed = workspace_created && workload::remove_workspace(ordinary_workload.as_mut(), Path::new(work_dir));
                    let err_chunk = serde_json::json!({
                        "type": "STDERR",
                        "data": format!(
                            "SPLAT refused to execute: '{command}' is not in this lease's allowedExecPaths.\n")
                    });
                    out.send(&err_chunk).await?;
                    let mut exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                    if workspace_created {
                        exit_chunk["workspaceRemoved"] = serde_json::json!(workspace_removed);
                    }
                    out.send(&exit_chunk).await?;
                    line.clear();
                    continue;
                }

                // A lease that could not be installed is a refusal, not a warning. register_lease
                // rolls back its own partial map writes and returns Err, so there is no state in
                // which the cgroup is policed while some of its protections are missing.
                let installed = if enable_cow {
                    cow::validate_policy(Path::new(work_dir), &lease_cfg.protected_paths, &lease_cfg.allowed_exec_paths)
                } else {
                    Ok(())
                }.and_then(|()| lease_mgr.register_lease(cg.cgroup_id, cg.path.clone(), &lease_cfg));
                if let Err(e) = installed {
                    error!("Refusing to execute for mission {mission_id}: {e:#}");
                    let workspace_removed = workspace_created && workload::remove_workspace(ordinary_workload.as_mut(), Path::new(work_dir));
                    let err_chunk = serde_json::json!({
                        "type": "STDERR",
                        "data": format!("SPLAT refused to execute: the capability lease could not be installed ({e}).\n")
                    });
                    out.send(&err_chunk).await?;
                    let mut exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                    if workspace_created {
                        exit_chunk["workspaceRemoved"] = serde_json::json!(workspace_removed);
                    }
                    out.send(&exit_chunk).await?;
                    line.clear();
                    continue;
                }

                // Bind the installed policy and read-back clamps, including the execution filter,
                // into the signed receipt. This is not a signature over an uninstalled request.
                let effective_policy_sha256 = {
                    use sha2::{Digest, Sha256};
                    let installed = installed.as_ref().expect("successful installation checked above");
                    format!("{:x}", Sha256::digest(serde_json::to_vec(&serde_json::json!({
                        "lease": lease_cfg, "executionPolicySha256": execution_policy.as_ref().map(|p| &p.sha256),
                        "overlay": enable_cow, "scratchExec": allow_scratch_exec,
                        "execInodes": installed.allowed_exec_inodes.iter().map(|i| (i.dev, i.ino)).collect::<Vec<_>>(),
                        "protectedInodes": installed.protected_inodes.iter().map(|i| (i.dev, i.ino)).collect::<Vec<_>>(),
                        "endpoints": installed.allowed_endpoints.iter().map(|e| (e.addr, e.port)).collect::<Vec<_>>()
                    }))?))
                };

                // 2. Spawn Subprocess
                let effective_work_dir = if Path::new(work_dir).exists() { work_dir } else { "/tmp" };

                // The jail's root, built here in the parent where allocation is allowed. A real
                // cgroup means a root daemon, and a root daemon jails every workload: there is no
                // configuration in which a leased tool runs with the host's root as its own. A root
                // that cannot be prepared refuses the request, as a cgroup that cannot be does.
                let jail_plan = if cgroup_is_real {
                    match jail::JailPlan::prepare(
                        Path::new(jail::ROOTS_BASE),
                        mission_id,
                        Path::new(effective_work_dir),
                        read_only_fs,
                        enable_cow,
                        Path::new("/"),
                    ).and_then(|mut plan| {
                        if private_uid.is_some() { plan.set_workload_identity(workload.uid, workload.gid)?; }
                        if allow_scratch_exec {
                            plan.authorize_scratch_exec(lease_mgr.scratch_exec_map()?, cg.cgroup_id)?;
                        }
                        Ok(plan)
                    }) {
                        Ok(plan) => Some(Arc::new(plan)),
                        Err(e) => {
                            error!("Refusing to execute for mission {mission_id}: the jail root could not be prepared: {e:#}");
                            lease_mgr.revoke_lease(cg.cgroup_id);
                            let workspace_removed = workspace_created && workload::remove_workspace(ordinary_workload.as_mut(), Path::new(work_dir));
                            let err_chunk = serde_json::json!({
                                "type": "STDERR",
                                "data": format!("SPLAT refused to execute: the workload's root could not be prepared ({e}).\n")
                            });
                            out.send(&err_chunk).await?;
                            let mut exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                            if workspace_created {
                                exit_chunk["workspaceRemoved"] = serde_json::json!(workspace_removed);
                            }
                            out.send(&exit_chunk).await?;
                            line.clear();
                            continue;
                        }
                    }
                } else {
                    None
                };

                // What was installed, read back and told to the caller before the tool's first byte:
                // the cgroup and the clamps its controllers took, whether the lease is policed at
                // all, the jail, the workspace, and the uid the tool will run as. The bridge writes
                // these into the mission's record as what the guest held, not what was asked.
                let lease_frame = serde_json::json!({
                    "type": "LEASE",
                    "missionId": mission_id,
                    "cgroupId": cg.cgroup_id,
                    "cgroupPath": cg.path.display().to_string(),
                    "enforcing": cgroup_is_real && lease_mgr.is_enforcing(),
                    "limitsReadBack": cgroup_is_real,
                    "limits": {
                        "maxMemoryBytes": cg.effective.max_memory_bytes,
                        "maxCpuPercent": cg.effective.max_cpu_percent,
                        "maxPids": cg.effective.max_pids,
                    },
                    "jailed": jail_plan.is_some(),
                    "readOnlyFs": read_only_fs && jail_plan.is_some(),
                    "workspace": effective_work_dir,
                    "workspaceCreated": workspace_created,
                    "workloadUid": workload.uid,
                    "environmentMode": "explicit",
                    "secretStdin": secret_step,
                    "processOutput": if secret_step { "discarded" } else { "streamed" },
                });
                if let Some(secret) = &mut step_secret {
                    secret.arm_cleanup(&cg, lease_mgr.clone(), jail_plan.clone());
                }
                if let Some(ordinary) = &mut ordinary_workload {
                    ordinary.arm_cleanup(&cg, lease_mgr.clone(), jail_plan.clone());
                }
                out.send(&lease_frame).await?;

                let mut cmd = Command::new(command);
                cmd.args(&argv);
                cmd.env_clear().envs(&environment).kill_on_drop(true);
                cmd.stdin(step_secret.as_mut().and_then(|secret| secret.stdin.take())
                    .map(Stdio::from).unwrap_or_else(Stdio::null));
                if jail_plan.is_none() {
                    // Jailed, the child changes directory itself after pivot_root; std's chdir would
                    // land in the old root, which is detached by then.
                    cmd.current_dir(effective_work_dir);
                }
                cmd.stdout(if secret_step { Stdio::null() } else { Stdio::piped() });
                cmd.stderr(if secret_step { Stdio::null() } else { Stdio::piped() });

                // Join the leased cgroup BETWEEN fork and exec.
                //
                // Attaching after spawn() returns is too late: bprm_check_security fires during the
                // exec, when the process is still in the daemon's own cgroup, so `is_leased` was
                // false and the exec allow-list never applied to the tool itself. It also left a
                // window in which the tool ran wholly unleased. Doing it in pre_exec closes both.
                //
                // pre_exec runs in the forked child of a multithreaded process, so it must be
                // async-signal-safe: no allocation, no locks. The path is turned into a CString in
                // the parent, and writing "0" to cgroup.procs means "the calling process", which
                // avoids formatting a pid here. Returning Err fails the spawn, so a tool that
                // cannot be placed in its lease never executes.
                //
                // The privilege drop happens in the SAME closure, immediately after the join and
                // before the exec, because the two orderings conflict: writing cgroup.procs needs
                // root, and the workload must not have it. Command::uid/gid cannot express that -
                // std applies them before pre_exec runs, so the join would fail as nobody.
                // Order within the drop matters too: setgroups first (it needs privilege), then
                // gid, then uid, because setuid is the step that makes the rest impossible.
                let (wl_uid, wl_gid) = (workload.uid, workload.gid);
                if cgroup_is_real {
                    let procs = cg.path.join("cgroup.procs");
                    let plan_for_child = jail_plan.clone();
                    let policy_for_child = execution_policy.clone();
                    match std::ffi::CString::new(procs.as_os_str().as_bytes()) {
                        Ok(procs_c) => unsafe {
                            cmd.pre_exec(move || {
                                let fd = libc::open(procs_c.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                                if fd < 0 {
                                    return Err(std::io::Error::last_os_error());
                                }
                                let joined = libc::write(fd, b"0\n".as_ptr().cast(), 2);
                                libc::close(fd);
                                if joined < 0 {
                                    return Err(std::io::Error::last_os_error());
                                }

                                // Between the join and the drop: the mounts need root, and the
                                // workload must not have it. The cgroup.procs path above was the
                                // host's; after this the host's tree is not there to name.
                                if let Some(plan) = &plan_for_child {
                                    jail::enter(plan)?;
                                }

                                if secret_step { execution::isolate_secret_ipc()?; }

                                // SIGCONT may cross UID boundaries within one session. A private
                                // session closes that exception while descendants keep job control.
                                if libc::setsid() < 0 { return Err(std::io::Error::last_os_error()); }
                                drop_privileges(wl_uid, wl_gid)?;
                                if let Some(policy) = &policy_for_child { policy.apply()?; }
                                Ok(())
                            });
                        },
                        Err(e) => {
                            error!("Refusing to execute for mission {mission_id}: cgroup path is not a valid C string: {e}");
                            lease_mgr.revoke_lease(cg.cgroup_id);
                            let workspace_removed = workspace_created && workload::remove_workspace(ordinary_workload.as_mut(), Path::new(work_dir));
                            let err_chunk = serde_json::json!({
                                "type": "STDERR",
                                "data": "SPLAT refused to execute: the lease cgroup path could not be used.\n"
                            });
                            out.send(&err_chunk).await?;
                            let mut exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                            if workspace_created {
                                exit_chunk["workspaceRemoved"] = serde_json::json!(workspace_removed);
                            }
                            out.send(&exit_chunk).await?;
                            line.clear();
                            continue;
                        }
                    }
                }

                // Even without a cgroup - the openly non-enforcing dev path - the workload still
                // drops privilege. There is no configuration in which a leased tool runs as root.
                if !cgroup_is_real {
                    unsafe {
                        cmd.pre_exec(move || drop_privileges(wl_uid, wl_gid));
                    }
                }

                // Subscribe BEFORE spawning. An exec refused by the LSM fails inside the child, so
                // spawn() returns EPERM and the request ends here - if the subscription only began
                // after a successful spawn, the kernel's own violation for that refusal would never
                // reach the caller, who then cannot tell "the lease refused this" from "no such
                // binary". That is exactly what the first root run showed.
                let target_cgid = cg.cgroup_id;
                let mut viol_rx = viol_tx.subscribe();
                // The program's drop counter is global; what this lease can honestly report is how
                // far it moved while the lease ran.
                let dropped_before = lease_mgr.dropped_events();

                let mut child = match cmd.spawn() {
                    Ok(c) => c,
                    Err(e) => {
                        if lease_mgr.is_enforcing() && e.raw_os_error() == Some(libc::EPERM) {
                            // Give the ringbuf a moment to deliver the matching violation rather
                            // than inferring one from errno - the kernel's event or nothing.
                            let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
                            while tokio::time::Instant::now() < deadline {
                                match tokio::time::timeout(Duration::from_millis(60), viol_rx.recv()).await {
                                    Ok(Ok(v)) if v.cgroup_id == target_cgid => {
                                        out.send(&step_violation_frame(&v, secret_step)).await?;
                                        break;
                                    }
                                    Ok(Ok(_)) => continue,
                                    // Overtaken by a burst, not closed: the event may still be behind it.
                                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                                    _ => break,
                                }
                            }
                        }

                        let err_chunk = serde_json::json!({
                            "type": "STDERR",
                            "data": format!("Failed to spawn process '{command}': {e}\n")
                        });
                        out.send(&err_chunk).await?;

                        let workspace_removed = workspace_created && workload::remove_workspace(ordinary_workload.as_mut(), Path::new(work_dir));
                        let exit_chunk = serde_json::json!({
                            "type": "EXIT",
                            "exitCode": -1,
                            "workspaceRemoved": workspace_removed
                        });
                        out.send(&exit_chunk).await?;
                        line.clear();
                        continue;
                    }
                };

                let mut pump_error: Option<std::io::Error> = None;
                if let Some(policy) = &execution_policy {
                    // spawn succeeds only after the pre-exec restriction calls and exec succeed.
                    // Prepared policy in a LEASE frame would otherwise overstate installation.
                    pump_error = out.send(&serde_json::json!({"type":"POLICY_APPLIED", "sha256":policy.sha256,
                        "landlockAbi":policy.landlock_abi, "syscallFilter":"seccomp-cbpf-v1"})).await.err();
                }

                // The child joined its cgroup in pre_exec, before exec, so there is nothing to attach
                // here. Verify rather than assume: a tool running outside its lease must be visible,
                // not silently tolerated the way the discarded attach_pid error used to be.
                if let Some(secret) = &mut step_secret { secret.identity.mark_spawned(); }
                if let Some(ordinary) = &mut ordinary_workload { ordinary.identity.mark_spawned(); }
                if cgroup_is_real {
                    if let Some(pid) = child.id() {
                        match cg.contains_pid(pid) {
                            Ok(true) => {}
                            Ok(false) => error!(
                                "Mission {mission_id}: pid {pid} is NOT in its leased cgroup — it is \
                                 running UNCONTAINED. Treat any output from it as ungoverned."
                            ),
                            Err(e) => warn!("Mission {mission_id}: could not verify cgroup membership for pid {pid}: {e}"),
                        }
                    }
                }

                // Verify rather than assume, the same way cgroup membership is verified: a drop
                // that silently did not happen looks identical to one that did.
                if let Some(pid) = child.id() {
                    match effective_uid_of(pid) {
                        Ok(Some(0)) => error!(
                            "Mission {mission_id}: pid {pid} is running as ROOT. The privilege drop \
                             did not take; treat any output from it as ungoverned."
                        ),
                        Ok(_) => {}
                        Err(e) => warn!("Mission {mission_id}: could not read the uid of pid {pid}: {e}"),
                    }
                }

                let stdout = child.stdout.take();
                let stderr = child.stderr.take();

                let (tx, mut rx) = mpsc::channel::<serde_json::Value>(64);

                // The violation forwarder must end when the child does. It previously looped on a
                // broadcast receiver that never closes while holding a clone of `tx`, so the pump
                // below never saw the channel close: EXIT was never sent, the lease was never
                // revoked at exit (only later by the expiry reaper), and every EXECUTE_TOOL hung
                // until the client gave up. Requests that produced no output looked like silence.
                let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
                let tx_viol = tx.clone();
                // What the caller was actually told, counted as it is told. The EXIT frame compares
                // this with the kernel's own tally for the same cgroup, so a receipt that is short
                // says so instead of reading as a lease that was never denied anything.
                let forwarded = Arc::new(AtomicU64::new(0));
                let forwarded_in_task = forwarded.clone();
                let lease_mgr_for_drain = lease_mgr.clone();
                let violation_forwarder = tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = &mut done_rx => {
                                // The ringbuf is polled on a ~100ms tick, so a denial that killed the
                                // child can still be in flight as it exits.
                                //
                                // This used to be a flat 250ms sleep and one drain, which is a guess
                                // about someone else's scheduler: on 2026-09-25, on a machine also
                                // running a cargo build, the guess lost and a datagram the kernel had
                                // refused never reached its session. Now the wait has an answer to
                                // wait FOR - the kernel's count for this cgroup - and ends the moment
                                // the caller has been told that many. The deadline is the fallback,
                                // not the mechanism, and a daemon with no live program (no count to
                                // ask for) keeps the old behaviour of draining what is there.
                                let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                                loop {
                                    loop {
                                        match viol_rx.try_recv() {
                                            Ok(v) if v.cgroup_id == target_cgid => {
                                                forwarded_in_task.fetch_add(1, Ordering::Relaxed);
                                                let _ = tx_viol.send(step_violation_frame(&v, secret_step)).await;
                                            }
                                            Ok(_) => {}
                                            Err(broadcast::error::TryRecvError::Lagged(_)) => {}
                                            Err(_) => break,
                                        }
                                    }

                                    let told = forwarded_in_task.load(Ordering::Relaxed);
                                    match lease_mgr_for_drain.violations_for(target_cgid) {
                                        Some(counted) if told >= counted => break,
                                        None => break,
                                        _ => {}
                                    }

                                    if tokio::time::Instant::now() >= deadline {
                                        break;
                                    }
                                    tokio::time::sleep(Duration::from_millis(20)).await;
                                }
                                break;
                            }
                            recv = viol_rx.recv() => match recv {
                                Ok(v) => {
                                    if v.cgroup_id == target_cgid {
                                        forwarded_in_task.fetch_add(1, Ordering::Relaxed);
                                        let _ = tx_viol.send(step_violation_frame(&v, secret_step)).await;
                                    }
                                }
                                // A burst across every lease overran this subscriber's slot of the
                                // broadcast channel. The events it missed are gone, and that is said;
                                // the stream is not over. Treating it as closed ended this forwarder
                                // before, and every later denial of this lease was lost to the caller
                                // while the kernel went on denying.
                                Err(broadcast::error::RecvError::Lagged(missed)) => warn!(
                                    "Violation forwarder for cgroup {target_cgid} lagged; {missed} event(s) across all leases were not inspected"
                                ),
                                Err(broadcast::error::RecvError::Closed) => break,
                            },
                        }
                    }
                });

                if let Some(out) = stdout {
                    tokio::spawn(pump_output(out, "STDOUT", tx.clone()));
                }

                if let Some(err) = stderr {
                    tokio::spawn(pump_output(err, "STDERR", tx.clone()));
                }

                drop(tx);

                // Reap the child concurrently with pumping, and use its exit to release the
                // violation forwarder. Waiting after the pump would deadlock: the pump cannot end
                // until every sender is dropped, and the forwarder does not drop its sender until
                // it learns the child is gone.
                let waiter = tokio::spawn(async move {
                    let status = child.wait().await;
                    let _ = done_tx.send(());
                    status
                });

                // Pump stream chunks to client.
                //
                // A write failure here means the client is gone. `?` used to propagate straight out
                // of handle_client, leaving the tool running against a socket nobody reads until
                // the expiry reaper came round - and that reaper then unpoliced it rather than
                // killing it. A lost client ends the lease, in the same order expiry uses: kill
                // inside the installed policy, then withdraw the policy.
                let mut watch_client = true;
                let mut cancellation_accepted = false;
                while pump_error.is_none() {
                    tokio::select! {
                        // Silent ordinary steps need EOF detection too. Leave ordinary pipelined
                        // bytes queued for the next request without repeatedly polling a ready buffer.
                        // Secret sessions still refuse pipelining to keep grant ownership unambiguous.
                        incoming = buf_reader.fill_buf(), if watch_client => {
                            match incoming {
                                Ok(bytes) if !bytes.is_empty() && execution_context.is_some() => {
                                    // Only this authenticated session may cancel this mission. Keep
                                    // its policy installed until cgroup.events confirms every descendant left.
                                    let mut control = String::new();
                                    let result = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut buf_reader, &mut control)).await;
                                    let valid = match result {
                                        Ok(Ok(n)) if n > 0 => authenticated_request(control.trim(), &session, &peer_auth, sequence)
                                            .is_ok_and(|v| v["type"] == "CANCEL" && v["missionId"] == mission_id),
                                        _ => false,
                                    };
                                    if !valid {
                                        pump_error = Some(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid lease cancellation"));
                                        break;
                                    }
                                    sequence += 1;
                                    cg.kill_all().context("drain canceled workload while its policy remains installed")?;
                                    cancellation_accepted = true;
                                    watch_client = false;
                                }
                                Ok(bytes) if !bytes.is_empty() && !secret_step => watch_client = false,
                                Ok(_) => {
                                    pump_error = Some(std::io::Error::new(std::io::ErrorKind::ConnectionAborted,
                                        "lease connection ended or secret request pipelined"));
                                    break;
                                }
                                Err(error) => { pump_error = Some(error); break; }
                            }
                        }
                        message = rx.recv() => match message {
                            Some(msg) => if let Err(e) = out.send(&msg).await {
                                pump_error = Some(e);
                                break;
                            },
                            None => break,
                        }
                    }
                }

                if pump_error.is_some() {
                    if cgroup_is_real && cg.kill_all().is_err() {
                        error!("Disconnected lease could not be drained; retaining policy for the expiry reaper");
                        return Err(anyhow::anyhow!("disconnected workload could not be drained"));
                    }
                    // Release blocked output producers, then follow the same signed completion
                    // path as a connected caller. Transport loss must not discard drain evidence.
                    drop(rx);
                }

                let status = waiter.await.context("join child reaper")??;
                violation_forwarder.await.context("join violation forwarder before signing its counters")?;
                let exit_code = status.code().unwrap_or(-1);
                if cgroup_is_real {
                    cg.kill_all().context("drain workload before removing overlay scratch")?;
                }
                // Command retains the pre_exec closure's Arc after spawn. Release both owners
                // only after draining descendants, before reporting EXIT and scratch teardown.
                drop(cmd);
                drop(jail_plan);
                if let Some(secret) = &mut step_secret { secret.finish()?; }
                if let Some(ordinary) = &mut ordinary_workload { ordinary.finish()?; }

                // The cgroup is already drained. Guarded cleanup must not revisit a pathname
                // that a later request may reuse after the original workspace was removed.
                let workspace_removed = workspace_created && workload::remove_workspace(ordinary_workload.as_mut(), Path::new(work_dir));

                // The lease's own denial count, read from the kernel after the forwarder has
                // finished, and the number of frames the caller was actually sent. Read in this
                // order so `counted` can never be lower than `reported` through timing alone.
                let violations_reported = forwarded.load(Ordering::Relaxed);
                let violations_counted = lease_mgr.violations_for(target_cgid);
                let violations_dropped = lease_mgr.dropped_events().saturating_sub(dropped_before);

                let mut exit_chunk = serde_json::json!({
                    "type": "EXIT",
                    "exitCode": exit_code,
                    // Denials the kernel refused but could not record while this lease ran, across
                    // every lease on the host. Zero is the normal case; anything else means the
                    // VIOLATION frames above are incomplete, which the caller must be told.
                    "violationsDropped": violations_dropped,
                    // How many VIOLATION frames this lease was sent.
                    "violationsReported": violations_reported
                });
                if secret_step {
                    exit_chunk["secretStdinClosed"] = serde_json::Value::Bool(true);
                }

                // What the kernel counted for this cgroup, and whether the caller was told all of
                // it. Absent on a daemon with no live program: it denied nothing because it denies
                // nothing, and reporting a confident zero there would be the same lie in reverse.
                //
                // `violationsComplete` is the field a run record should carry. A receipt that says
                // "two denials, and that is all of them" is evidence; one that says "two denials"
                // and cannot say whether there was a third is not, and until now every receipt was
                // the second kind without admitting it.
                if let Some(counted) = violations_counted {
                    exit_chunk["violationsCounted"] = serde_json::Value::from(counted);
                    let complete = violations_reported >= counted && violations_dropped == 0;
                    exit_chunk["violationsComplete"] = serde_json::Value::Bool(complete);
                    if !complete {
                        warn!(
                            "Mission {mission_id}: the kernel counted {counted} denial(s) for cgroup \
                             {target_cgid}, {violations_reported} reached the caller, and {violations_dropped} \
                             were dropped by the ring buffer. The receipt for this lease is incomplete and says so."
                        );
                    }
                }
                if workspace_created {
                    exit_chunk["workspaceRemoved"] = serde_json::Value::Bool(workspace_removed);
                }

                // Roadmap 2.5: the guest signs what it just reported, so the record cannot claim
                // more than the guest said. The signed text travels verbatim rather than being
                // rebuilt from the fields above - three implementations have to agree on the exact
                // bytes, and "rebuild the canonical form" is where that agreement goes wrong. The
                // public key rides along so a bundle verifies without a second call to this host.
                if let Some(signer) = outcome_signer.as_ref() {
                    let mut canonical = outcome::canonical_outcome(
                        &mission_id,
                        cg.cgroup_id,
                        lease_mgr.is_enforcing(),
                        workload.uid,
                        exit_code,
                        violations_counted,
                        violations_reported,
                        violations_dropped,
                        if workspace_created { Some(work_dir) } else { None },
                        if workspace_created { Some(workspace_removed) } else { None },
                    );
                    if let Some(context) = execution_context {
                        let policy_hash = execution_policy.as_ref().map_or("none", |p| p.sha256.as_str());
                        canonical = outcome::bound_outcome(&canonical, policy_hash, context,
                            &effective_policy_sha256, cgroup_is_real, cancellation_accepted);
                        exit_chunk["executionPolicySha256"] = serde_json::json!(policy_hash);
                        exit_chunk["executionContext"] = serde_json::json!(context);
                        exit_chunk["effectivePolicySha256"] = serde_json::json!(effective_policy_sha256);
                        exit_chunk["workloadDrained"] = serde_json::json!(cgroup_is_real);
                        exit_chunk["cancellationAccepted"] = serde_json::json!(cancellation_accepted);
                    }
                    exit_chunk["outcomeCanonical"] = serde_json::Value::from(canonical.clone());
                    exit_chunk["outcomeSignature"] = serde_json::Value::from(signer.sign(&canonical));
                    exit_chunk["outcomeKeyId"] = serde_json::Value::from(signer.key_id());
                    exit_chunk["outcomePublicKey"] = serde_json::Value::from(signer.public_key_base64());
                    if let Some(secret) = &step_secret {
                        let receipt = secret.receipt(parsed["stepId"].as_str().expect("validated secret step"), &canonical);
                        exit_chunk["secretOutcomeSignature"] = serde_json::Value::from(signer.sign(&receipt));
                        exit_chunk["secretOutcomeCanonical"] = serde_json::Value::from(receipt);
                    }
                }

                // 3. Atomically revoke lease upon exit
                lease_mgr.revoke_lease(cg.cgroup_id);
                let mut retained = true;
                if let Some(context) = execution_context {
                    // The cache serves a caller who lost the connection. A connected caller is owed
                    // its signed EXIT whether or not the copy could be written; the reservation
                    // stays pending, so a lookup reports the mission unresolved and the mission ID
                    // still cannot be admitted again.
                    if let Err(error) = receipt_store.as_ref().context("receipt cache unavailable")
                        .and_then(|store| store.finish(mission_id, context, &lease_frame, &exit_chunk)) {
                        error!("Bound outcome for mission {mission_id} could not be retained: {error:#}");
                        retained = false;
                    }
                }
                if let Some(error) = pump_error {
                    let state = if retained { "terminal outcome retained" } else { "terminal outcome lost" };
                    return Err(anyhow::Error::from(error).context(format!("client disconnected; {state}")));
                }
                out.send(&exit_chunk).await?;
                info!("Completed tool execution for mission {mission_id} (exit code {exit_code})");
            }

            _ => {
                // Answered, not just logged: a caller that sent something this daemon does not
                // know used to hear nothing at all, and waited out its own deadline to learn so.
                warn!("Unknown request type: {req_type}");
                let err_resp = serde_json::json!({
                    "type": "STDERR",
                    "data": format!("SPLAT refused the request: '{req_type}' is not a request this daemon knows.\n")
                });
                out.send(&err_resp).await?;
            }
        }

        line.clear();
    }

    Ok(())
}
#[cfg(test)]
mod frame_tests {
    use super::{read_frame, MAX_FRAME_BYTES};
    use anyhow::Result;
    use std::io::Cursor;
    use tokio::io::BufReader;

    async fn read_one(input: Vec<u8>) -> Result<(usize, String)> {
        let mut reader = BufReader::new(Cursor::new(input));
        let mut line = String::new();
        let read = read_frame(&mut reader, &mut line).await?;
        Ok((read, line))
    }

    /// The limit is the frame, not the frame plus its delimiter: one of exactly this size is legal.
    #[tokio::test]
    async fn a_frame_at_the_limit_is_read_whole() {
        let payload = "a".repeat(MAX_FRAME_BYTES);
        let (read, line) = read_one(format!("{payload}\n").into_bytes()).await.unwrap();

        assert_eq!(read, MAX_FRAME_BYTES + 1);
        assert_eq!(line.trim_end(), payload);
    }

    /// One byte more is refused, and the refusal happens before the rest can be buffered: the ten
    /// megabytes trailing this frame are never read, which is the property the auth check needed.
    #[tokio::test]
    async fn a_frame_over_the_limit_is_refused_before_it_grows() {
        let mut input = "a".repeat(MAX_FRAME_BYTES + 1).into_bytes();
        input.extend(std::iter::repeat(b'a').take(10 * 1024 * 1024));
        input.push(b'\n');

        let err = read_one(input).await.unwrap_err();

        assert!(err.to_string().contains("may not exceed"), "{err}");
    }

    /// A peer that closes without sending a newline ends the loop rather than holding the frame.
    #[tokio::test]
    async fn end_of_stream_reads_nothing() {
        let (read, line) = read_one(Vec::new()).await.unwrap();

        assert_eq!(read, 0);
        assert!(line.is_empty());
    }
}

#[cfg(test)]
mod output_tests {
    use super::{pump_output, MAX_OUTPUT_CHUNK_BYTES};
    use std::io::Cursor;
    use tokio::sync::mpsc;

    async fn frames_for(input: Vec<u8>) -> Vec<String> {
        let (tx, mut rx) = mpsc::channel(8);
        let pump = tokio::spawn(pump_output(Cursor::new(input), "STDOUT", tx));
        let mut out = Vec::new();
        while let Some(frame) = rx.recv().await {
            assert_eq!(frame["type"], "STDOUT");
            out.push(frame["data"].as_str().unwrap().to_string());
        }
        pump.await.unwrap();
        out
    }

    #[tokio::test]
    async fn a_line_arrives_as_one_frame() {
        assert_eq!(frames_for(b"hello\nworld\n".to_vec()).await, vec!["hello\n", "world\n"]);
    }

    /// The whole point of the cap: a tool's single long line no longer sits in a root process's
    /// memory in full before the first byte of it is forwarded.
    #[tokio::test]
    async fn a_line_longer_than_the_cap_is_split_and_reassembles_intact() {
        let line = "x".repeat(MAX_OUTPUT_CHUNK_BYTES * 3 + 17) + "\n";
        let frames = frames_for(line.clone().into_bytes()).await;
        assert!(frames.len() >= 4, "{} frames", frames.len());
        assert!(frames.iter().all(|f| f.len() <= MAX_OUTPUT_CHUNK_BYTES));
        assert_eq!(frames.concat(), line);
    }

    #[tokio::test]
    async fn a_multibyte_character_cut_by_the_cap_is_not_torn() {
        // 'é' is two bytes; its first byte lands exactly at the cap.
        let mut input = "a".repeat(MAX_OUTPUT_CHUNK_BYTES - 1).into_bytes();
        input.extend_from_slice("é".as_bytes());
        input.extend_from_slice(b"z\n");
        let frames = frames_for(input.clone()).await;
        assert_eq!(frames.concat(), String::from_utf8(input).unwrap());
        assert!(frames.iter().all(|f| !f.contains('\u{FFFD}')), "a character was torn: {frames:?}");
    }

    #[tokio::test]
    async fn output_with_no_trailing_newline_is_still_delivered() {
        assert_eq!(frames_for(b"no newline".to_vec()).await, vec!["no newline"]);
    }

    #[tokio::test]
    async fn bytes_that_are_not_utf8_are_replaced_rather_than_held_forever() {
        let frames = frames_for(b"ok\xff\xfe\n".to_vec()).await;
        assert_eq!(frames.len(), 1);
        assert!(frames[0].starts_with("ok") && frames[0].ends_with('\n'));
    }
}

#[cfg(test)]
mod session_tests {
    use super::{authenticated_request, hello_nonce, open_session, PROTOCOL_VERSION};
    use crate::auth::{self, PeerAuth};
    use tokio::io::BufReader;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// The point of protocol 3: a caller learns this daemon holds the token before it sends a request.
    #[tokio::test]
    async fn a_hello_is_answered_with_a_proof_of_the_token() {
        let auth = PeerAuth::from_token(TOKEN);
        let client_nonce = [7u8; auth::NONCE_BYTES];
        let hello = serde_json::json!({
            "type": "HELLO",
            "protocolVersion": PROTOCOL_VERSION,
            "clientNonce": auth::hex(&client_nonce),
        });
        let input = format!("{hello}\n");
        let mut reader = BufReader::new(input.as_bytes());
        let mut written: Vec<u8> = Vec::new();
        let mut line = String::new();

        let session = open_session(&mut reader, &mut written, &mut line, &auth)
            .await
            .unwrap()
            .expect("a HELLO opens a session");

        let challenge: serde_json::Value = serde_json::from_slice(&written).unwrap();
        assert_eq!(challenge["type"], "CHALLENGE");
        assert_eq!(challenge["serverNonce"].as_str(), Some(auth::hex(&session.server_nonce).as_str()));
        assert_eq!(
            challenge["serverProof"].as_str(),
            Some(auth::hex(&auth.daemon_proof(&client_nonce, &session.server_nonce, false)).as_str())
        );
        // A caller that did not ask for proven frames is a bridge older than the field: answered as
        // before, and told nothing it would not understand.
        assert!(!session.prove_frames);
        assert!(challenge.get("framesProven").is_none());
    }

    /// A HELLO that asks for proven frames is answered under the frames label, and says so.
    #[tokio::test]
    async fn a_hello_that_asks_for_proven_frames_is_answered_under_the_frames_label() {
        let auth = PeerAuth::from_token(TOKEN);
        let client_nonce = [9u8; auth::NONCE_BYTES];
        let hello = serde_json::json!({
            "type": "HELLO",
            "protocolVersion": PROTOCOL_VERSION,
            "clientNonce": auth::hex(&client_nonce),
            "proveFrames": true,
        });
        let input = format!("{hello}\n");
        let mut reader = BufReader::new(input.as_bytes());
        let mut written: Vec<u8> = Vec::new();
        let mut line = String::new();

        let session = open_session(&mut reader, &mut written, &mut line, &auth)
            .await
            .unwrap()
            .expect("a HELLO opens a session");

        let challenge: serde_json::Value = serde_json::from_slice(&written).unwrap();
        assert!(session.prove_frames);
        assert_eq!(challenge["framesProven"], true);
        assert_eq!(
            challenge["serverProof"].as_str(),
            Some(auth::hex(&auth.daemon_proof(&client_nonce, &session.server_nonce, true)).as_str()),
            "the agreement is bound into the proof, not only stated beside it"
        );
    }

    /// The sink wraps and numbers every frame on a connection that asked, and none on one that did not.
    #[tokio::test]
    async fn frames_are_proven_for_their_place_only_on_a_connection_that_asked() {
        let auth = std::sync::Arc::new(PeerAuth::from_token(TOKEN));
        let asked = auth::Session { client_nonce: [1; auth::NONCE_BYTES], server_nonce: [2; auth::NONCE_BYTES], prove_frames: true };
        let mut written: Vec<u8> = Vec::new();
        let mut sink = super::FrameSink::new(&mut written, &asked, &auth);
        let first = serde_json::json!({ "type": "STDOUT", "data": "hello\n" });
        let second = serde_json::json!({ "type": "EXIT", "exitCode": 0 });
        sink.send(&first).await.unwrap();
        sink.send(&second).await.unwrap();

        let lines: Vec<serde_json::Value> = String::from_utf8(written.clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        for (i, (line, frame)) in lines.iter().zip([&first, &second]).enumerate() {
            assert_eq!(line["type"], "PROVEN");
            let inner = line["frame"].as_str().expect("the frame travels as a string");
            assert_eq!(inner, frame.to_string(), "the frame's bytes are exactly what was proven");
            assert_eq!(
                line["proof"].as_str(),
                Some(auth::hex(&auth.frame_proof(&asked.client_nonce, &asked.server_nonce, i as u64, inner.as_bytes())).as_str()),
                "frame {i} is proven for its place"
            );
        }

        let did_not_ask = auth::Session { client_nonce: [1; auth::NONCE_BYTES], server_nonce: [2; auth::NONCE_BYTES], prove_frames: false };
        let mut plain: Vec<u8> = Vec::new();
        let mut sink = super::FrameSink::new(&mut plain, &did_not_ask, &auth);
        sink.send(&second).await.unwrap();
        assert_eq!(String::from_utf8(plain).unwrap(), format!("{second}\n"), "an older caller is answered as before");
    }

    /// A protocol 2 caller opens with its token in the clear. It is refused, and no session opens.
    #[tokio::test]
    async fn a_protocol_2_request_opens_no_session() {
        let auth = PeerAuth::from_token(TOKEN);
        let input = format!("{}\n", serde_json::json!({ "type": "HEALTH_CHECK", "authToken": TOKEN }));
        let mut reader = BufReader::new(input.as_bytes());
        let mut written: Vec<u8> = Vec::new();
        let mut line = String::new();

        assert!(open_session(&mut reader, &mut written, &mut line, &auth).await.unwrap().is_none());
        let refusal = String::from_utf8(written).unwrap();
        assert!(refusal.contains("protocol 3"), "{refusal}");
        assert!(!refusal.contains(TOKEN), "a refusal must not echo what it refused");

        let old = serde_json::json!({ "type": "HELLO", "protocolVersion": 2, "clientNonce": "00".repeat(32) });
        assert!(hello_nonce(&old.to_string()).is_err());
    }

    /// After the handshake a request stands or falls by its proof.
    #[test]
    fn a_request_is_believed_only_with_its_proof() {
        let auth = PeerAuth::from_token(TOKEN);
        let session = auth::Session { client_nonce: [1; auth::NONCE_BYTES], server_nonce: [2; auth::NONCE_BYTES], prove_frames: false };
        let request = r#"{"type":"HEALTH_CHECK"}"#;
        let frame = |proof: &[u8]| {
            serde_json::json!({ "type": "AUTHENTICATED", "proof": auth::hex(proof), "request": request }).to_string()
        };
        let proof = auth.request_proof(&session.client_nonce, &session.server_nonce, 0, request.as_bytes());

        let parsed = authenticated_request(&frame(&proof), &session, &auth, 0).unwrap();
        assert_eq!(parsed["type"], "HEALTH_CHECK");

        let replayed = authenticated_request(&frame(&proof), &session, &auth, 1).unwrap_err();
        assert!(replayed.contains("proof"), "{replayed}");
        assert!(authenticated_request(request, &session, &auth, 0).is_err(), "a bare request is not believed");
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::process::CommandExt as _;

    /// The containment property depends on the cgroup join landing BEFORE the exec, which is the
    /// whole reason it moved into `pre_exec`. tokio's `pre_exec` delegates straight to std's, so
    /// exercising it here tests the same mechanism the daemon uses, without needing root.
    #[test]
    fn pre_exec_side_effect_lands_before_the_child_execs() {
        let path = std::env::temp_dir().join(format!("splat_pre_exec_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let c = CString::new(path.to_str().unwrap()).unwrap();

        let mut cmd = std::process::Command::new("/bin/true");
        unsafe {
            cmd.pre_exec(move || {
                let fd = libc::open(
                    c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o600 as libc::c_int,
                );
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let written = libc::write(fd, b"0\n".as_ptr().cast(), 2);
                libc::close(fd);
                if written < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let status = cmd.status().expect("spawn /bin/true");
        assert!(status.success(), "child should have run");
        assert_eq!(
            std::fs::read_to_string(&path).expect("pre_exec wrote the file"),
            "0\n",
            "pre_exec must have written before the exec replaced the image"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// Failing the join must fail the spawn. If this ever regresses, a tool that could not be placed
    /// in its lease would run anyway - the fail-open shape this whole change exists to remove.
    #[test]
    fn pre_exec_failure_prevents_the_child_from_running() {
        let mut cmd = std::process::Command::new("/bin/true");
        unsafe {
            cmd.pre_exec(|| Err(std::io::Error::from_raw_os_error(libc::EPERM)));
        }
        assert!(
            cmd.status().is_err(),
            "a failed cgroup join must abort the spawn, never execute uncontained"
        );
    }
}
