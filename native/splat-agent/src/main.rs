use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
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
mod jail;
mod lease;
mod violation;
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
use lease_lsm::*;

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
        .map(|a| a.iter().filter_map(|e| e.as_str().map(str::to_string)).collect())
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

    /// The uid a leased tool runs as. Defaults to nobody.
    ///
    /// The daemon needs root to load BPF programs and write the cgroup tree; the WORKLOAD needs
    /// none of that. It used to inherit the daemon's uid 0, so every containment claim rested on
    /// three LSM hooks holding against a root process - with the cgroup controls, host mounts and
    /// every unprotected file still reachable underneath them.
    #[arg(long, default_value_t = 65534)]
    workload_uid: u32,

    /// The gid a leased tool runs as. Defaults to nogroup.
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
        let one: u8 = 1;
        self.leased_cgroups
            .update(&lease.cgroup_id.to_ne_bytes(), &[one], MapFlags::ANY)
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

    info!("Starting SPLAT Resident eBPF Containment Daemon on {}", args.listen);

    let (viol_tx, _viol_rx) = broadcast::channel::<ViolationEvent>(128);
    let mut bpf_sync: Option<Arc<dyn BpfMapSync>> = None;

    let is_root = unsafe { libc::geteuid() } == 0;
    if !is_root {
        warn!("Running unprivileged. In-kernel BPF-LSM hooks require CAP_BPF / CAP_SYS_ADMIN.");
    } else if !args.mock_bpf {
        info!("Initializing in-kernel BPF-LSM capability lease skeleton...");
        let open_object = Box::leak(Box::new(MaybeUninit::uninit()));
        let skel_builder = LeaseLsmSkelBuilder::default();
        match skel_builder.open(open_object) {
            Ok(open_skel) => match open_skel.load() {
                Ok(mut skel) => match skel.attach() {
                    Ok(_) => {
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
                                info!("Kernel -EPERM violation: {}", event.detail_text);
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
                            MapHandle::try_from(&skel.maps.allowed_connect_ipv4),
                            MapHandle::try_from(&skel.maps.counters),
                            MapHandle::try_from(&skel.maps.violation_counts),
                        ) {
                            (
                                Ok(leased_cgroups),
                                Ok(protected_inodes),
                                Ok(allowed_exec_inodes),
                                Ok(allowed_connect_ipv4),
                                Ok(counters),
                                Ok(violation_counts),
                            ) => {
                                bpf_sync = Some(Arc::new(LiveBpfSync {
                                    leased_cgroups,
                                    protected_inodes,
                                    allowed_exec_inodes,
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
                    Err(e) => warn!("Failed to attach BPF-LSM programs: {e}"),
                },
                Err(e) => warn!("Failed to load BPF-LSM skeleton: {e}"),
            },
            Err(e) => warn!("Failed to open BPF-LSM skeleton: {e}"),
        }
    }

    // FAIL CLOSED. Reaching here without map handles means every hook is absent: a tool would run
    // with the daemon's own privileges while the caller was told it held a capability lease. Each
    // failure above logged and fell through, so the only symptom was a warning in a log nobody
    // reads. --mock-bpf is the way to ask for a non-enforcing daemon on purpose.
    if bpf_sync.is_none() && !args.mock_bpf {
        error!(
            "Refusing to start: BPF-LSM enforcement is not live{}. Re-run as root on a BPF-LSM kernel, or pass --mock-bpf for a daemon that openly does not contain anything.",
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

    // A daemon that stopped - crashed, or stopped by systemd - took its maps and hooks with it and
    // left any workload still running under splat_leases with nothing policing it. None can be
    // re-policed: the lease that described it died with the process that held it. So they are ended
    // here, before this daemon accepts a request, and again on the way out below. A tree that will
    // not drain is a workload running uncontained, and serving beside it would report a containment
    // this daemon does not have.
    match EphemeralCgroup::reap_orphans(Path::new(cgroup::BASE_PATH)) {
        Ok(drained) if drained.is_empty() => {}
        Ok(drained) => warn!(
            "Ended {} orphaned lease(s) a previous daemon left running unpoliced: {drained:?}",
            drained.len()
        ),
        Err(e) => {
            error!("Refusing to start: an orphaned lease cgroup could not be drained: {e:#}");
            std::process::exit(1);
        }
    }
    // The skeletons of their jails go the same way; only empty directories and links are removed.
    match jail::reap_leftover_roots(Path::new(jail::ROOTS_BASE)) {
        Ok(0) => {}
        Ok(n) => warn!("Removed {n} jail skeleton(s) a previous daemon left under {}", jail::ROOTS_BASE),
        Err(e) => warn!("Could not sweep {}: {e:#}", jail::ROOTS_BASE),
    }

    let lease_manager = LeaseManager::new(bpf_sync);

    // systemd stops this daemon with SIGTERM, and the workloads it leased are not in its own cgroup,
    // so they would outlive the stop - unpoliced, once the maps went with the process. End them while
    // the policy is still installed, then exit cleanly; the unit restarts only on failure.
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
            Err(e) => error!("Stopping, but a leased workload could not be drained and is now unpoliced: {e:#}"),
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

    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                info!("Accepted connection from {peer}");
                let mgr = lease_manager.clone();
                let viol_tx_clone = viol_tx.clone();
                let auth = peer_auth.clone();
                let ceiling_for_client = lease_ceiling.clone();
                let missions_root_for_client = missions_root.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(socket, mgr, viol_tx_clone, auth, workload_ids, ceiling_for_client, missions_root_for_client).await {
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
        self.writer.write_all(format!("{line}\n").as_bytes()).await
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
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    // Protocol 3: the caller's HELLO, and this daemon's proof that it holds the token, before anything
    // else is read. Protocol 2 put the token itself in every request, so a caller handed it to whatever
    // answered on this port - and while this daemon was not listening, anything in the guest could.
    let Some(session) = open_session(&mut buf_reader, &mut writer, &mut line, &peer_auth).await? else {
        return Ok(());
    };
    // From here every frame this daemon sends goes through the sink, which proves each one when the
    // caller asked - refusals included, because a refusal is a frame the caller acts on.
    let mut out = FrameSink::new(writer, &session, &peer_auth);
    let mut sequence: u64 = 0;

    loop {
        match read_frame(&mut buf_reader, &mut line).await {
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
                    "ceiling": lease_ceiling.is_some()
                });
                out.send(&resp).await?;
            }

            "EXECUTE_TOOL" => {
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
                let argv: Vec<String> = match parsed.get("argv") {
                    Some(v) if v.is_array() => v
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(|e| e.as_str().map(str::to_string))
                        .collect(),
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

                info!("Executing tool for mission {mission_id}: {command} {argv:?}");

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

                if parsed
                    .get("overlayFs")
                    .and_then(|v| v.get("enableCow"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    unsupported.push(
                        "overlayFs.enableCow: the overlay would mount in the daemon's own mount \
                         namespace and the tool could step out of the merged directory, so it \
                         would not be a workspace boundary",
                    );
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
                    if let Err(reason) = c.check(&ask) {
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
                        let workspace_removed = workspace_created && workspace::remove(Path::new(work_dir));
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
                    let workspace_removed = workspace_created && workspace::remove(Path::new(work_dir));
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
                if let Err(e) = lease_mgr.register_lease(cg.cgroup_id, cg.path.clone(), &lease_cfg) {
                    error!("Refusing to execute for mission {mission_id}: {e:#}");
                    let workspace_removed = workspace_created && workspace::remove(Path::new(work_dir));
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
                        Path::new("/"),
                    ) {
                        Ok(plan) => Some(Arc::new(plan)),
                        Err(e) => {
                            error!("Refusing to execute for mission {mission_id}: the jail root could not be prepared: {e:#}");
                            lease_mgr.revoke_lease(cg.cgroup_id);
                            let workspace_removed = workspace_created && workspace::remove(Path::new(work_dir));
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
                });
                out.send(&lease_frame).await?;

                let mut cmd = Command::new(command);
                cmd.args(&argv);
                if jail_plan.is_none() {
                    // Jailed, the child changes directory itself after pivot_root; std's chdir would
                    // land in the old root, which is detached by then.
                    cmd.current_dir(effective_work_dir);
                }
                cmd.stdout(Stdio::piped());
                cmd.stderr(Stdio::piped());

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

                                drop_privileges(wl_uid, wl_gid)
                            });
                        },
                        Err(e) => {
                            error!("Refusing to execute for mission {mission_id}: cgroup path is not a valid C string: {e}");
                            lease_mgr.revoke_lease(cg.cgroup_id);
                            let workspace_removed = workspace_created && workspace::remove(Path::new(work_dir));
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
                                        out.send(&violation_frame(&v)).await?;
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

                        let workspace_removed = workspace_created && workspace::remove(Path::new(work_dir));
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

                // The child joined its cgroup in pre_exec, before exec, so there is nothing to attach
                // here. Verify rather than assume: a tool running outside its lease must be visible,
                // not silently tolerated the way the discarded attach_pid error used to be.
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
                tokio::spawn(async move {
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
                                                let _ = tx_viol.send(violation_frame(&v)).await;
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
                                        let _ = tx_viol.send(violation_frame(&v)).await;
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
                let mut pump_error: Option<std::io::Error> = None;
                while let Some(msg) = rx.recv().await {
                    if let Err(e) = out.send(&msg).await {
                        pump_error = Some(e);
                        break;
                    }
                }

                if let Some(e) = pump_error {
                    if cgroup_is_real {
                        match cg.kill_all() {
                            Ok(n) if n > 0 => warn!(
                                "Client for mission {mission_id} disconnected; killed {n} process(es) \
                                 that were still holding its lease"
                            ),
                            Ok(_) => {}
                            Err(err) => error!(
                                "Client for mission {mission_id} disconnected and its cgroup could \
                                 not be drained: {err:#}"
                            ),
                        }
                    }
                    lease_mgr.revoke_lease(cg.cgroup_id);
                    // Reap the (now dead) child so no zombie is left behind.
                    let _ = waiter.await;
                    return Err(anyhow::Error::from(e).context("client write failed; lease terminated"));
                }

                let status = waiter.await.context("join child reaper")??;
                let exit_code = status.code().unwrap_or(-1);

                // The workspace goes before EXIT is written, so the frame can say it went. Anything
                // the tool left running in its cgroup is killed first, so nothing is still writing
                // into a directory being removed; revoking the lease below drains the same cgroup
                // again, which is then a no-op.
                let workspace_removed = if workspace_created {
                    if cgroup_is_real {
                        if let Err(e) = cg.kill_all() {
                            warn!("Mission {mission_id}: the cgroup could not be drained before its workspace was removed: {e:#}");
                        }
                    }
                    workspace::remove(Path::new(work_dir))
                } else {
                    false
                };

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
                out.send(&exit_chunk).await?;

                // 3. Atomically revoke lease upon exit
                lease_mgr.revoke_lease(cg.cgroup_id);
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
