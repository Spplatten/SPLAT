use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt as _;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle, RingBufferBuilder};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::{broadcast, mpsc};
use tracing::{error, info, warn};

mod cgroup;
mod cow;
mod lease;
mod violation;

/// Daemon-wide ceilings. A request may ask for less; it can never ask for more.
const MAX_MEMORY_BYTES_CEILING: u64 = 256 * 1024 * 1024;
const MAX_CPU_PERCENT_CEILING: u32 = 50;
const MAX_PIDS_CEILING: u32 = 100;

mod lease_lsm {
    include!(concat!(env!("OUT_DIR"), "/lease_lsm.skel.rs"));
}
use lease_lsm::*;

use cgroup::EphemeralCgroup;
use cow::OverlayWorkspace;
use lease::{bytes_of, lease_map_keys, BpfMapSync, LeaseConfig, LeaseManager};
use violation::{RawViolationEvent, ViolationEvent};

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
}

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
}

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
                                std::thread::spawn(move || {
                                    while let Ok(_) = built_rb.poll(Duration::from_millis(100)) {}
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
                        ) {
                            (Ok(leased_cgroups), Ok(protected_inodes), Ok(allowed_exec_inodes), Ok(allowed_connect_ipv4)) => {
                                bpf_sync = Some(Arc::new(LiveBpfSync {
                                    leased_cgroups,
                                    protected_inodes,
                                    allowed_exec_inodes,
                                    allowed_connect_ipv4,
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

    let lease_manager = LeaseManager::new(bpf_sync);

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
                    Err(e) => error!(
                        "Expired lease for mission {} (cg {}) could NOT be drained: {e:#}. Holding its policy installed rather than unpolicing a live workload.",
                        l.mission_id, l.cgroup_id
                    ),
                }

                // Only withdraw the policy once the cgroup is empty. A surviving process keeps its
                // lease so that it stays contained, and the failure above is what an operator acts
                // on - an unpoliced survivor is not an acceptable resting state.
                if EphemeralCgroup::kill_tree(&l.cgroup_path).is_ok() {
                    reaper_mgr.release_expired(&l);
                }
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
                tokio::spawn(async move {
                    if let Err(e) = handle_client(socket, mgr, viol_tx_clone).await {
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

async fn handle_client(
    socket: TcpStream,
    lease_mgr: LeaseManager,
    viol_tx: broadcast::Sender<ViolationEvent>,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    while buf_reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let parsed: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = serde_json::json!({
                    "type": "STDERR",
                    "data": format!("Invalid JSON request: {e}\n")
                });
                writer.write_all(format!("{err_resp}\n").as_bytes()).await?;
                line.clear();
                continue;
            }
        };

        let req_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match req_type {
            "HEALTH_CHECK" => {
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
                    "activeLeaseCount": lease_mgr.get_active_count()
                });
                writer.write_all(format!("{resp}\n").as_bytes()).await?;
            }

            "EXECUTE_TOOL" => {
                let mission_id = parsed.get("missionId").and_then(|v| v.as_str()).unwrap_or("default");
                let command = parsed.get("command").and_then(|v| v.as_str()).unwrap_or("/bin/sh");
                let arguments = parsed.get("arguments").and_then(|v| v.as_str()).unwrap_or("");
                let work_dir = parsed.get("workingDirectory").and_then(|v| v.as_str()).unwrap_or("/tmp");
                let duration_sec = parsed.get("leaseDurationSeconds").and_then(|v| v.as_u64()).unwrap_or(30) as u32;

                info!("Executing tool for mission {mission_id}: {command} {arguments}");

                // 0. Resolve the clamps FIRST.
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
                    cgroup::CgroupLimits {
                        max_memory_bytes: get_u64("maxMemoryBytes", MAX_MEMORY_BYTES_CEILING),
                        max_cpu_percent: get_u64("maxCpuPercent", MAX_CPU_PERCENT_CEILING as u64) as u32,
                        max_pids: get_u64("maxPids", MAX_PIDS_CEILING as u64) as u32,
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
                        let err_chunk = serde_json::json!({
                            "type": "STDERR",
                            "data": format!("SPLAT refused to execute: no lease could be provisioned ({e}).\n")
                        });
                        writer.write_all(format!("{err_chunk}\n").as_bytes()).await?;
                        let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                        writer.write_all(format!("{exit_chunk}\n").as_bytes()).await?;
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
                    allow_network: parsed.get("allowNetwork").and_then(|v| v.as_bool()).unwrap_or(false),
                    // The caller's declared policy is the lease. These were hardcoded, so a governed
                    // template could name its one approved destination and the kernel would never
                    // hear about it - the 1:1:1 rule held on the Windows side and evaporated here.
                    // An absent key keeps the old default so the local probe still works; an empty
                    // list is honoured as "nothing permitted" rather than silently widened.
                    allowed_egress_ips: string_list(&parsed, "allowedEgressIps")
                        .unwrap_or_else(|| vec!["127.0.0.1".to_string()]),
                    allowed_egress_ports: parsed
                        .get("allowedEgressPorts")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|p| p.as_u64().map(|n| n as u32)).collect())
                        .unwrap_or_else(|| vec![80, 443]),
                    read_only_fs: parsed.get("readOnlyFs").and_then(|v| v.as_bool()).unwrap_or(false),
                    // Union, never replacement: a caller may add protected paths but must not be
                    // able to unprotect the ones this daemon always guards.
                    protected_paths: {
                        let mut paths = vec!["/etc/shadow".to_string(), "/etc/sudoers".to_string()];
                        for extra in string_list(&parsed, "protectedPaths").unwrap_or_default() {
                            if !paths.contains(&extra) {
                                paths.push(extra);
                            }
                        }
                        paths
                    },
                    // The tool the caller asked for must itself be executable, or the lease refuses
                    // the very thing it was created to run. Before this, the list was the three
                    // hardcoded entries alone, so every EXECUTE_TOOL for anything else died at exec
                    // with a bare "Operation not permitted" - which read as a daemon bug rather than
                    // as policy. The other three stay because a shell tool commonly reaches for them.
                    allowed_exec_paths: {
                        let mut paths = vec![
                            "/bin/sh".to_string(),
                            "/bin/ping".to_string(),
                            "/usr/bin/curl".to_string(),
                        ];
                        if !paths.iter().any(|p| p == command) {
                            paths.push(command.to_string());
                        }
                        paths
                    },
                    lease_duration_seconds: duration_sec,
                    // Resolved above, before the cgroup existed, and already read back out of the
                    // controllers - so this records what the kernel holds, not what was requested.
                    limits: lease::LeaseLimits {
                        max_memory_bytes: cg.effective.max_memory_bytes,
                        max_cpu_percent: cg.effective.max_cpu_percent,
                        max_pids: cg.effective.max_pids,
                    },
                };

                // A lease that could not be installed is a refusal, not a warning. register_lease
                // rolls back its own partial map writes and returns Err, so there is no state in
                // which the cgroup is policed while some of its protections are missing.
                if let Err(e) = lease_mgr.register_lease(cg.cgroup_id, cg.path.clone(), &lease_cfg) {
                    error!("Refusing to execute for mission {mission_id}: {e:#}");
                    let err_chunk = serde_json::json!({
                        "type": "STDERR",
                        "data": format!("SPLAT refused to execute: the capability lease could not be installed ({e}).\n")
                    });
                    writer.write_all(format!("{err_chunk}\n").as_bytes()).await?;
                    let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                    writer.write_all(format!("{exit_chunk}\n").as_bytes()).await?;
                    line.clear();
                    continue;
                }

                // 2. Spawn Subprocess
                let mut cmd = Command::new(command);
                if !arguments.is_empty() {
                    cmd.args(arguments.split_whitespace());
                }
                cmd.current_dir(if Path::new(work_dir).exists() { work_dir } else { "/tmp" });
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
                if cgroup_is_real {
                    let procs = cg.path.join("cgroup.procs");
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
                                Ok(())
                            });
                        },
                        Err(e) => {
                            error!("Refusing to execute for mission {mission_id}: cgroup path is not a valid C string: {e}");
                            let err_chunk = serde_json::json!({
                                "type": "STDERR",
                                "data": "SPLAT refused to execute: the lease cgroup path could not be used.\n"
                            });
                            writer.write_all(format!("{err_chunk}\n").as_bytes()).await?;
                            let exit_chunk = serde_json::json!({ "type": "EXIT", "exitCode": -1 });
                            writer.write_all(format!("{exit_chunk}\n").as_bytes()).await?;
                            line.clear();
                            continue;
                        }
                    }
                }

                // Subscribe BEFORE spawning. An exec refused by the LSM fails inside the child, so
                // spawn() returns EPERM and the request ends here - if the subscription only began
                // after a successful spawn, the kernel's own violation for that refusal would never
                // reach the caller, who then cannot tell "the lease refused this" from "no such
                // binary". That is exactly what the first root run showed.
                let target_cgid = cg.cgroup_id;
                let mut viol_rx = viol_tx.subscribe();

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
                                        let chunk = serde_json::json!({
                                            "type": "VIOLATION",
                                            "cgroupId": v.cgroup_id,
                                            "pid": v.pid,
                                            "hook": v.hook,
                                            "detail": v.detail,
                                            "detailText": v.detail_text,
                                            "comm": v.comm
                                        });
                                        writer.write_all(format!("{chunk}\n").as_bytes()).await?;
                                        break;
                                    }
                                    Ok(Ok(_)) => continue,
                                    _ => break,
                                }
                            }
                        }

                        let err_chunk = serde_json::json!({
                            "type": "STDERR",
                            "data": format!("Failed to spawn process '{command}': {e}\n")
                        });
                        writer.write_all(format!("{err_chunk}\n").as_bytes()).await?;

                        let exit_chunk = serde_json::json!({
                            "type": "EXIT",
                            "exitCode": -1
                        });
                        writer.write_all(format!("{exit_chunk}\n").as_bytes()).await?;
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
                tokio::spawn(async move {
                    loop {
                        tokio::select! {
                            _ = &mut done_rx => {
                                // The ringbuf is polled on a ~100ms tick, so a denial that killed
                                // the child can still be in flight as it exits. Wait briefly, then
                                // flush whatever queued, so the last violation is not lost.
                                tokio::time::sleep(Duration::from_millis(250)).await;
                                while let Ok(v) = viol_rx.try_recv() {
                                    if v.cgroup_id == target_cgid {
                                        let chunk = serde_json::json!({
                                            "type": "VIOLATION",
                                            "cgroupId": v.cgroup_id,
                                            "pid": v.pid,
                                            "hook": v.hook,
                                            "detail": v.detail,
                                            "detailText": v.detail_text,
                                            "comm": v.comm
                                        });
                                        let _ = tx_viol.send(chunk).await;
                                    }
                                }
                                break;
                            }
                            recv = viol_rx.recv() => match recv {
                                Ok(v) => {
                                    if v.cgroup_id == target_cgid {
                                        let chunk = serde_json::json!({
                                            "type": "VIOLATION",
                                            "cgroupId": v.cgroup_id,
                                            "pid": v.pid,
                                            "hook": v.hook,
                                            "detail": v.detail,
                                            "detailText": v.detail_text,
                                            "comm": v.comm
                                        });
                                        let _ = tx_viol.send(chunk).await;
                                    }
                                }
                                Err(_) => break,
                            },
                        }
                    }
                });

                if let Some(out) = stdout {
                    let tx_out = tx.clone();
                    tokio::spawn(async move {
                        let mut reader = BufReader::new(out);
                        let mut buf = String::new();
                        while let Ok(n) = reader.read_line(&mut buf).await {
                            if n == 0 { break; }
                            let chunk = serde_json::json!({
                                "type": "STDOUT",
                                "data": buf.clone()
                            });
                            let _ = tx_out.send(chunk).await;
                            buf.clear();
                        }
                    });
                }

                if let Some(err) = stderr {
                    let tx_err = tx.clone();
                    tokio::spawn(async move {
                        let mut reader = BufReader::new(err);
                        let mut buf = String::new();
                        while let Ok(n) = reader.read_line(&mut buf).await {
                            if n == 0 { break; }
                            let chunk = serde_json::json!({
                                "type": "STDERR",
                                "data": buf.clone()
                            });
                            let _ = tx_err.send(chunk).await;
                            buf.clear();
                        }
                    });
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
                    if let Err(e) = writer.write_all(format!("{msg}\n").as_bytes()).await {
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

                let exit_chunk = serde_json::json!({
                    "type": "EXIT",
                    "exitCode": exit_code
                });
                writer.write_all(format!("{exit_chunk}\n").as_bytes()).await?;

                // 3. Atomically revoke lease upon exit
                lease_mgr.revoke_lease(cg.cgroup_id);
                info!("Completed tool execution for mission {mission_id} (exit code {exit_code})");
            }

            _ => {
                warn!("Unknown request type: {req_type}");
            }
        }

        line.clear();
    }

    Ok(())
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
