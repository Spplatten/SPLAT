// Multi-lease manager for BPF-LSM capability policies.
// Manages concurrent per-cgroup leases with deterministic second-scale lifecycles.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::violation::ipv4_to_be_u32;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InodeKey {
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

/// A policy entry as the kernel maps key it: the resource, scoped to ONE lease.
///
/// The maps used to be keyed by the resource alone, with the cgroup consulted only to decide
/// whether policy applied at all. Two concurrent leases therefore held the union of each other's
/// permissions, and revoking one deleted an entry the other still relied on. Mirrors
/// `struct lease_inode_key` in lease_lsm.bpf.c byte for byte.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LeaseInodeKey {
    pub cgroup_id: u64,
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

impl LeaseInodeKey {
    pub fn new(cgroup_id: u64, inode: &InodeKey) -> Self {
        Self { cgroup_id, ino: inode.ino, dev: inode.dev, _pad: 0 }
    }
}

/// Mirrors `struct lease_ipv4_key`. Address AND port, both in network byte order.
///
/// The port used to be missing on both sides: `allowed_egress_ports` was parsed, stored on the
/// config and never sent anywhere, so a lease that approved one host approved it on every port
/// that host listened on. Network byte order so the hook compares it straight against `sin_port`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LeaseIpv4Key {
    pub cgroup_id: u64,
    pub addr: u32,
    pub port: u16,
    pub _pad: u16,
}

impl LeaseIpv4Key {
    pub fn new(cgroup_id: u64, endpoint: &Ipv4Endpoint) -> Self {
        Self { cgroup_id, addr: endpoint.addr, port: endpoint.port, _pad: 0 }
    }
}

/// One approved destination: an IPv4 address on one port, both network byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Endpoint {
    pub addr: u32,
    pub port: u16,
}

// A map key whose Rust layout disagrees with the BPF struct silently looks up the wrong bytes, and
// for protected_inodes a missed lookup falls OPEN. Fail the build instead.
const _: () = assert!(std::mem::size_of::<LeaseInodeKey>() == 24);
const _: () = assert!(std::mem::size_of::<LeaseIpv4Key>() == 16);

/// Userspace `st_dev` and the kernel's `inode->i_sb->s_dev` encode the same device differently:
/// glibc packs major/minor into a 64-bit `dev_t`, while the kernel packs `(major << 20) | minor`
/// into 32 bits. The BPF program keys on the kernel form, so passing `st_dev` through made every
/// (dev, ino) lookup miss. That is not a symmetric failure - exec falls closed and is obvious,
/// but `protected_inodes` falls OPEN, because a missed lookup there reads as "not protected".
/// Caught by the canary on 2026-09-02, where the kernel denied exec of an allow-listed /bin/sh.
pub(crate) fn kernel_dev_from_st_dev(st_dev: u64) -> u32 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfffu64);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xffu64);
    (((major << 20) | (minor & 0xf_ffff)) & 0xffff_ffff) as u32
}

pub fn inode_key_for_path(path: &Path) -> Result<InodeKey> {
    let md = fs::metadata(path).with_context(|| format!("stat path {}", path.display()))?;
    Ok(InodeKey {
        ino: md.ino(),
        dev: kernel_dev_from_st_dev(md.dev()),
        _pad: 0,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseLimits {
    pub max_memory_bytes: u64,
    pub max_cpu_percent: u32,
    pub max_pids: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseConfig {
    pub mission_id: String,
    pub working_directory: String,
    pub allow_network: bool,
    pub allowed_egress_ips: Vec<String>,
    pub allowed_egress_ports: Vec<u32>,
    pub read_only_fs: bool,
    pub protected_paths: Vec<String>,
    pub allowed_exec_paths: Vec<String>,
    pub lease_duration_seconds: u32,
    pub limits: LeaseLimits,
}

#[derive(Clone, Debug)]
pub struct ActiveLease {
    pub mission_id: String,
    pub cgroup_id: u64,
    /// The cgroup this lease polices. Carried so expiry can KILL the workload before withdrawing
    /// the policy - a reaper holding only a cgroup id can unpolice a process but cannot stop it.
    pub cgroup_path: PathBuf,
    pub expires_at: Instant,
    /// The same deadline on CLOCK_BOOTTIME, as the kernel program compares it. `expires_at` drives
    /// the reaper's kill; this ends the lease's authority even when no reaper is running.
    pub deadline_boot_ns: u64,
    pub protected_inodes: Vec<InodeKey>,
    pub allowed_exec_inodes: Vec<InodeKey>,
    pub allowed_endpoints: Vec<Ipv4Endpoint>,
}

/// CLOCK_BOOTTIME in nanoseconds: the clock `bpf_ktime_get_boot_ns()` reads, which keeps counting
/// through suspend. A deadline written on any other clock would not mean the same instant in the kernel.
pub fn boot_clock_ns() -> Result<u64> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes one timespec through a valid pointer and reads nothing else.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        bail!("clock_gettime(CLOCK_BOOTTIME): {}", std::io::Error::last_os_error());
    }
    Ok(ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64)
}

pub fn bytes_of<T: Copy>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((v as *const T) as *const u8, std::mem::size_of::<T>()) }
}

/// The exact keys a lease occupies in each policy map.
///
/// Factored out so the live map driver and the isolation tests read the same construction: a test
/// that rebuilt the keys itself would only prove the test agrees with itself.
pub struct LeaseMapKeys {
    pub protected: Vec<LeaseInodeKey>,
    pub allowed_exec: Vec<LeaseInodeKey>,
    pub allowed_ipv4: Vec<LeaseIpv4Key>,
}

pub fn lease_map_keys(lease: &ActiveLease) -> LeaseMapKeys {
    LeaseMapKeys {
        protected: lease
            .protected_inodes
            .iter()
            .map(|k| LeaseInodeKey::new(lease.cgroup_id, k))
            .collect(),
        allowed_exec: lease
            .allowed_exec_inodes
            .iter()
            .map(|k| LeaseInodeKey::new(lease.cgroup_id, k))
            .collect(),
        allowed_ipv4: lease
            .allowed_endpoints
            .iter()
            .map(|e| LeaseIpv4Key::new(lease.cgroup_id, e))
            .collect(),
    }
}

pub trait BpfMapSync: Send + Sync {
    fn add_lease(&self, lease: &ActiveLease) -> Result<()>;
    fn remove_lease(&self, lease: &ActiveLease) -> Result<()>;

    fn scratch_exec_map(&self) -> Result<OwnedFd> {
        bail!("scratch execution requires a live kernel map")
    }

    /// How many denials the kernel could not record because the ring buffer was full, since the
    /// program was loaded. Global, not per lease: the counter lives in the program, and a lease can
    /// only report the difference across its own lifetime.
    fn dropped_events(&self) -> u64 {
        0
    }

    /// How many denials the kernel counted for this cgroup, read from its own map rather than from
    /// what the daemon managed to forward. `None` when there is no live program to ask: a mock or
    /// unprivileged daemon contains nothing, so it has no count and must not report zero as though
    /// it had one.
    ///
    /// This is the number a lease's receipt is measured against. Without it, "no VIOLATION frames
    /// arrived" and "nothing was denied" are the same sentence - and on 2026-09-25 they were. The
    /// kernel refused a datagram, the frame missed its session, and the run read as clean.
    fn violations_for(&self, _cgroup_id: u64) -> Option<u64> {
        None
    }

    /// Forgets a cgroup's denial count. Called when the lease is revoked, so the map holds only
    /// live leases and a cgroup id the kernel reuses cannot inherit a number.
    fn forget_violations(&self, _cgroup_id: u64) {}
}

#[derive(Clone)]
pub struct LeaseManager {
    leases: Arc<Mutex<HashMap<u64, ActiveLease>>>,
    bpf_sync: Option<Arc<dyn BpfMapSync>>,
}

impl LeaseManager {
    pub fn new(bpf_sync: Option<Arc<dyn BpfMapSync>>) -> Self {
        Self {
            leases: Arc::new(Mutex::new(HashMap::new())),
            bpf_sync,
        }
    }

    /// Whether leases registered here actually reach the kernel.
    ///
    /// False in mock and unprivileged modes, where the daemon is openly a stub. Callers use this to
    /// decide whether a containment failure is tolerable (dev run) or must refuse the work
    /// (enforcing run) - the distinction that keeps "we could not contain it" from being logged as a
    /// warning and then executed anyway.
    pub fn is_enforcing(&self) -> bool {
        self.bpf_sync.is_some()
    }

    pub fn scratch_exec_map(&self) -> Result<OwnedFd> {
        self.bpf_sync.as_ref().context("scratch execution requires kernel enforcement")?.scratch_exec_map()
    }

    pub fn register_lease(
        &self,
        cgroup_id: u64,
        cgroup_path: PathBuf,
        config: &LeaseConfig,
    ) -> Result<ActiveLease> {
        let duration = Duration::from_secs(config.lease_duration_seconds.clamp(5, 300) as u64);
        let now = Instant::now();

        let mut protected_inodes = Vec::new();
        for p in &config.protected_paths {
            if let Ok(key) = inode_key_for_path(Path::new(p)) {
                protected_inodes.push(key);
            }
        }

        let mut allowed_exec_inodes = Vec::new();
        for p in &config.allowed_exec_paths {
            if let Ok(key) = inode_key_for_path(Path::new(p)) {
                allowed_exec_inodes.push(key);
            }
        }

        // The cross product of approved addresses and approved ports. An address with no port is
        // not a destination, and the lease has always named both - only one of them ever travelled.
        let mut allowed_endpoints = Vec::new();
        if config.allow_network {
            for ip in &config.allowed_egress_ips {
                let Ok(addr) = ipv4_to_be_u32(ip) else { continue };
                for port in &config.allowed_egress_ports {
                    if let Ok(p) = u16::try_from(*port) {
                        allowed_endpoints.push(Ipv4Endpoint { addr, port: p.to_be() });
                    }
                }
            }
        }

        // A path the caller named that does not resolve is a policy the kernel will never see. It
        // used to be skipped silently by the `if let Ok` above, and the asymmetry is what makes
        // that dangerous: a missing entry in allowed_exec_inodes fails CLOSED and is obvious, while
        // a missing entry in protected_inodes fails OPEN - the file simply is not protected.
        if protected_inodes.len() != config.protected_paths.len() {
            bail!(
                "{} of {} protected path(s) could not be resolved to an inode; refusing to register \
                 a lease that would leave them unprotected",
                config.protected_paths.len() - protected_inodes.len(),
                config.protected_paths.len()
            );
        }

        let lease = ActiveLease {
            mission_id: config.mission_id.clone(),
            cgroup_id,
            cgroup_path,
            expires_at: now + duration,
            deadline_boot_ns: boot_clock_ns()?.saturating_add(duration.as_nanos() as u64),
            protected_inodes,
            allowed_exec_inodes,
            allowed_endpoints,
        };

        // A map write that failed used to be a warning, and the lease was registered anyway. The
        // writes are not atomic: leased_cgroups goes in first, so a failure partway through leaves
        // the cgroup POLICED while some of its protections are absent - the worst of both, and the
        // caller was told the lease was live. Roll the partial write back and refuse.
        if let Some(ref sync) = self.bpf_sync {
            if let Err(e) = sync.add_lease(&lease) {
                let _ = sync.remove_lease(&lease);
                bail!(
                    "could not install lease {} into the kernel capability maps: {e:#}",
                    lease.mission_id
                );
            }
        }

        let mut lock = self.leases.lock().unwrap();
        lock.insert(cgroup_id, lease.clone());

        Ok(lease)
    }

    pub fn revoke_lease(&self, cgroup_id: u64) -> Option<ActiveLease> {
        let mut lock = self.leases.lock().unwrap();
        if let Some(removed) = lock.remove(&cgroup_id) {
            if let Some(ref sync) = self.bpf_sync {
                if let Err(e) = sync.remove_lease(&removed) {
                    tracing::warn!("Failed to remove BPF capability maps for lease {}: {e}", removed.mission_id);
                }
                // After remove_lease, never before: the count is read for the EXIT frame that is
                // already written by now, and a cgroup id the kernel reuses must not inherit it.
                sync.forget_violations(cgroup_id);
            }
            Some(removed)
        } else {
            None
        }
    }

    pub fn get_active_count(&self) -> usize {
        let lock = self.leases.lock().unwrap();
        lock.len()
    }

    /// See [`BpfMapSync::dropped_events`]. Zero when nothing reaches the kernel.
    pub fn dropped_events(&self) -> u64 {
        self.bpf_sync.as_ref().map_or(0, |sync| sync.dropped_events())
    }

    /// See [`BpfMapSync::violations_for`]. `None` without a live program, which is the honest
    /// answer for a daemon that is not enforcing: it has denied nothing because it denies nothing.
    pub fn violations_for(&self, cgroup_id: u64) -> Option<u64> {
        self.bpf_sync.as_ref().and_then(|sync| sync.violations_for(cgroup_id))
    }

    /// Takes the expired leases out of the table WITHOUT touching the kernel.
    ///
    /// Withdrawing policy is deliberately not done here. An expired lease whose workload is still
    /// running must be killed while it is still policed; deleting its map entries first would leave
    /// a live process that every hook now waves through, which is the opposite of expiry. The
    /// caller kills, then calls `release_expired`.
    pub fn take_expired(&self) -> Vec<ActiveLease> {
        let mut lock = self.leases.lock().unwrap();
        let now = Instant::now();
        let mut expired = Vec::new();
        lock.retain(|_, v| {
            if now >= v.expires_at {
                expired.push(v.clone());
                false
            } else {
                true
            }
        });
        expired
    }

    /// Puts an expired lease whose workload would not die back into the table, policy still
    /// installed, so the next reaper tick tries again. Dropping it instead left the survivor policed
    /// but forgotten: its map entries never withdrawn, its cgroup never retried.
    pub fn hold_expired(&self, lease: ActiveLease) {
        let mut lock = self.leases.lock().unwrap();
        lock.insert(lease.cgroup_id, lease);
    }

    /// Withdraws an already-removed lease's kernel state. Call after the workload is dead.
    pub fn release_expired(&self, lease: &ActiveLease) {
        if let Some(ref sync) = self.bpf_sync {
            if let Err(e) = sync.remove_lease(lease) {
                tracing::warn!(
                    "Failed to remove BPF capability maps for expired lease {}: {e:#}",
                    lease.mission_id
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Records what reached the kernel, and can be told to fail the way a full or unwritable map
    /// does.
    struct RecordingSync {
        added: AtomicUsize,
        removed: AtomicUsize,
        fail_add: AtomicBool,
    }

    impl RecordingSync {
        fn new(fail_add: bool) -> Arc<Self> {
            Arc::new(Self {
                added: AtomicUsize::new(0),
                removed: AtomicUsize::new(0),
                fail_add: AtomicBool::new(fail_add),
            })
        }
    }

    impl BpfMapSync for RecordingSync {
        fn add_lease(&self, _lease: &ActiveLease) -> Result<()> {
            self.added.fetch_add(1, Ordering::SeqCst);
            if self.fail_add.load(Ordering::SeqCst) {
                anyhow::bail!("simulated map update failure partway through the lease");
            }
            Ok(())
        }

        fn remove_lease(&self, _lease: &ActiveLease) -> Result<()> {
            self.removed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn config(protected: Vec<&str>, seconds: u32) -> LeaseConfig {
        LeaseConfig {
            mission_id: "m-1".to_string(),
            working_directory: "/tmp".to_string(),
            allow_network: false,
            allowed_egress_ips: vec![],
            allowed_egress_ports: vec![],
            read_only_fs: false,
            protected_paths: protected.into_iter().map(str::to_string).collect(),
            allowed_exec_paths: vec!["/bin/sh".to_string()],
            lease_duration_seconds: seconds,
            limits: LeaseLimits { max_memory_bytes: 1024, max_cpu_percent: 10, max_pids: 4 },
        }
    }

    #[test]
    fn a_failed_map_write_refuses_the_lease_and_rolls_back() {
        let sync = RecordingSync::new(true);
        let mgr = LeaseManager::new(Some(sync.clone()));

        let err = mgr
            .register_lease(42, PathBuf::from("/sys/fs/cgroup/splat_leases/mission_m-1"), &config(vec!["/etc/hostname"], 30))
            .unwrap_err();

        // The map writes are not atomic - leased_cgroups goes in first - so a partial failure used
        // to leave the cgroup POLICED with some of its protections missing, reported as a warning.
        assert!(err.to_string().contains("could not install lease"));
        assert_eq!(sync.removed.load(Ordering::SeqCst), 1, "the partial write must be rolled back");
        assert_eq!(mgr.get_active_count(), 0, "a refused lease must not be registered");
    }

    #[test]
    fn a_protected_path_that_does_not_resolve_refuses_the_lease() {
        let sync = RecordingSync::new(false);
        let mgr = LeaseManager::new(Some(sync.clone()));

        let err = mgr
            .register_lease(
                43,
                PathBuf::from("/sys/fs/cgroup/splat_leases/mission_m-1"),
                &config(vec!["/etc/hostname", "/no/such/file/splat-test"], 30),
            )
            .unwrap_err();

        // Skipping it silently is the asymmetric failure: a missing allowed_exec entry falls
        // closed and is obvious, a missing protected_inodes entry falls OPEN.
        assert!(err.to_string().contains("could not be resolved"));
        assert_eq!(sync.added.load(Ordering::SeqCst), 0, "nothing should reach the kernel");
        assert_eq!(mgr.get_active_count(), 0);
    }

    #[test]
    fn a_good_lease_still_registers() {
        let sync = RecordingSync::new(false);
        let mgr = LeaseManager::new(Some(sync.clone()));

        mgr.register_lease(44, PathBuf::from("/sys/fs/cgroup/splat_leases/mission_m-1"), &config(vec!["/etc/hostname"], 30))
            .expect("a resolvable lease with a working map must register");

        assert_eq!(sync.added.load(Ordering::SeqCst), 1);
        assert_eq!(mgr.get_active_count(), 1);
    }

    #[test]
    fn taking_an_expired_lease_does_not_withdraw_its_policy() {
        let sync = RecordingSync::new(false);
        let mgr = LeaseManager::new(Some(sync.clone()));

        // clamp() floors the duration at 5s, so drive expiry by hand rather than sleeping.
        mgr.register_lease(45, PathBuf::from("/tmp/splat-nonexistent-cg"), &config(vec!["/etc/hostname"], 5))
            .unwrap();
        {
            let mut lock = mgr.leases.lock().unwrap();
            let lease = lock.get_mut(&45).unwrap();
            lease.expires_at = Instant::now() - Duration::from_secs(1);
        }

        let expired = mgr.take_expired();

        assert_eq!(expired.len(), 1);
        assert_eq!(mgr.get_active_count(), 0);
        // The kernel state must still be installed at this point. Withdrawing it before the
        // workload is dead does not contain an overrunning process, it UNPOLICES it - every hook
        // returns allow for a cgroup it no longer knows.
        assert_eq!(
            sync.removed.load(Ordering::SeqCst),
            0,
            "take_expired must not touch the maps; the caller kills first, then releases"
        );

        mgr.release_expired(&expired[0]);
        assert_eq!(sync.removed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_lease_the_reaper_could_not_drain_is_held_for_the_next_tick() {
        let sync = RecordingSync::new(false);
        let mgr = LeaseManager::new(Some(sync.clone()));

        mgr.register_lease(47, PathBuf::from("/tmp/splat-nonexistent-cg"), &config(vec!["/etc/hostname"], 5))
            .unwrap();
        {
            let mut lock = mgr.leases.lock().unwrap();
            lock.get_mut(&47).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        }

        let expired = mgr.take_expired();
        assert_eq!(expired.len(), 1);
        assert_eq!(mgr.get_active_count(), 0);

        // The kill failed: the lease goes back, still expired, and its policy is still installed.
        mgr.hold_expired(expired.into_iter().next().unwrap());
        assert_eq!(mgr.get_active_count(), 1, "a held lease is still a live lease");
        assert_eq!(sync.removed.load(Ordering::SeqCst), 0, "holding must not withdraw the policy");

        let again = mgr.take_expired();
        assert_eq!(again.len(), 1, "the next tick sees it again");
        mgr.release_expired(&again[0]);
        assert_eq!(sync.removed.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_endpoint_cross_product_is_what_reaches_the_maps() {
        // Two addresses and two ports is four endpoints, not two - a lease that names both
        // dimensions has to install both, and only the address half ever travelled before.
        let sync = RecordingSync::new(false);
        let mgr = LeaseManager::new(Some(sync));

        let mut cfg = config(vec!["/etc/hostname"], 30);
        cfg.allow_network = true;
        cfg.allowed_egress_ips = vec!["127.0.0.1".to_string(), "10.0.0.1".to_string()];
        cfg.allowed_egress_ports = vec![80, 443];

        let lease = mgr
            .register_lease(77, PathBuf::from("/tmp/cg"), &cfg)
            .expect("register");

        assert_eq!(lease_map_keys(&lease).allowed_ipv4.len(), 4);
    }

    #[test]
    fn an_expired_lease_carries_the_cgroup_the_reaper_has_to_kill() {
        let sync = RecordingSync::new(false);
        let mgr = LeaseManager::new(Some(sync));
        let path = PathBuf::from("/sys/fs/cgroup/splat_leases/mission_m-1");

        mgr.register_lease(46, path.clone(), &config(vec!["/etc/hostname"], 5)).unwrap();
        {
            let mut lock = mgr.leases.lock().unwrap();
            lock.get_mut(&46).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        }

        // A reaper holding only a cgroup id can unpolice a process but cannot stop it.
        assert_eq!(mgr.take_expired()[0].cgroup_path, path);
    }
}

#[cfg(test)]
mod isolation_tests {
    use super::*;
    use std::collections::HashSet;

    /// A stand-in for the four BPF hash maps: a set of the exact key bytes the driver wrote.
    ///
    /// The keys come from `lease_map_keys`, the same function the live driver calls, so this
    /// exercises the real construction rather than a test's opinion of it.
    #[derive(Default)]
    struct FakeKernelMaps {
        protected: HashSet<Vec<u8>>,
        allowed_exec: HashSet<Vec<u8>>,
        allowed_ipv4: HashSet<Vec<u8>>,
    }

    impl FakeKernelMaps {
        fn install(&mut self, lease: &ActiveLease) {
            let keys = lease_map_keys(lease);
            for k in &keys.protected {
                self.protected.insert(bytes_of(k).to_vec());
            }
            for k in &keys.allowed_exec {
                self.allowed_exec.insert(bytes_of(k).to_vec());
            }
            for k in &keys.allowed_ipv4 {
                self.allowed_ipv4.insert(bytes_of(k).to_vec());
            }
        }

        fn withdraw(&mut self, lease: &ActiveLease) {
            let keys = lease_map_keys(lease);
            for k in &keys.protected {
                self.protected.remove(bytes_of(k));
            }
            for k in &keys.allowed_exec {
                self.allowed_exec.remove(bytes_of(k));
            }
            for k in &keys.allowed_ipv4 {
                self.allowed_ipv4.remove(bytes_of(k));
            }
        }

        /// The kernel's question at the hook: is (this cgroup, this resource) permitted?
        fn may_exec(&self, cgroup_id: u64, inode: &InodeKey) -> bool {
            self.allowed_exec
                .contains(bytes_of(&LeaseInodeKey::new(cgroup_id, inode)))
        }

        fn is_protected(&self, cgroup_id: u64, inode: &InodeKey) -> bool {
            self.protected
                .contains(bytes_of(&LeaseInodeKey::new(cgroup_id, inode)))
        }

        fn may_connect(&self, cgroup_id: u64, addr: u32, port: u16) -> bool {
            self.allowed_ipv4.contains(bytes_of(&LeaseIpv4Key::new(
                cgroup_id,
                &Ipv4Endpoint { addr, port: port.to_be() },
            )))
        }
    }

    fn inode(ino: u64) -> InodeKey {
        InodeKey { ino, dev: 66, _pad: 0 }
    }

    fn lease_for(
        cgroup_id: u64,
        exec: Vec<InodeKey>,
        protected: Vec<InodeKey>,
        endpoints: Vec<Ipv4Endpoint>,
    ) -> ActiveLease {
        let now = Instant::now();
        ActiveLease {
            mission_id: format!("m-{cgroup_id}"),
            cgroup_id,
            cgroup_path: PathBuf::from(format!("/sys/fs/cgroup/splat_leases/mission_m-{cgroup_id}")),
            expires_at: now + Duration::from_secs(30),
            deadline_boot_ns: boot_clock_ns().unwrap() + 30_000_000_000,
            protected_inodes: protected,
            allowed_exec_inodes: exec,
            allowed_endpoints: endpoints,
        }
    }

    const PYTHON: u64 = 4242;
    const SHADOW: u64 = 1111;
    const GRANTS_IP: u32 = 0x0100_007f;
    const HTTPS: u16 = 443;

    fn endpoint(addr: u32, port: u16) -> Ipv4Endpoint {
        Ipv4Endpoint { addr, port: port.to_be() }
    }

    #[test]
    fn one_missions_allowed_executable_is_not_granted_to_another() {
        let mut maps = FakeKernelMaps::default();

        // A asked for python3. B asked only for /bin/sh, and never named python3.
        let a = lease_for(100, vec![inode(PYTHON)], vec![inode(SHADOW)], vec![]);
        let b = lease_for(200, vec![inode(9001)], vec![inode(SHADOW)], vec![]);
        maps.install(&a);
        maps.install(&b);

        assert!(maps.may_exec(a.cgroup_id, &inode(PYTHON)), "A asked for it and must keep it");
        assert!(
            !maps.may_exec(b.cgroup_id, &inode(PYTHON)),
            "B never asked for python3; a resource-only key handed it B's way as the union of both leases"
        );
    }

    #[test]
    fn one_missions_egress_destination_is_not_granted_to_another() {
        let mut maps = FakeKernelMaps::default();

        let a = lease_for(100, vec![], vec![], vec![endpoint(GRANTS_IP, HTTPS)]);
        let b = lease_for(200, vec![], vec![], vec![]);
        maps.install(&a);
        maps.install(&b);

        assert!(maps.may_connect(a.cgroup_id, GRANTS_IP, HTTPS));
        assert!(
            !maps.may_connect(b.cgroup_id, GRANTS_IP, HTTPS),
            "B declared no egress at all and must not inherit A's destination"
        );
    }

    #[test]
    fn an_approved_host_is_not_approved_on_every_port() {
        let mut maps = FakeKernelMaps::default();

        // The lease names 443. Port 22 on the same host was never granted - and used to be
        // reachable anyway, because the key carried no port at all.
        let a = lease_for(100, vec![], vec![], vec![endpoint(GRANTS_IP, HTTPS)]);
        maps.install(&a);

        assert!(maps.may_connect(a.cgroup_id, GRANTS_IP, HTTPS));
        assert!(
            !maps.may_connect(a.cgroup_id, GRANTS_IP, 22),
            "approving a host on 443 must not approve it on 22"
        );
    }

    #[test]
    fn revoking_one_lease_does_not_unprotect_a_file_another_still_holds() {
        let mut maps = FakeKernelMaps::default();

        // Both leases protect /etc/shadow - the daemon adds it to every lease unconditionally.
        let a = lease_for(100, vec![], vec![inode(SHADOW)], vec![]);
        let b = lease_for(200, vec![], vec![inode(SHADOW)], vec![]);
        maps.install(&a);
        maps.install(&b);

        maps.withdraw(&a);

        assert!(!maps.is_protected(a.cgroup_id, &inode(SHADOW)), "A's entry is gone, as intended");
        assert!(
            maps.is_protected(b.cgroup_id, &inode(SHADOW)),
            "revoking A deleted the single shared entry, and B lost a protection it still held - \
             a revocation that fails OPEN for a live mission"
        );
    }

    #[test]
    fn the_lease_scope_is_the_only_thing_that_differs_between_two_leases_on_one_resource() {
        // Byte-level, because the kernel compares these keys as bytes. If the cgroup id ever stopped
        // occupying the leading eight, two leases would collide again without any test noticing.
        let a = LeaseInodeKey::new(100, &inode(PYTHON));
        let b = LeaseInodeKey::new(200, &inode(PYTHON));

        let (ab, bb) = (bytes_of(&a).to_vec(), bytes_of(&b).to_vec());
        assert_ne!(ab, bb);
        assert_eq!(ab[8..], bb[8..], "the resource half must be identical");
        assert_ne!(ab[..8], bb[..8], "the lease half must differ");
    }

    #[test]
    fn the_key_layout_matches_the_bpf_structs() {
        // struct lease_inode_key { __u64; __u64; __u32; __u32; } and
        // struct lease_ipv4_key  { __u64; __u32; __u32; }.
        // A mismatch looks up the wrong bytes, and for protected_inodes a miss falls OPEN.
        assert_eq!(std::mem::size_of::<LeaseInodeKey>(), 24);
        assert_eq!(std::mem::align_of::<LeaseInodeKey>(), 8);
        // struct lease_ipv4_key { __u64; __u32; __u16; __u16; } - still 16 bytes with the port
        // folded into the padding the address left behind.
        assert_eq!(std::mem::size_of::<LeaseIpv4Key>(), 16);
        assert_eq!(std::mem::align_of::<LeaseIpv4Key>(), 8);
    }
}
