// Multi-lease manager for BPF-LSM capability policies.
// Manages concurrent per-cgroup leases with deterministic second-scale lifecycles.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
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

/// Userspace `st_dev` and the kernel's `inode->i_sb->s_dev` encode the same device differently:
/// glibc packs major/minor into a 64-bit `dev_t`, while the kernel packs `(major << 20) | minor`
/// into 32 bits. The BPF program keys on the kernel form, so passing `st_dev` through made every
/// (dev, ino) lookup miss. That is not a symmetric failure - exec falls closed and is obvious,
/// but `protected_inodes` falls OPEN, because a missed lookup there reads as "not protected".
/// Caught by the canary on 2026-09-02, where the kernel denied exec of an allow-listed /bin/sh.
fn kernel_dev_from_st_dev(st_dev: u64) -> u32 {
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
    pub created_at: Instant,
    pub expires_at: Instant,
    pub protected_inodes: Vec<InodeKey>,
    pub allowed_exec_inodes: Vec<InodeKey>,
    pub allowed_ips: Vec<u32>,
}

pub fn bytes_of<T: Copy>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((v as *const T) as *const u8, std::mem::size_of::<T>()) }
}

pub trait BpfMapSync: Send + Sync {
    fn add_lease(&self, lease: &ActiveLease) -> Result<()>;
    fn remove_lease(&self, lease: &ActiveLease) -> Result<()>;
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

        let mut allowed_ips = Vec::new();
        if config.allow_network {
            for ip in &config.allowed_egress_ips {
                if let Ok(val) = ipv4_to_be_u32(ip) {
                    allowed_ips.push(val);
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
            created_at: now,
            expires_at: now + duration,
            protected_inodes,
            allowed_exec_inodes,
            allowed_ips,
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
