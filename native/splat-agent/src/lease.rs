// Multi-lease manager for BPF-LSM capability policies.
// Manages concurrent per-cgroup leases with deterministic second-scale lifecycles.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
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

pub struct ActiveLease {
    pub mission_id: String,
    pub cgroup_id: u64,
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

        let lease = ActiveLease {
            mission_id: config.mission_id.clone(),
            cgroup_id,
            created_at: now,
            expires_at: now + duration,
            protected_inodes,
            allowed_exec_inodes,
            allowed_ips,
        };

        if let Some(ref sync) = self.bpf_sync {
            if let Err(e) = sync.add_lease(&lease) {
                tracing::warn!("Failed to synchronize BPF capability maps for lease {}: {e}", lease.mission_id);
            }
        }

        let mut lock = self.leases.lock().unwrap();
        lock.insert(cgroup_id, ActiveLease {
            mission_id: lease.mission_id.clone(),
            cgroup_id: lease.cgroup_id,
            created_at: lease.created_at,
            expires_at: lease.expires_at,
            protected_inodes: lease.protected_inodes.clone(),
            allowed_exec_inodes: lease.allowed_exec_inodes.clone(),
            allowed_ips: lease.allowed_ips.clone(),
        });

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

    pub fn prune_expired(&self) -> Vec<ActiveLease> {
        let mut lock = self.leases.lock().unwrap();
        let now = Instant::now();
        let mut expired = Vec::new();
        let sync_opt = self.bpf_sync.clone();
        lock.retain(|_, v| {
            if now >= v.expires_at {
                let lease = ActiveLease {
                    mission_id: v.mission_id.clone(),
                    cgroup_id: v.cgroup_id,
                    created_at: v.created_at,
                    expires_at: v.expires_at,
                    protected_inodes: v.protected_inodes.clone(),
                    allowed_exec_inodes: v.allowed_exec_inodes.clone(),
                    allowed_ips: v.allowed_ips.clone(),
                };
                if let Some(ref sync) = sync_opt {
                    let _ = sync.remove_lease(&lease);
                }
                expired.push(lease);
                false
            } else {
                true
            }
        });
        expired
    }
}