//! A secret step cannot share a UID with a sibling that can inspect its process memory.

use anyhow::{bail, Result};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct IdentityPool {
    start: u32,
    used: Arc<Mutex<Vec<bool>>>,
}

impl IdentityPool {
    pub fn reserved(start: u32, count: u32, legacy_uid: u32, legacy_gid: u32) -> Result<Self> {
        if start < 65536 || count == 0 || count > 256 || start.checked_add(count).is_none_or(|end| end == u32::MAX) {
            bail!("secret identity range must contain 1..256 IDs above 65535, without overflow");
        }
        for id in start..start + count {
            if id == legacy_uid || id == legacy_gid || account_exists(id)? {
                bail!("secret identity range overlaps an existing account or the legacy workload identity");
            }
        }
        // An account-free range can still have a surviving process. Startup drains old lease
        // cgroups before this check; an unrelated occupant requires a different reserved range.
        for entry in std::fs::read_dir("/proc")? {
            let entry = entry?;
            if !entry.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) { continue; }
            match std::fs::read_to_string(entry.path().join("status")) {
                Ok(status) => {
                    for line in status.lines().filter(|line| line.starts_with("Uid:") || line.starts_with("Gid:")) {
                        if line.split_whitespace().skip(1).filter_map(|id| id.parse::<u32>().ok())
                            .any(|id| (start..start + count).contains(&id)) {
                            bail!("secret identity range is in use by an existing process");
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) => {}
                Err(_) => bail!("could not verify that the secret identity range is unused"),
            }
        }
        Ok(Self::empty(start, count as usize))
    }

    fn empty(start: u32, count: usize) -> Self {
        Self { start, used: Arc::new(Mutex::new(vec![false; count])) }
    }

    pub fn acquire(&self) -> Result<LeaseIdentity> {
        let mut used = self.used.lock().map_err(|_| anyhow::anyhow!("identity pool unavailable"))?;
        let index = used.iter().position(|busy| !busy).ok_or_else(|| anyhow::anyhow!("secret step capacity exhausted"))?;
        used[index] = true;
        Ok(LeaseIdentity { pool: self.clone(), index, spawned: false })
    }

    #[cfg(test)]
    pub fn for_test(count: usize) -> Self { Self::empty(200000, count) }
}

fn account_exists(id: u32) -> Result<bool> {
    // Reentrant NSS calls avoid static passwd/group buffers in the multithreaded daemon.
    let mut buffer = vec![0u8; 65536];
    unsafe {
        let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut found = std::ptr::null_mut();
        let rc = libc::getpwuid_r(id, passwd.as_mut_ptr(), buffer.as_mut_ptr().cast(), buffer.len(), &mut found);
        if rc != 0 { bail!("could not check the reserved UID range"); }
        if !found.is_null() { return Ok(true); }
        let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut found = std::ptr::null_mut();
        let rc = libc::getgrgid_r(id, group.as_mut_ptr(), buffer.as_mut_ptr().cast(), buffer.len(), &mut found);
        if rc != 0 { bail!("could not check the reserved GID range"); }
        Ok(!found.is_null())
    }
}

pub struct LeaseIdentity {
    pool: IdentityPool,
    index: usize,
    spawned: bool,
}

impl LeaseIdentity {
    pub fn id(&self) -> u32 { self.pool.start + self.index as u32 }
    pub fn mark_spawned(&mut self) { self.spawned = true; }
    pub fn release_after_drain(&mut self) { self.spawned = false; }
}

impl Drop for LeaseIdentity {
    fn drop(&mut self) {
        // A failed drain must never hand the same identity to a new secret. Quarantine it until
        // restart, when orphan cleanup and the /proc scan precede a new pool.
        if !self.spawned {
            if let Ok(mut used) = self.pool.used.lock() { used[self.index] = false; }
        } else {
            tracing::warn!("A secret workload identity remains quarantined after incomplete teardown");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_steps_have_distinct_ids_and_capacity_is_bounded() {
        let pool = IdentityPool::for_test(2);
        let first = pool.acquire().unwrap();
        let second = pool.acquire().unwrap();
        assert_ne!(first.id(), second.id());
        assert!(pool.acquire().is_err());
        drop(first);
        assert!(pool.acquire().is_ok());
    }

    #[test]
    fn an_undrained_identity_is_never_reused() {
        let pool = IdentityPool::for_test(1);
        let mut step = pool.acquire().unwrap();
        step.mark_spawned();
        drop(step);
        assert!(pool.acquire().is_err());
    }

    #[test]
    fn a_proven_drain_releases_capacity() {
        let pool = IdentityPool::for_test(1);
        let mut step = pool.acquire().unwrap();
        step.mark_spawned();
        step.release_after_drain();
        drop(step);
        assert!(pool.acquire().is_ok());
    }
}
