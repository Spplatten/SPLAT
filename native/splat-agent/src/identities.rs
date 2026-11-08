//! Leases and pending secret grants cannot share a UID with a sibling that can inspect them.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// How many leases this daemon can hold at once: `leased_cgroups` in lease_lsm.bpf.c has this many
/// entries and no more. The session limit and the identity pool are both this number, so every
/// lease the kernel can police has a private UID and no UID is reserved for a lease that could
/// never be admitted. The operator's rule for the pool (2026-10-29): no more, no less.
pub const LEASE_CAPACITY: u32 = 256;

/// The first private lease UID unless the operator reserves another range. Debian's useradd hands
/// each new login a 65536-wide subordinate block from 100000, so the second user created already
/// owns 165536..231071 - which held the old default, 200000. Two million is past the first 28 such
/// blocks; the /etc/subuid check in `reserved` covers a host that has handed out more.
pub const DEFAULT_LEASE_UID_START: u32 = 2_000_000;
const _: () = assert!(DEFAULT_LEASE_UID_START >= 100_000 + 65_536 * 28);

#[derive(Clone)]
pub struct IdentityPool {
    start: u32,
    used: Arc<Mutex<Vec<bool>>>,
}

impl IdentityPool {
    pub fn reserved(start: u32, count: u32, legacy_uid: u32, legacy_gid: u32) -> Result<Self> {
        if start < 65536 || count == 0 || count > LEASE_CAPACITY || start.checked_add(count).is_none_or(|end| end == u32::MAX) {
            bail!("lease identity range must contain 1..{LEASE_CAPACITY} IDs above 65535, without overflow");
        }
        for id in start..start + count {
            if id == legacy_uid || id == legacy_gid || account_exists(id)? {
                bail!("lease identity range overlaps an existing account or the legacy workload identity");
            }
        }
        // Subordinate IDs are not accounts, so NSS never names them, but their owner can map them
        // into a user namespace and become them - including a lease's UID, files and processes.
        if overlaps_subordinate_ids(start, count, &[Path::new("/etc/subuid"), Path::new("/etc/subgid")])? {
            bail!("lease identity range overlaps a subordinate ID block in /etc/subuid or /etc/subgid");
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
                            bail!("lease identity range is in use by an existing process");
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) => {}
                Err(_) => bail!("could not verify that the lease identity range is unused"),
            }
        }
        Ok(Self::empty(start, count as usize))
    }

    fn empty(start: u32, count: usize) -> Self {
        Self { start, used: Arc::new(Mutex::new(vec![false; count])) }
    }

    pub fn acquire(&self) -> Result<LeaseIdentity> {
        let mut used = self.used.lock().map_err(|_| anyhow::anyhow!("identity pool unavailable"))?;
        let index = used.iter().position(|busy| !busy).ok_or_else(|| anyhow::anyhow!("private lease identity capacity exhausted"))?;
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

/// Does `[start, start + count)` meet any `owner:first:count` block in these files? A missing file
/// holds no blocks; one that cannot be read or parsed is not evidence that the range is free.
fn overlaps_subordinate_ids(start: u32, count: u32, files: &[&Path]) -> Result<bool> {
    let (lo, hi) = (u64::from(start), u64::from(start) + u64::from(count));
    for file in files {
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).with_context(|| format!("read {}", file.display())),
        };
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let fields: Vec<&str> = line.split(':').collect();
            let block = match fields.as_slice() {
                [_, first, n] => first.parse::<u64>().ok().zip(n.parse::<u64>().ok()),
                _ => None,
            };
            let Some((first, n)) = block else {
                bail!("could not parse a line of {}", file.display());
            };
            if first < hi && lo < first.saturating_add(n) {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
            tracing::warn!("A workload identity remains quarantined after incomplete teardown");
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
    fn a_range_inside_a_subordinate_block_is_refused() {
        let file = std::env::temp_dir().join(format!("splat_subuid_{}", std::process::id()));
        std::fs::write(&file, "alice:100000:65536\nbob:165536:65536\n").unwrap();
        let files = [file.as_path(), Path::new("/nonexistent/subgid")];
        assert!(overlaps_subordinate_ids(200_000, 256, &files).unwrap(), "the old default sat in bob's block");
        assert!(overlaps_subordinate_ids(231_071, 1, &files).unwrap(), "a block's last id is in it");
        assert!(!overlaps_subordinate_ids(231_072, 256, &files).unwrap());
        assert!(!overlaps_subordinate_ids(DEFAULT_LEASE_UID_START, LEASE_CAPACITY, &files).unwrap());
        std::fs::write(&file, "alice:100000\n").unwrap();
        assert!(overlaps_subordinate_ids(DEFAULT_LEASE_UID_START, LEASE_CAPACITY, &files).is_err(),
                "a file that cannot be parsed is not proof the range is free");
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn the_pool_holds_exactly_as_many_leases_as_the_kernel_map() {
        assert_eq!(LEASE_CAPACITY, crate::admission::Role::LeasedCgroups.spec().max_entries);
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
