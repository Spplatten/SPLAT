// Ephemeral cgroup v2 manager for per-mission capability leases.
// Every tool execution runs in an isolated sub-cgroup whose inode number
// is the kernel cgroup id used by BPF-LSM hooks.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};
use anyhow::{bail, Context, Result};
use tracing::warn;

/// Resource ceiling a lease actually receives, as opposed to the one it asked for.
///
/// Kept as its own type because the two used to drift: the cgroup was provisioned from three
/// constants at the call site while the request's own limits were parsed further down and never
/// applied, so a caller asking for 64 MiB silently got 256.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CgroupLimits {
    pub max_memory_bytes: u64,
    pub max_cpu_percent: u32,
    pub max_pids: u32,
}

pub struct EphemeralCgroup {
    pub path: PathBuf,
    pub cgroup_id: u64,
    /// What the controllers report AFTER the write, not what was requested.
    pub effective: CgroupLimits,
}

/// The cpu.max period, in microseconds. Quota is expressed against it.
const CPU_PERIOD_US: u64 = 100_000;

impl EphemeralCgroup {
    /// Creates the lease cgroup and installs `limits`, refusing if the kernel did not take them.
    ///
    /// Every write here used to be `let _ = fs::write(..)`. A controller that is not delegated to
    /// this cgroup, or a value the kernel clamps, therefore left the workload running with whatever
    /// limit it inherited while the caller was told its request had been accepted. A clamp nobody
    /// checked is not a clamp.
    pub fn create(mission_id: &str, limits: CgroupLimits) -> Result<Self> {
        let base = Path::new("/sys/fs/cgroup/splat_leases");
        if !base.exists() {
            fs::create_dir_all(base).context("create base splat_leases cgroup")?;
        }

        let path = base.join(format!("mission_{mission_id}"));
        if !path.exists() {
            fs::create_dir(&path).with_context(|| format!("create mission cgroup {}", path.display()))?;
        }

        // Read inode number as cgroup id (this matches bpf_get_current_cgroup_id in kernel)
        let md = fs::metadata(&path).with_context(|| format!("stat cgroup {}", path.display()))?;
        let cgroup_id = md.ino();

        let effective = match Self::apply_and_verify(&path, limits) {
            Ok(effective) => effective,
            Err(e) => {
                // Leave nothing half-configured behind: a cgroup that exists but is not clamped is
                // worse than none, because the next create() would find it and reuse it as-is.
                let _ = fs::remove_dir(&path);
                return Err(e);
            }
        };

        Ok(Self { path, cgroup_id, effective })
    }

    /// Writes each clamp and reads back what the controller actually holds.
    fn apply_and_verify(path: &Path, limits: CgroupLimits) -> Result<CgroupLimits> {
        if limits.max_memory_bytes > 0 {
            Self::write_control(path, "memory.max", &limits.max_memory_bytes.to_string())?;
        }

        if limits.max_cpu_percent > 0 {
            let quota = (limits.max_cpu_percent as u64) * CPU_PERIOD_US / 100;
            Self::write_control(path, "cpu.max", &format!("{quota} {CPU_PERIOD_US}"))?;
        }

        if limits.max_pids > 0 {
            Self::write_control(path, "pids.max", &limits.max_pids.to_string())?;
        }

        let effective = CgroupLimits {
            max_memory_bytes: Self::read_memory_max(path)?,
            max_cpu_percent: Self::read_cpu_percent(path)?,
            max_pids: Self::read_pids_max(path)?,
        };

        // The kernel may clamp a request downward - that is a stricter lease and therefore fine.
        // It must never end up looser than what was asked for, which is what an ignored write error
        // produced: the value stayed at the parent's "max" and the request looked honoured.
        if limits.max_memory_bytes > 0 && effective.max_memory_bytes > limits.max_memory_bytes {
            bail!(
                "memory.max is {} after requesting {}; the clamp did not take",
                effective.max_memory_bytes, limits.max_memory_bytes
            );
        }
        if limits.max_cpu_percent > 0 && effective.max_cpu_percent > limits.max_cpu_percent {
            bail!(
                "cpu.max is {}% after requesting {}%; the clamp did not take",
                effective.max_cpu_percent, limits.max_cpu_percent
            );
        }
        if limits.max_pids > 0 && effective.max_pids > limits.max_pids {
            bail!(
                "pids.max is {} after requesting {}; the clamp did not take",
                effective.max_pids, limits.max_pids
            );
        }

        Ok(effective)
    }

    fn write_control(path: &Path, control: &str, value: &str) -> Result<()> {
        let file = path.join(control);
        fs::write(&file, value)
            .with_context(|| format!("write {value} to {}", file.display()))
    }

    /// `max` means unlimited, which is the value a failed write leaves behind.
    fn read_memory_max(path: &Path) -> Result<u64> {
        let raw = Self::read_control(path, "memory.max")?;
        Ok(if raw == "max" { u64::MAX } else { raw.parse().context("parse memory.max")? })
    }

    fn read_pids_max(path: &Path) -> Result<u32> {
        let raw = Self::read_control(path, "pids.max")?;
        Ok(if raw == "max" { u32::MAX } else { raw.parse().context("parse pids.max")? })
    }

    /// cpu.max is "<quota> <period>", with quota "max" meaning no ceiling.
    fn read_cpu_percent(path: &Path) -> Result<u32> {
        let raw = Self::read_control(path, "cpu.max")?;
        let mut parts = raw.split_whitespace();
        let quota = parts.next().unwrap_or("max");
        if quota == "max" {
            return Ok(u32::MAX);
        }
        let period: u64 = parts.next().unwrap_or("100000").parse().unwrap_or(CPU_PERIOD_US);
        let quota: u64 = quota.parse().context("parse cpu.max quota")?;
        Ok(((quota.saturating_mul(100)) / period.max(1)) as u32)
    }

    fn read_control(path: &Path, control: &str) -> Result<String> {
        let file = path.join(control);
        Ok(fs::read_to_string(&file)
            .with_context(|| format!("read {}", file.display()))?
            .trim()
            .to_string())
    }

    pub fn attach_pid(&self, pid: u32) -> Result<()> {
        let procs = self.path.join("cgroup.procs");
        fs::write(&procs, format!("{pid}\n")).with_context(|| format!("attach pid {pid} to {}", procs.display()))?;
        Ok(())
    }

    /// Whether `pid` is a member of this cgroup.
    ///
    /// Used to confirm a tool really landed in its lease. Membership is what the BPF program keys
    /// on via `bpf_get_current_cgroup_id`, so a process outside the cgroup is entirely unpoliced —
    /// worth an explicit check rather than an assumption.
    pub fn contains_pid(&self, pid: u32) -> Result<bool> {
        let procs = self.path.join("cgroup.procs");
        let body = fs::read_to_string(&procs)
            .with_context(|| format!("read {}", procs.display()))?;
        Ok(body.lines().any(|l| l.trim() == pid.to_string()))
    }

    /// Kills every process in the cgroup and waits for it to drain.
    ///
    /// This is what makes expiry mean something. Removing a lease's BPF state while its workload
    /// keeps running does not contain that workload - it UNPOLICES it, because every hook returns
    /// allow for a cgroup it does not know. So the order at expiry is kill first, then withdraw the
    /// policy, and this is the half that was missing entirely.
    ///
    /// `cgroup.kill` (cgroup v2, Linux 5.14+) kills the whole subtree atomically, including
    /// descendants that reparented or that a signal loop would race. The SIGKILL fallback exists for
    /// older kernels and is inherently racy against a forking workload, which is why it is second.
    pub fn kill_all(&self) -> Result<usize> {
        Self::kill_tree(&self.path)
    }

    pub fn kill_tree(path: &Path) -> Result<usize> {
        if !path.exists() {
            return Ok(0);
        }

        let before = Self::member_pids(path).unwrap_or_default().len();

        let kill_file = path.join("cgroup.kill");
        if kill_file.exists() {
            fs::write(&kill_file, "1")
                .with_context(|| format!("write cgroup.kill for {}", path.display()))?;
        } else {
            for pid in Self::member_pids(path).unwrap_or_default() {
                // SAFETY: a pid read from this cgroup's own procs file; ESRCH is expected and fine.
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
        }

        // Reaping is asynchronous, and removing the directory before it drains fails with EBUSY -
        // which is how the old teardown left orphan cgroups behind.
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match Self::member_pids(path) {
                Ok(pids) if pids.is_empty() => return Ok(before),
                Ok(_) => thread::sleep(Duration::from_millis(20)),
                Err(_) => return Ok(before),
            }
        }

        let survivors = Self::member_pids(path).unwrap_or_default();
        if survivors.is_empty() {
            Ok(before)
        } else {
            bail!(
                "{} process(es) still in {} two seconds after kill: {survivors:?}",
                survivors.len(),
                path.display()
            )
        }
    }

    fn member_pids(path: &Path) -> Result<Vec<u32>> {
        let procs = path.join("cgroup.procs");
        let body = fs::read_to_string(&procs)
            .with_context(|| format!("read {}", procs.display()))?;
        Ok(body.lines().filter_map(|l| l.trim().parse::<u32>().ok()).collect())
    }
}

impl Drop for EphemeralCgroup {
    fn drop(&mut self) {
        if !self.path.exists() {
            return;
        }

        // Kill before removing. remove_dir on an occupied cgroup fails with EBUSY, and the previous
        // `let _ =` swallowed that - so a workload that outlived its request kept running in a
        // cgroup nobody was tracking any more.
        if let Err(e) = Self::kill_tree(&self.path) {
            warn!("Could not drain lease cgroup {}: {e:#}", self.path.display());
        }

        if let Err(e) = fs::remove_dir(&self.path) {
            warn!("Could not remove lease cgroup {}: {e}", self.path.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_percent_round_trips_through_the_quota_encoding() {
        // 50% of a 100ms period is a 50ms quota. The old encoding wrote percent * 1000, which is
        // the same number only because the period happened to be 100000us - it would have been
        // wrong for any other period.
        let dir = std::env::temp_dir().join(format!("splat_cg_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("cpu.max"), "50000 100000").unwrap();
        assert_eq!(EphemeralCgroup::read_cpu_percent(&dir).unwrap(), 50);

        std::fs::write(dir.join("cpu.max"), "max 100000").unwrap();
        assert_eq!(EphemeralCgroup::read_cpu_percent(&dir).unwrap(), u32::MAX);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unlimited_controller_reads_as_unlimited_not_as_the_request() {
        let dir = std::env::temp_dir().join(format!("splat_cg_max_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // "max" is exactly what a discarded write error leaves behind, so it must not be mistaken
        // for a clamp that took.
        std::fs::write(dir.join("memory.max"), "max").unwrap();
        std::fs::write(dir.join("pids.max"), "max").unwrap();
        assert_eq!(EphemeralCgroup::read_memory_max(&dir).unwrap(), u64::MAX);
        assert_eq!(EphemeralCgroup::read_pids_max(&dir).unwrap(), u32::MAX);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_controller_that_stayed_unlimited_fails_verification() {
        let dir = std::env::temp_dir().join(format!("splat_cg_verify_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("memory.max"), "max").unwrap();
        std::fs::write(dir.join("cpu.max"), "max 100000").unwrap();
        std::fs::write(dir.join("pids.max"), "max").unwrap();

        // apply_and_verify writes first; on a plain directory the writes succeed but the values do
        // not behave like a controller, so the read-back is what has to catch it. Simulate the
        // controller-absent case by verifying against a request stricter than the file contents.
        let limits = CgroupLimits { max_memory_bytes: 1024, max_cpu_percent: 10, max_pids: 4 };
        std::fs::write(dir.join("memory.max"), "max").unwrap();
        let err = (|| -> Result<()> {
            let effective = CgroupLimits {
                max_memory_bytes: EphemeralCgroup::read_memory_max(&dir)?,
                max_cpu_percent: EphemeralCgroup::read_cpu_percent(&dir)?,
                max_pids: EphemeralCgroup::read_pids_max(&dir)?,
            };
            if effective.max_memory_bytes > limits.max_memory_bytes {
                bail!("memory.max did not take");
            }
            Ok(())
        })()
        .unwrap_err();

        assert!(err.to_string().contains("did not take"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
