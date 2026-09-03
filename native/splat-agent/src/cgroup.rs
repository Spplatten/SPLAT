// Ephemeral cgroup v2 manager for per-mission capability leases.
// Every tool execution runs in an isolated sub-cgroup whose inode number
// is the kernel cgroup id used by BPF-LSM hooks.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};

pub struct EphemeralCgroup {
    pub path: PathBuf,
    pub cgroup_id: u64,
}

impl EphemeralCgroup {
    pub fn create(mission_id: &str, max_memory_bytes: u64, max_cpu_percent: u32, max_pids: u32) -> Result<Self> {
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

        // 1. Configure RAM clamp
        if max_memory_bytes > 0 {
            let mem_max = path.join("memory.max");
            let _ = fs::write(&mem_max, format!("{max_memory_bytes}"));
        }

        // 2. Configure CPU quota (percent of single core or multi-core quota)
        if max_cpu_percent > 0 {
            let cpu_max = path.join("cpu.max");
            // quota period: 100000us. e.g. 50% = 50000 100000
            let quota = (max_cpu_percent as u64) * 1000;
            let _ = fs::write(&cpu_max, format!("{quota} 100000"));
        }

        // 3. Configure PID clamp
        if max_pids > 0 {
            let pids_max = path.join("pids.max");
            let _ = fs::write(&pids_max, format!("{max_pids}"));
        }

        Ok(Self { path, cgroup_id })
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
}

impl Drop for EphemeralCgroup {
    fn drop(&mut self) {
        // Remove cgroup directory upon drop (cgroup must be empty of processes)
        if self.path.exists() {
            let _ = fs::remove_dir(&self.path);
        }
    }
}