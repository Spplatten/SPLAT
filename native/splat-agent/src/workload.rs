//! Ordinary workloads retain their private identity until processes, scratch and workspace drain.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Workload {
    pub identity: crate::identities::LeaseIdentity,
    recovery: crate::secret_recovery::Registry,
    workspace: Option<PathBuf>,
    record: Option<PathBuf>,
    cleanup: Option<Cleanup>,
}

struct Cleanup {
    path: PathBuf,
    cgroup_id: u64,
    manager: crate::lease::LeaseManager,
    jail: Option<Arc<crate::jail::JailPlan>>,
    scratch: Vec<PathBuf>,
    drained: bool,
}

impl Workload {
    pub fn new(identity: crate::identities::LeaseIdentity, recovery: crate::secret_recovery::Registry) -> Self {
        Self { identity, recovery, workspace: None, record: None, cleanup: None }
    }

    pub fn register_workspace(&mut self, path: &Path) -> Result<()> {
        self.workspace = Some(path.to_owned());
        self.record = Some(self.recovery.register(path, self.identity.id())?);
        Ok(())
    }

    pub fn arm_cleanup(&mut self, cgroup: &crate::cgroup::EphemeralCgroup,
        manager: crate::lease::LeaseManager, jail: Option<Arc<crate::jail::JailPlan>>) {
        let scratch = jail.as_ref().map_or_else(Vec::new, |plan| plan.cleanup_paths());
        self.cleanup = Some(Cleanup { path: cgroup.path.clone(), cgroup_id: cgroup.cgroup_id,
            manager, jail, scratch, drained: false });
    }

    pub fn finish(&mut self) -> Result<()> {
        if let Some(cleanup) = &mut self.cleanup {
            if !cleanup.drained {
                crate::cgroup::EphemeralCgroup::kill_tree(&cleanup.path)?;
                cleanup.drained = true;
            }
            cleanup.jail.take();
            for path in &cleanup.scratch {
                match std::fs::symlink_metadata(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    _ => bail!("ordinary workload scratch cleanup is incomplete"),
                }
            }
            cleanup.scratch.clear();
        }
        self.remove_workspace()?;
        self.identity.release_after_drain();
        Ok(())
    }

    fn remove_workspace(&mut self) -> Result<()> {
        if self.workspace.as_ref().is_some_and(|path| !crate::workspace::remove(path)) {
            bail!("ordinary workload workspace cleanup is incomplete");
        }
        self.workspace = None;
        if let Some(record) = &self.record {
            match std::fs::remove_file(record) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.record = None;
        Ok(())
    }
}

pub fn remove_workspace(workload: Option<&mut Workload>, path: &Path) -> bool {
    // Refusal branches can remove a workspace before the guard drops. Retire its pathname once,
    // so cleanup cannot remove another request's directory after the mission name is reused.
    workload.map_or_else(|| crate::workspace::remove(path), |workload| workload.remove_workspace().is_ok())
}

impl Drop for Workload {
    fn drop(&mut self) {
        // Socket errors and cancelled tasks take this path too. Keeping a jail Arc here prevents
        // earlier local drops from tearing down mounts while a descendant still uses its UID.
        let drained = self.cleanup.as_mut().is_none_or(|cleanup| {
            // Once drained, never resolve this mission's pathname again: a later cgroup with the
            // same mission name must not be mistaken for the one whose identity we are releasing.
            if !cleanup.drained { cleanup.drained = crate::cgroup::EphemeralCgroup::kill_tree(&cleanup.path).is_ok(); }
            cleanup.drained
        });
        if !drained {
            self.identity.mark_spawned();
            if let Some(jail) = self.cleanup.as_mut().and_then(|cleanup| cleanup.jail.take()) {
                std::mem::forget(jail);
            }
            return;
        }
        if let Some(cleanup) = &self.cleanup { cleanup.manager.revoke_lease(cleanup.cgroup_id); }
        if self.finish().is_err() {
            self.identity.mark_spawned();
            tracing::warn!("An ordinary workload identity remains quarantined after incomplete cleanup");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "root component proof; only private temporary workspace fixtures are changed"]
    fn root_workload_cleanup_releases_only_removed_workspaces() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let base = std::env::temp_dir().join(format!("splat-workload-cleanup-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        let recovery = crate::secret_recovery::Registry::recover(&base).unwrap();
        let pool = crate::identities::IdentityPool::for_test(1);
        let workspace = base.join("removed");
        std::fs::create_dir(&workspace).unwrap();
        let mut workload = Workload::new(pool.acquire().unwrap(), recovery.clone());
        workload.register_workspace(&workspace).unwrap();
        workload.identity.mark_spawned();
        workload.finish().unwrap();
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("later-request"), "synthetic").unwrap();
        drop(workload);
        assert!(workspace.join("later-request").exists());
        // A file where a directory should be makes cleanup fail. That UID must stay quarantined.
        let obstacle = base.join("retained");
        std::fs::write(&obstacle, "synthetic").unwrap();
        let mut workload = Workload::new(pool.acquire().unwrap(), recovery);
        workload.register_workspace(&obstacle).unwrap();
        drop(workload);
        assert!(obstacle.exists());
        assert!(pool.acquire().is_err());
        std::fs::remove_dir_all(base).unwrap();
    }
}
