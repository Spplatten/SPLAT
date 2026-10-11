//! A root-only, payload-free journal identifies secret workspaces left by a daemon crash.
//! Recovery runs only after startup has verified that all old lease cgroups are drained.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct Registry { root: PathBuf, directory: PathBuf }

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record { workspace: String, uid: u32 }

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        bail!("secret recovery journal must be a root-owned private directory");
    }
    Ok(())
}

impl Registry {
    pub fn recover(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
            || root.canonicalize()? != root {
            bail!("secret workspace root must be canonical, root-owned and not writable by others");
        }
        let directory = root.join(".secret-steps");
        match fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("create secret recovery journal"),
        }
        private_directory(&directory)?;
        let registry = Self { root: root.to_owned(), directory };
        for entry in fs::read_dir(&registry.directory)? {
            let path = entry?.path();
            let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.len() > 4096 {
                bail!("untrustworthy secret recovery record");
            }
            let mut public = Vec::new();
            std::io::Read::by_ref(&mut file).take(4097).read_to_end(&mut public)?;
            let record: Record = serde_json::from_slice(&public).context("invalid secret recovery record")?;
            let workspace = registry.root.join(&record.workspace);
            if !crate::workspace::is_mission_workspace(&registry.root.to_string_lossy(), &workspace.to_string_lossy()) {
                bail!("secret recovery record escapes the workspace root");
            }
            match fs::symlink_metadata(&workspace) {
                Ok(metadata) if metadata.is_dir() && metadata.uid() == record.uid => {
                    if !crate::workspace::remove(&workspace) { bail!("secret workspace recovery is incomplete"); }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => bail!("secret workspace identity changed; refusing recovery"),
            }
            fs::remove_file(path)?;
        }
        Ok(registry)
    }

    pub fn register(&self, workspace: &Path, uid: u32) -> Result<PathBuf> {
        if !crate::workspace::is_mission_workspace(&self.root.to_string_lossy(), &workspace.to_string_lossy()) {
            bail!("secret workspace lies outside the recovery root");
        }
        let name = workspace.file_name().and_then(|name| name.to_str()).context("invalid secret workspace name")?;
        let path = self.directory.join(format!("{}.json", crate::auth::hex(&crate::auth::random_bytes::<32>()?)));
        let record = serde_json::to_vec(&Record { workspace: name.into(), uid })?;
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        file.write_all(&record)?;
        file.sync_all()?;
        fs::File::open(&self.directory)?.sync_all()?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    #[ignore = "root component proof; touches only a temporary fixture directory"]
    fn root_secret_recovery_removes_recorded_workspaces_and_rejects_path_escape() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let base = std::env::temp_dir().join(format!("splat-secret-recovery-{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        let root = base.join("missions");
        let registry = Registry::recover(&root).unwrap();
        let workspace = root.join("crashed");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("synthetic-input"), "synthetic-only").unwrap();
        let record = registry.register(&workspace, 0).unwrap();
        drop(registry);
        let registry = Registry::recover(&root).unwrap();
        assert!(!workspace.exists());
        assert!(!record.exists());
        let outside = base.join("keep");
        fs::create_dir(&outside).unwrap();
        let corrupt = registry.directory.join("corrupt.json");
        let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(&corrupt).unwrap();
        file.write_all(br#"{"workspace":"../keep","uid":0}"#).unwrap();
        assert!(Registry::recover(&root).is_err());
        assert!(outside.exists());
        fs::remove_file(corrupt).unwrap();
        fs::remove_dir_all(base).unwrap();
    }
}
