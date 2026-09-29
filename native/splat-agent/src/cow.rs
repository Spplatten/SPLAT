// Parent-only scratch preparation. Only jail::enter mounts it, after unshare in the child.

use std::fs;
use std::path::PathBuf;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::Path;
use anyhow::{bail, Context, Result};

pub const SCRATCH_BASE: &str = "/run/splat/cow";

pub fn validate_policy(lower: &Path, protected: &[String], executable: &[String]) -> Result<()> {
    let lower = fs::canonicalize(lower).context("resolve overlay workingDirectory")?;
    for path in protected.iter().chain(executable) {
        let resolved = fs::canonicalize(path).with_context(|| format!("resolve overlay policy path {path}"))?;
        // Overlay inodes do not retain the host (dev, ino). A deny-list miss would allow access;
        // an exec allow-list miss would deny it. Neither is the policy the caller requested.
        if resolved.starts_with(&lower) {
            bail!("overlayFs.enableCow: inode policy path {path} overlaps workingDirectory");
        }
    }
    Ok(())
}

// Called only after every orphan cgroup has drained; no surviving namespace may use this upperdir.
pub fn reap_leftovers(base: &Path) -> Result<()> {
    if !base.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        if entry.file_name().as_bytes().starts_with(b"mission_") && entry.file_type()?.is_dir() {
            fs::remove_dir_all(entry.path()).context("remove orphan overlay scratch")?;
        }
    }
    Ok(())
}

pub struct OverlayWorkspace {
    pub scratch_dir: PathBuf,
    pub options: CString,
}

impl OverlayWorkspace {
    pub fn setup(lower_dir: &Path, scratch_dir: &Path) -> Result<Self> {
        let lower = fs::canonicalize(lower_dir).context("resolve overlay lowerdir")?;
        let scratch = scratch_dir.to_path_buf();
        let upper = scratch.join("upper");
        let work = scratch.join("work");
        // Separators or escapes must not turn a path into different mount options.
        for path in [&lower, &upper, &work] {
            if path.as_os_str().as_bytes().iter().any(|b| matches!(b, 0 | b',' | b':' | b'\\')) {
                bail!("overlay path {} contains a mount-option separator", path.display());
            }
        }
        let parent = scratch.parent().context("overlay scratch needs a parent")?;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
        if fs::canonicalize(parent)?.starts_with(&lower) {
            bail!("overlay scratch must be outside its lowerdir");
        }
        fs::DirBuilder::new().mode(0o700).create(&scratch).context("create private overlay scratch")?;
        // A collision must never delete another lease's scratch; ownership starts after create.
        let mut workspace = Self { scratch_dir: scratch, options: CString::default() };
        fs::create_dir(&upper).context("create upperdir")?;
        fs::create_dir(&work).context("create workdir")?;
        let md = fs::metadata(&lower)?;
        let upper_c = CString::new(upper.as_os_str().as_bytes())?;
        if unsafe { libc::chown(upper_c.as_ptr(), md.uid(), md.gid()) } != 0 {
            return Err(std::io::Error::last_os_error()).context("preserve overlay root ownership");
        }
        fs::set_permissions(&upper, md.permissions())?;

        let mut options = b"lowerdir=".to_vec();
        options.extend_from_slice(lower.as_os_str().as_bytes());
        options.extend_from_slice(b",upperdir=");
        options.extend_from_slice(upper.as_os_str().as_bytes());
        options.extend_from_slice(b",workdir=");
        options.extend_from_slice(work.as_os_str().as_bytes());
        workspace.options = CString::new(options)?;
        Ok(workspace)
    }

    pub fn teardown(&mut self) -> Result<()> {
        if self.scratch_dir.exists() {
            fs::remove_dir_all(&self.scratch_dir).context("remove overlay scratch")?;
        }
        Ok(())
    }
}

impl Drop for OverlayWorkspace {
    fn drop(&mut self) {
        if let Err(e) = self.teardown() {
            tracing::warn!("Left overlay scratch {} behind: {e:#}", self.scratch_dir.display());
        }
    }
}
