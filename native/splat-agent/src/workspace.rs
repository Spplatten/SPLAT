//! A governed mission's workspace in the guest: made by the daemon for one lease, owned by the
//! workload, and removed when the lease ends.
//!
//! The working directory of a lease had to exist already, and one that did not sent the tool to
//! `/tmp` without a word. A mission run from Windows has no way to make a directory in the guest
//! except through root, and root in the guest is this daemon. So the lease may ask, and the daemon
//! makes the directory - but only directly under its missions root, named by one safe component,
//! so a request cannot have root create a path of its choosing anywhere else.

use std::fs;
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::{Component, Path};

use anyhow::{bail, Context, Result};
use tracing::warn;

/// Whether `work_dir` is a directory this daemon may make: directly under `root`, one component,
/// and that component made of the characters a mission id is made of.
pub fn is_mission_workspace(root: &str, work_dir: &str) -> bool {
    let root = Path::new(root);
    let path = Path::new(work_dir);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return false;
    }
    let Some(parent) = path.parent() else { return false };
    if parent != root {
        return false;
    }
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) if !name.is_empty() => name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'),
        _ => false,
    }
}

/// Makes `work_dir` for the workload, and its root above it for the daemon, and returns whether this
/// call created it. A directory that already exists is not adopted: a lease's workspace is its own,
/// and one that is already there belongs to something else.
pub fn create(work_dir: &Path, uid: u32, gid: u32) -> Result<bool> {
    if work_dir.exists() {
        bail!("{} already exists; a mission's workspace is made for it, never adopted", work_dir.display());
    }
    if let Some(root) = work_dir.parent() {
        fs::create_dir_all(root).with_context(|| format!("create {}", root.display()))?;
        // Root's, traversable by the workload so it can reach its own directory, writable by nobody else.
        fs::set_permissions(root, fs::Permissions::from_mode(0o711)).with_context(|| format!("mode {}", root.display()))?;
    }
    fs::create_dir(work_dir).with_context(|| format!("create {}", work_dir.display()))?;
    fs::set_permissions(work_dir, fs::Permissions::from_mode(0o700)).with_context(|| format!("mode {}", work_dir.display()))?;
    chown(work_dir, Some(uid), Some(gid)).with_context(|| format!("chown {} to {uid}:{gid}", work_dir.display()))?;
    Ok(true)
}

/// Removes a workspace this daemon made. Best effort, and says so: the lease is over either way, and
/// a directory that could not be removed is reported to the caller as remaining, never as gone.
pub fn remove(work_dir: &Path) -> bool {
    match fs::remove_dir_all(work_dir) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
        Err(e) => {
            warn!("The workspace {} could not be removed: {e}", work_dir.display());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_child_of_the_root_named_like_a_mission_is_a_workspace() {
        assert!(is_mission_workspace("/var/lib/splat/missions", "/var/lib/splat/missions/3f2a-mission_1.x"));
        assert!(!is_mission_workspace("/var/lib/splat/missions", "/var/lib/splat/missions"));
        assert!(!is_mission_workspace("/var/lib/splat/missions", "/var/lib/splat/missions/a/b"));
        assert!(!is_mission_workspace("/var/lib/splat/missions", "/var/lib/splat/missions/../etc"));
        assert!(!is_mission_workspace("/var/lib/splat/missions", "/etc/splat"));
        assert!(!is_mission_workspace("/var/lib/splat/missions", "/var/lib/splat/missions/with space"));
        assert!(!is_mission_workspace("/var/lib/splat/missions", "relative/path"));
    }

    #[test]
    fn a_workspace_is_made_once_and_removed() {
        let root = std::env::temp_dir().join(format!("splat_ws_{}", std::process::id()));
        let ws = root.join("mission-1");
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        assert!(create(&ws, uid, gid).unwrap());
        assert!(ws.is_dir());
        assert_eq!(fs::metadata(&ws).unwrap().permissions().mode() & 0o777, 0o700);
        // Made for one lease: a second lease naming the same directory is refused it.
        assert!(create(&ws, uid, gid).is_err());
        assert!(remove(&ws));
        assert!(!ws.exists());
        // Gone already is still gone.
        assert!(remove(&ws));
        let _ = fs::remove_dir_all(&root);
    }
}
