// Ephemeral OverlayFS Copy-on-Write workspace manager.
// Creates merged view over lowerdir + transient upper/work dirs.
// Discards scratch state on mission failure or teardown for clean rollback.

use std::fs;
use std::path::{Path, PathBuf};
use std::ffi::CString;
use anyhow::{bail, Context, Result};

pub struct OverlayWorkspace {
    pub lower_dir: PathBuf,
    pub scratch_dir: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub merged_dir: PathBuf,
    pub is_mounted: bool,
}

impl OverlayWorkspace {
    pub fn setup(lower_dir: &str, scratch_dir: &str) -> Result<Self> {
        let lower = PathBuf::from(lower_dir);
        let scratch = PathBuf::from(scratch_dir);
        let upper = scratch.join("upper");
        let work = scratch.join("work");
        let merged = scratch.join("merged");

        if !lower.exists() {
            fs::create_dir_all(&lower).context("create lowerdir")?;
        }
        fs::create_dir_all(&upper).context("create upperdir")?;
        fs::create_dir_all(&work).context("create workdir")?;
        fs::create_dir_all(&merged).context("create mergeddir")?;

        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );

        let c_src = CString::new("overlay")?;
        let c_tgt = CString::new(merged.to_string_lossy().as_bytes())?;
        let c_type = CString::new("overlay")?;
        let c_opts = CString::new(options.as_bytes())?;

        let res = unsafe {
            libc::mount(
                c_src.as_ptr(),
                c_tgt.as_ptr(),
                c_type.as_ptr(),
                0,
                c_opts.as_ptr() as *const libc::c_void,
            )
        };

        if res != 0 {
            bail!("failed to mount overlayfs at {}: errno {}", merged.display(), unsafe { *libc::__errno_location() });
        }

        Ok(Self {
            lower_dir: lower,
            scratch_dir: scratch,
            upper_dir: upper,
            work_dir: work,
            merged_dir: merged,
            is_mounted: true,
        })
    }

    pub fn teardown(&mut self) -> Result<()> {
        if self.is_mounted {
            let c_tgt = CString::new(self.merged_dir.to_string_lossy().as_bytes())?;
            let res = unsafe { libc::umount2(c_tgt.as_ptr(), libc::MNT_DETACH) };
            if res == 0 {
                self.is_mounted = false;
            }
        }
        if self.scratch_dir.exists() {
            let _ = fs::remove_dir_all(&self.scratch_dir);
        }
        Ok(())
    }
}

impl Drop for OverlayWorkspace {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}