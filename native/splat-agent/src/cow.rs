// Ephemeral OverlayFS copy-on-write workspace: merged view over lowerdir plus transient
// upper/work dirs, discarded on teardown.
//
// NOT WIRED, AND NOT YET A BOUNDARY. Two separate facts, and the second is why the first has not
// been fixed by simply calling it:
//
//   * `mount()` here happens in the DAEMON's mount namespace, so the overlay is visible to every
//     process on the host rather than only to the leased tool.
//   * A merged directory handed to a child as its working directory is a starting point, not a
//     jail. The tool can `cd /` out of it in one syscall.
//
// Making this a filesystem boundary needs `unshare(CLONE_NEWNS)` in the child followed by
// pivot_root, done inside the same pre_exec closure that already performs the cgroup join and the
// privilege drop - and that closure is async-signal-safe code in a forked child of a multithreaded
// process, so it is real work with real failure modes rather than a call site that was forgotten.
//
// Until that lands the daemon REFUSES `overlayFs.enableCow`, so the gap is a refusal rather than a
// silently ignored field. The mount code stays because it is correct as far as it goes and is the
// half that will be reused; it is parked, not abandoned.
#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;
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