// The workload's own root: a mount namespace holding only what the lease needs.
//
// Until this existed the lease was a deny-list on files. Everything the deny-list did not name was
// reachable at the workload's uid, which on WSL included the Windows drives under /mnt. A jail is
// the other shape: a root that contains the system directories read-only, the working directory,
// a fresh /tmp, a /proc and a handful of device nodes, and nothing else. /home, /root, /mnt, /var,
// /opt and /sys are not hidden; they are absent.
//
// Two halves, kept apart on purpose:
//
//   * `JailPlan::prepare` runs in the PARENT. It may allocate, and it builds every path the child
//     will need as a CString, creates the root's skeleton of empty directories, and remembers what
//     it created so that it - and only it - is removed afterwards.
//   * `enter` runs in the forked CHILD, between the cgroup join and the privilege drop, while the
//     child is still root. It is async-signal-safe code: raw syscalls on pointers the parent
//     prepared, no allocation, no locks, no formatting. A failure returns the errno, and a failed
//     spawn refuses the request; a workload never runs half-jailed.
//
// Bind mounts keep inode identity, so the exec allow-list and the file deny-list - both keyed on
// (dev, ino) resolved from the host's view of the path - hold inside the jail unchanged.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::ptr;

use anyhow::{bail, Context, Result};
use tracing::warn;

/// Where lease roots are built: a root-owned directory on tmpfs, gone on reboot.
pub const ROOTS_BASE: &str = "/run/splat/roots";

/// Bound read-only into every jail, whichever of them exist on the host. /etc travels whole: the
/// resolver, the certificates and the passwd entry for `nobody` live there, and the files there
/// that `nobody` may not read are denied by their mode or by the inode deny-list, both of which a
/// bind mount preserves.
const SYSTEM_DIRS: [&str; 8] = ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc"];

/// The device nodes a tool can reasonably need. Each is a bind of the host's node onto an empty
/// file in the jail's /dev, so nothing else under /dev exists there.
const DEV_NODES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];

/// One bind mount the child performs, in order.
struct Bind {
    source: CString,
    target: CString,
    read_only: bool,
}

/// Something the parent created and will remove. Never a tree: removal is one `rmdir` or
/// `unlink` per entry, so a mount that somehow leaked into the host namespace makes the removal
/// fail rather than making it recurse into `/usr`.
enum Created {
    Dir(PathBuf),
    Entry(PathBuf),
}

pub struct JailPlan {
    new_root: CString,
    old_root: CString,
    /// The system directories, read-only, mounted first.
    system_binds: Vec<Bind>,
    /// The working directory, mounted after the fresh /tmp it may live inside.
    workdir_bind: Option<Bind>,
    tmpfs_tmp: Option<CString>,
    tmp_mkdirs: Vec<CString>,
    dev_binds: Vec<(CString, CString)>,
    proc_dir: CString,
    chdir: CString,
    created: Vec<Created>,
}

impl JailPlan {
    /// Builds the root's skeleton under `base` for `mission_id`, with `workdir` bound read-write, or
    /// read-only when `read_only_workdir`. `host` is `/` in the daemon; the tests point it at a
    /// directory of their own.
    pub fn prepare(base: &Path, mission_id: &str, workdir: &Path, read_only_workdir: bool, host: &Path) -> Result<Self> {
        if mission_id.is_empty() || !mission_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            bail!("mission id {mission_id:?} is not a safe path component");
        }
        if !workdir.is_absolute() || workdir.components().any(|c| matches!(c, Component::ParentDir)) {
            bail!("working directory {} is not an absolute path without '..'", workdir.display());
        }
        let host_workdir = host.join(workdir.strip_prefix("/").unwrap_or(workdir));
        if !host_workdir.is_dir() {
            bail!("working directory {} is not a directory", workdir.display());
        }

        fs::create_dir_all(base).with_context(|| format!("create {}", base.display()))?;
        let root = base.join(format!("mission_{mission_id}"));
        let mut plan = Self {
            new_root: c_path(&root),
            old_root: c_path(&root.join(".oldroot")),
            system_binds: Vec::new(),
            workdir_bind: None,
            tmpfs_tmp: None,
            tmp_mkdirs: Vec::new(),
            dev_binds: Vec::new(),
            proc_dir: c_path(&root.join("proc")),
            chdir: c_path(workdir),
            created: Vec::new(),
        };
        // From here every early return drops the plan, and Drop removes what was made so far.
        plan.mkdir(&root)?;

        let mut bound_prefixes: Vec<&Path> = Vec::new();
        for dir in SYSTEM_DIRS {
            let on_host = host.join(&dir[1..]);
            let Ok(md) = fs::symlink_metadata(&on_host) else { continue };
            let in_jail = root.join(&dir[1..]);
            if md.file_type().is_symlink() {
                // A merged-usr host has /bin -> usr/bin. The same link in the jail keeps every path
                // the same as on the host, which is what the allow-list keys were resolved against.
                let target = fs::read_link(&on_host).with_context(|| format!("read link {}", on_host.display()))?;
                symlink(&target, &in_jail).with_context(|| format!("create link {}", in_jail.display()))?;
                plan.created.push(Created::Entry(in_jail));
            } else if md.is_dir() {
                plan.mkdir(&in_jail)?;
                plan.system_binds.push(Bind { source: c_path(&on_host), target: c_path(&in_jail), read_only: true });
                bound_prefixes.push(Path::new(dir));
            }
        }

        // /tmp is fresh unless it IS the working directory. A working directory under /tmp lives
        // inside the fresh tmpfs, so its mount point can only be made in the child, after the tmpfs.
        let jail_tmp = root.join("tmp");
        if workdir == Path::new("/tmp") {
            plan.mkdir(&jail_tmp)?;
        } else {
            plan.mkdir(&jail_tmp)?;
            plan.tmpfs_tmp = Some(c_path(&jail_tmp));
        }

        let jail_workdir = root.join(workdir.strip_prefix("/").unwrap_or(workdir));
        if workdir == Path::new("/tmp") {
            // Its mount point already exists.
        } else if workdir.starts_with("/tmp") {
            let mut at = jail_tmp.clone();
            for component in workdir.strip_prefix("/tmp").unwrap_or(Path::new("")).components() {
                at.push(component);
                plan.tmp_mkdirs.push(c_path(&at));
            }
        } else if !bound_prefixes.iter().any(|p| workdir.starts_with(p)) {
            // Under a bound system directory the mount point is the host's own directory, visible
            // through the bind; anywhere else the skeleton needs the path.
            let mut at = root.clone();
            for component in workdir.strip_prefix("/").unwrap_or(workdir).components() {
                at.push(component);
                if !at.exists() {
                    plan.mkdir(&at)?;
                }
            }
        }
        plan.workdir_bind = Some(Bind { source: c_path(&host_workdir), target: c_path(&jail_workdir), read_only: read_only_workdir });

        let jail_dev = root.join("dev");
        plan.mkdir(&jail_dev)?;
        for node in DEV_NODES {
            let on_host = host.join("dev").join(node);
            if !on_host.exists() {
                continue;
            }
            let in_jail = jail_dev.join(node);
            fs::File::create(&in_jail).with_context(|| format!("create {}", in_jail.display()))?;
            plan.created.push(Created::Entry(in_jail.clone()));
            plan.dev_binds.push((c_path(&on_host), c_path(&in_jail)));
        }
        for (name, target) in [("fd", "/proc/self/fd"), ("stdin", "/proc/self/fd/0"), ("stdout", "/proc/self/fd/1"), ("stderr", "/proc/self/fd/2")] {
            let link = jail_dev.join(name);
            symlink(target, &link).with_context(|| format!("create link {}", link.display()))?;
            plan.created.push(Created::Entry(link));
        }

        plan.mkdir(&root.join("proc"))?;
        plan.mkdir(&root.join(".oldroot"))?;
        Ok(plan)
    }

    fn mkdir(&mut self, path: &Path) -> Result<()> {
        fs::create_dir(path).with_context(|| format!("create {}", path.display()))?;
        self.created.push(Created::Dir(path.to_path_buf()));
        Ok(())
    }

    /// The paths the child will bind, in order, as (source, target, read-only). For tests.
    #[cfg(test)]
    fn binds(&self) -> Vec<(String, String, bool)> {
        self.system_binds
            .iter()
            .chain(self.workdir_bind.iter())
            .map(|b| (b.source.to_string_lossy().into_owned(), b.target.to_string_lossy().into_owned(), b.read_only))
            .collect()
    }

    #[cfg(test)]
    fn tmp_mkdirs(&self) -> Vec<String> {
        self.tmp_mkdirs.iter().map(|p| p.to_string_lossy().into_owned()).collect()
    }
}

impl Drop for JailPlan {
    fn drop(&mut self) {
        // Reverse order, one entry at a time. A directory that is not empty is left where it is and
        // said so: the only way that happens is something this plan did not create being in it.
        for made in self.created.drain(..).rev() {
            let result = match &made {
                Created::Dir(path) => fs::remove_dir(path),
                Created::Entry(path) => fs::remove_file(path),
            };
            if let Err(e) = result {
                let path = match &made {
                    Created::Dir(p) | Created::Entry(p) => p,
                };
                warn!("Left {} behind: {e}", path.display());
            }
        }
    }
}

/// Removes the skeletons a previous daemon left under `base`. Only what a skeleton is made of is
/// removed - empty directories, symlinks and empty files - and never across a filesystem boundary,
/// so a mount that somehow survived is a stop, not a tree to descend.
pub fn reap_leftover_roots(base: &Path) -> Result<usize> {
    if !base.exists() {
        return Ok(0);
    }
    let base_dev = fs::metadata(base)?.dev();
    let mut removed = 0;
    for entry in fs::read_dir(base).with_context(|| format!("read {}", base.display()))? {
        let path = entry?.path();
        if remove_skeleton(&path, base_dev)? {
            removed += 1;
        }
    }
    Ok(removed)
}

fn remove_skeleton(path: &Path, base_dev: u64) -> Result<bool> {
    let md = fs::symlink_metadata(path)?;
    if md.file_type().is_symlink() || (md.is_file() && md.len() == 0) {
        fs::remove_file(path)?;
        return Ok(true);
    }
    if !md.is_dir() || md.dev() != base_dev {
        return Ok(false);
    }
    let mut all_gone = true;
    for child in fs::read_dir(path)? {
        if !remove_skeleton(&child?.path(), base_dev)? {
            all_gone = false;
        }
    }
    if all_gone {
        fs::remove_dir(path)?;
    }
    Ok(all_gone)
}

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("a path holds no NUL")
}

/// Enters the jail. Called in the forked child, as root, after the cgroup join and before the
/// privilege drop: async-signal-safe, nothing here allocates.
///
/// # Safety
/// Must run in a freshly forked child of the process that built `plan`, and nothing else.
pub unsafe fn enter(plan: &JailPlan) -> io::Result<()> {
    let none: *const libc::c_char = ptr::null();
    let null_data: *const libc::c_void = ptr::null();

    check(libc::unshare(libc::CLONE_NEWNS))?;
    // Nothing mounted below propagates back to the host's namespace.
    check(libc::mount(none, c"/".as_ptr(), none, libc::MS_REC | libc::MS_PRIVATE, null_data))?;
    // pivot_root wants a mount point; the root directory bound onto itself is one.
    check(libc::mount(plan.new_root.as_ptr(), plan.new_root.as_ptr(), none, libc::MS_BIND, null_data))?;

    for bind in &plan.system_binds {
        bind_mount(bind)?;
    }
    // The fresh /tmp, then the working directory, which may live inside it.
    if let Some(tmp) = &plan.tmpfs_tmp {
        check(libc::mount(
            c"tmpfs".as_ptr(),
            tmp.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV,
            c"mode=1777".as_ptr().cast(),
        ))?;
        for dir in &plan.tmp_mkdirs {
            check(libc::mkdir(dir.as_ptr(), 0o755))?;
        }
    }
    if let Some(bind) = &plan.workdir_bind {
        bind_mount(bind)?;
    }

    for (source, target) in &plan.dev_binds {
        check(libc::mount(source.as_ptr(), target.as_ptr(), none, libc::MS_BIND, null_data))?;
    }
    check(libc::mount(
        c"proc".as_ptr(),
        plan.proc_dir.as_ptr(),
        c"proc".as_ptr(),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        null_data,
    ))?;

    check(libc::syscall(libc::SYS_pivot_root, plan.new_root.as_ptr(), plan.old_root.as_ptr()) as libc::c_int)?;
    check(libc::chdir(c"/".as_ptr()))?;
    check(libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH))?;
    check(libc::rmdir(c"/.oldroot".as_ptr()))?;
    // std ran chdir before this closure, into a directory that is now on a detached mount.
    check(libc::chdir(plan.chdir.as_ptr()))
}

/// A bind, then the remount that sets its flags: a bind mount takes none on the first call.
/// nosuid on every one, because the workload is `nobody` and must stay so.
unsafe fn bind_mount(bind: &Bind) -> io::Result<()> {
    let none: *const libc::c_char = ptr::null();
    let null_data: *const libc::c_void = ptr::null();
    check(libc::mount(bind.source.as_ptr(), bind.target.as_ptr(), none, libc::MS_BIND, null_data))?;
    let mut flags = libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV;
    if bind.read_only {
        flags |= libc::MS_RDONLY;
    }
    check(libc::mount(none, bind.target.as_ptr(), none, flags, null_data))
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with a merged-usr layout, a working directory outside the system dirs, and two
    /// device nodes.
    fn fake_host() -> PathBuf {
        let host = std::env::temp_dir().join(format!("splat_jail_host_{}_{}", std::process::id(), rand_suffix()));
        fs::create_dir_all(host.join("usr/bin")).unwrap();
        fs::create_dir_all(host.join("etc")).unwrap();
        symlink("usr/bin", host.join("bin")).unwrap();
        fs::create_dir_all(host.join("tmp/work")).unwrap();
        fs::create_dir_all(host.join("srv/space")).unwrap();
        fs::create_dir_all(host.join("dev")).unwrap();
        fs::write(host.join("dev/null"), "").unwrap();
        fs::write(host.join("dev/urandom"), "").unwrap();
        host
    }

    fn rand_suffix() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    fn base_for(host: &Path) -> PathBuf {
        host.join("roots")
    }

    #[test]
    fn the_skeleton_mirrors_the_host_and_binds_only_the_system_dirs_and_the_workdir() {
        let host = fake_host();
        let base = base_for(&host);
        let plan = JailPlan::prepare(&base, "m-1", Path::new("/srv/space"), false, &host).expect("prepare");
        let root = base.join("mission_m-1");

        assert!(root.join("usr").is_dir() && root.join("etc").is_dir());
        assert_eq!(fs::read_link(root.join("bin")).unwrap(), Path::new("usr/bin"), "the merged-usr link is mirrored, not bound");
        assert!(root.join("srv/space").is_dir(), "the workdir's mount point is made in the parent");
        assert!(root.join("tmp").is_dir() && root.join("proc").is_dir() && root.join(".oldroot").is_dir());
        assert!(root.join("dev/null").is_file() && root.join("dev/urandom").is_file());
        assert_eq!(fs::read_link(root.join("dev/stdin")).unwrap(), Path::new("/proc/self/fd/0"));
        assert!(!root.join("dev/zero").exists(), "a node the host lacks is not invented");
        for absent in ["home", "mnt", "root", "var", "sys"] {
            assert!(!root.join(absent).exists(), "{absent} must not exist in the jail");
        }

        let binds = plan.binds();
        let targets: Vec<&str> = binds.iter().map(|(_, t, _)| t.as_str()).collect();
        assert_eq!(targets.len(), 3, "{targets:?}");
        assert!(binds[0].2 && binds[1].2, "system dirs are read-only");
        assert!(!binds[2].2, "the workdir is read-write");
        assert!(binds[2].1.ends_with("/mission_m-1/srv/space"));
        assert!(plan.tmp_mkdirs().is_empty());

        drop(plan);
        assert!(!root.exists(), "everything the plan made is gone");
        assert!(base.exists(), "the base is not the plan's to remove");
        let _ = fs::remove_dir_all(&host);
    }

    #[test]
    fn a_workdir_under_tmp_is_made_in_the_child_after_the_fresh_tmpfs() {
        let host = fake_host();
        let plan = JailPlan::prepare(&base_for(&host), "m-2", Path::new("/tmp/work"), true, &host).expect("prepare");

        let mkdirs = plan.tmp_mkdirs();
        assert_eq!(mkdirs.len(), 1);
        assert!(mkdirs[0].ends_with("/mission_m-2/tmp/work"));
        assert!(!base_for(&host).join("mission_m-2/tmp/work").exists(), "not made in the parent - it would be hidden by the tmpfs");
        assert!(plan.tmpfs_tmp.is_some());
        assert!(plan.binds().last().unwrap().2, "readOnlyFs binds the workdir read-only");

        drop(plan);
        let _ = fs::remove_dir_all(&host);
    }

    #[test]
    fn tmp_as_the_workdir_is_the_hosts_tmp_and_no_tmpfs_is_mounted() {
        let host = fake_host();
        let plan = JailPlan::prepare(&base_for(&host), "m-3", Path::new("/tmp"), false, &host).expect("prepare");

        assert!(plan.tmpfs_tmp.is_none());
        let (source, _, read_only) = plan.binds().last().unwrap().clone();
        assert!(source.ends_with("/tmp") && !read_only);

        drop(plan);
        let _ = fs::remove_dir_all(&host);
    }

    #[test]
    fn unsafe_ids_and_paths_are_refused_before_anything_is_made() {
        let host = fake_host();
        let base = base_for(&host);
        assert!(JailPlan::prepare(&base, "../x", Path::new("/tmp"), false, &host).is_err());
        assert!(JailPlan::prepare(&base, "m", Path::new("tmp"), false, &host).is_err());
        assert!(JailPlan::prepare(&base, "m", Path::new("/tmp/../etc"), false, &host).is_err());
        assert!(JailPlan::prepare(&base, "m", Path::new("/nowhere"), false, &host).is_err());
        assert!(!base.exists() || fs::read_dir(&base).unwrap().next().is_none(), "nothing was left behind");
        let _ = fs::remove_dir_all(&host);
    }

    #[test]
    fn cleanup_never_removes_what_it_did_not_create() {
        let host = fake_host();
        let base = base_for(&host);
        let plan = JailPlan::prepare(&base, "m-4", Path::new("/srv/space"), false, &host).expect("prepare");
        let root = base.join("mission_m-4");
        // Something appeared inside a skeleton directory - as a leaked mount's contents would.
        fs::write(root.join("usr/not-mine"), "keep").unwrap();

        drop(plan);

        assert!(root.join("usr/not-mine").exists(), "a non-empty directory is left, contents intact");
        assert!(!root.join("etc").exists(), "everything else still goes");
        let _ = fs::remove_dir_all(&host);
    }

    #[test]
    fn leftover_skeletons_are_reaped_but_a_populated_one_is_left() {
        let host = fake_host();
        let base = base_for(&host);
        {
            let _a = JailPlan::prepare(&base, "gone-1", Path::new("/srv/space"), false, &host).unwrap();
            let _b = JailPlan::prepare(&base, "gone-2", Path::new("/tmp/work"), false, &host).unwrap();
            // Forget both without dropping: what a crashed daemon leaves.
            std::mem::forget(_a);
            std::mem::forget(_b);
        }
        fs::write(base.join("mission_gone-2/usr/left"), "data").unwrap();

        let reaped = reap_leftover_roots(&base).expect("reap");

        assert_eq!(reaped, 1);
        assert!(!base.join("mission_gone-1").exists());
        assert!(base.join("mission_gone-2/usr/left").exists(), "a populated skeleton is not descended into");
        let _ = fs::remove_dir_all(&host);
    }
}
