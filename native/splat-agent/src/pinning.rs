// Pins retain the kernel policy across SIGKILL. The source digest is part of every path: there
// is deliberately no unversioned fallback, and an incomplete set never becomes a fresh policy.
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{libbpf_sys as sys, AsRawLibbpf, Link, MapCore, MapHandle, MapInfo, Program};
use sha2::{Digest, Sha256};

use crate::lease_lsm::{LeaseLsmLinks, LeaseLsmSkel, LeaseLsmSkelBuilder};

pub const PIN_BASE: &str = "/sys/fs/bpf/splat";

pub fn source_hash() -> String {
    format!("{:x}", Sha256::digest(include_bytes!("bpf/lease_lsm.bpf.c")))
}

fn private_directory(path: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("create {}", path.display())),
    }
    let md = fs::symlink_metadata(path)?;
    ensure!(md.is_dir() && md.uid() == 0 && md.mode() & 0o022 == 0,
        "{} must be a root-owned directory without group/other write access", path.display());
    Ok(())
}

pub fn lock_instance() -> Result<File> {
    private_directory(Path::new("/run/splat"))?;
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/run/splat/agent.lock")?;
    let md = file.metadata()?;
    ensure!(md.is_file() && md.uid() == 0 && md.mode() & 0o077 == 0, "untrusted daemon lock");
    // Serializes pin publication AND orphan cleanup; a second daemon must not kill live leases.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("another splat-agent owns the kernel policy: {}", std::io::Error::last_os_error());
    }
    Ok(file)
}

fn select_directory(base: &Path, hash: &str) -> Result<(PathBuf, bool)> {
    let path = base.join(hash);
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        // Old hooks may still police live workloads. Leave them pinned and refuse startup;
        // migration requires an operator to drain those workloads before retiring their pins.
        ensure!(entry.file_name() == hash, "foreign or incomplete BPF pin set: {} (expected {hash})", entry.path().display());
    }
    Ok((path.clone(), path.try_exists()?))
}

pub fn load<'obj>(object: &'obj mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<LeaseLsmSkel<'obj>> {
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(c"/sys/fs/bpf".as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("stat bpffs");
    }
    ensure!(unsafe { stat.assume_init() }.f_type == 0xcafe4a11, "/sys/fs/bpf must be mounted as bpffs");
    let base = Path::new(PIN_BASE);
    private_directory(base)?;
    let hash = source_hash();
    let (path, reuse) = select_directory(base, &hash)?;
    let mut open = LeaseLsmSkelBuilder::default().open(object)?;
    let expected: BTreeSet<_> = open.open_object().maps().map(|m| format!("map_{}", m.name().to_string_lossy()))
        .chain(open.open_object().progs().map(|p| format!("link_{}", p.name().to_string_lossy())))
        .collect();
    if reuse {
        private_directory(&path)?;
        let actual: BTreeSet<_> = fs::read_dir(&path)?
            .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned())).collect::<std::io::Result<_>>()?;
        ensure!(actual == expected, "incomplete BPF pin set at {}", path.display());
        for mut map in open.open_object_mut().maps_mut() {
            let pin = path.join(format!("map_{}", map.name().to_string_lossy()));
            let handle = MapHandle::from_pinned_path(&pin)?;
            let actual = MapInfo::new(handle.as_fd())?.info;
            let raw = map.as_libbpf_object().as_ptr();
            // reuse_fd alone does not establish that the map has the schema this program expects.
            let matches = unsafe {
                actual.type_ == sys::bpf_map__type(raw)
                    && actual.key_size == sys::bpf_map__key_size(raw)
                    && actual.value_size == sys::bpf_map__value_size(raw)
                    && actual.max_entries == sys::bpf_map__max_entries(raw)
                    && actual.map_flags == sys::bpf_map__map_flags(raw)
            };
            ensure!(matches, "incompatible pinned map {}", pin.display());
            map.reuse_fd(handle.as_fd())?;
        }
    }
    let mut skel = open.load()?;
    if reuse {
        // Never attach a second program when recovering pins. Check that each surviving hook
        // actually uses these very map IDs, not just maps with matching names and sizes.
        skel.links = LeaseLsmLinks {
            splat_bprm_check: Some(reopen(&path, &skel.progs.splat_bprm_check)?),
            splat_file_open: Some(reopen(&path, &skel.progs.splat_file_open)?),
            splat_socket_connect: Some(reopen(&path, &skel.progs.splat_socket_connect)?),
            splat_socket_sendmsg: Some(reopen(&path, &skel.progs.splat_socket_sendmsg)?),
        };
    } else {
        let staging = base.join(format!("pending_{hash}"));
        private_directory(&staging)?;
        skel.attach()?;
        for mut map in skel.object_mut().maps_mut() {
            map.pin(staging.join(format!("map_{}", map.name().to_string_lossy())))?;
        }
        for (name, link) in [
            ("splat_bprm_check", &mut skel.links.splat_bprm_check),
            ("splat_file_open", &mut skel.links.splat_file_open),
            ("splat_socket_connect", &mut skel.links.splat_socket_connect),
            ("splat_socket_sendmsg", &mut skel.links.splat_socket_sendmsg),
        ] {
            link.as_mut().context("missing attached LSM link")?.pin(staging.join(format!("link_{name}")))?;
        }
        // A crash during publication leaves pending_HASH, which select_directory refuses.
        fs::rename(&staging, &path).context("publish complete BPF pin set")?;
    }
    tracing::info!("BPF pins {} at {}", if reuse { "reused" } else { "created" }, path.display());

    // Policies stay installed until the last orphan dies. Only then can stale cgroup IDs and
    // allow-list entries be removed without briefly turning survivors into unleased processes.
    crate::cgroup::EphemeralCgroup::reap_orphans(Path::new(crate::cgroup::BASE_PATH))?;
    for map in [
        &skel.maps.leased_cgroups, &skel.maps.protected_inodes, &skel.maps.allowed_exec_inodes,
        &skel.maps.allowed_connect_ipv4, &skel.maps.violation_counts,
    ] {
        let mut key = vec![0u8; map.key_size() as usize];
        loop {
            // The safe iterator ends on any syscall error. Here only ENOENT proves emptiness;
            // silently stopping would leave old allow entries for a later recycled cgroup ID.
            if unsafe { sys::bpf_map_get_next_key(map.as_fd().as_raw_fd(), std::ptr::null(), key.as_mut_ptr().cast()) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOENT) {
                    break;
                }
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("enumerate drained lease policy");
            }
            map.delete(&key).context("clear drained lease policy")?;
        }
    }
    Ok(skel)
}

fn prog_info(fd: BorrowedFd<'_>) -> Result<(sys::bpf_prog_info, Vec<u32>)> {
    let mut info = sys::bpf_prog_info::default();
    let mut size = std::mem::size_of_val(&info) as u32;
    if unsafe { sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), (&mut info as *mut sys::bpf_prog_info).cast(), &mut size) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read pinned program info");
    }
    let mut maps = vec![0u32; info.nr_map_ids as usize];
    // The first query also reports bytecode/BTF lengths. Leave their pointers AND lengths zero
    // when requesting only map IDs; reusing those lengths with null buffers can fail with EFAULT.
    info = sys::bpf_prog_info { nr_map_ids: maps.len() as u32, ..Default::default() };
    info.map_ids = maps.as_mut_ptr() as u64;
    if unsafe { sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), (&mut info as *mut sys::bpf_prog_info).cast(), &mut size) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read pinned program map IDs");
    }
    maps.sort_unstable();
    Ok((info, maps))
}

fn reopen(path: &Path, expected: &Program<'_>) -> Result<Link> {
    let pin = path.join(format!("link_{}", expected.name().to_string_lossy()));
    let link = Link::open(&pin)?;
    let mut info = sys::bpf_link_info::default();
    let mut size = std::mem::size_of_val(&info) as u32;
    if unsafe { sys::bpf_obj_get_info_by_fd(link.as_fd().as_raw_fd(), (&mut info as *mut sys::bpf_link_info).cast(), &mut size) } != 0 {
        return Err(std::io::Error::last_os_error()).context("read pinned link info");
    }
    ensure!(info.type_ == sys::BPF_LINK_TYPE_TRACING && info.prog_id != 0, "inactive or non-LSM link {}", pin.display());
    let fd = Program::fd_from_id(info.prog_id)?;
    let (actual, maps) = prog_info(fd.as_fd())?;
    let (wanted, wanted_maps) = prog_info(expected.as_fd())?;
    ensure!(actual.type_ == sys::BPF_PROG_TYPE_LSM && actual.tag == wanted.tag
        && actual.attach_btf_id == wanted.attach_btf_id && actual.attach_btf_obj_id == wanted.attach_btf_obj_id
        && maps == wanted_maps,
        "pinned hook does not match this program and its maps: {}", pin.display());
    Ok(link)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foreign_and_partial_sets_never_fall_back_to_fresh_maps() {
        let base = std::env::temp_dir().join(format!("splat_pins_{}", std::process::id()));
        fs::create_dir(&base).unwrap();
        let hash = source_hash();
        assert_eq!(hash.len(), 64);
        assert!(!select_directory(&base, &hash).unwrap().1);
        let foreign = base.join("0".repeat(64));
        fs::create_dir(&foreign).unwrap();
        assert!(select_directory(&base, &hash).is_err());
        fs::remove_dir(&foreign).unwrap();
        let pending = base.join(format!("pending_{hash}"));
        fs::create_dir(&pending).unwrap();
        assert!(select_directory(&base, &hash).is_err());
        fs::rename(pending, base.join(&hash)).unwrap();
        assert!(select_directory(&base, &hash).unwrap().1);
        fs::remove_dir_all(base).unwrap();
    }
}
