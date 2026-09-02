// SPLAT kernel canary loader (Layer-2 daemon, minimal single-shot form).
//
// Flow:
//   1. Load + attach the BPF-LSM programs.
//   2. Create/locate a cgroup v2 directory; its kernfs inode number IS the cgroup id that
//      bpf_get_current_cgroup_id() reports in-kernel, so we stat() it to key the lease.
//   3. Seed the lease maps: protect /etc/shadow's inode, allow only 127.0.0.1 egress, allow
//      only the exact executables the canary needs.
//   4. Fork a child, move it into the leased cgroup, exec the canary script.
//   5. Parent drains the ringbuf and prints every -EPERM the kernel handed back.
//
// NOTE: targets the libbpf-rs 0.24 API. This file has NOT been compiled in this environment
// (WSL was not yet installed when it was written); the first real verification is `run-canary.sh`.

use std::ffi::CString;
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBufferBuilder};

mod lease_lsm {
    include!(concat!(env!("OUT_DIR"), "/lease_lsm.skel.rs"));
}
use lease_lsm::*;

#[derive(Parser)]
#[command(about = "Prove BPF-LSM per-cgroup lease enforcement (-EPERM canary).")]
struct Args {
    /// cgroup v2 directory to create and lease.
    #[arg(long, default_value = "/sys/fs/cgroup/splat-canary")]
    cgroup: PathBuf,

    /// File whose inode is protected from open() inside the lease.
    #[arg(long, default_value = "/etc/shadow")]
    protect: PathBuf,

    /// The single approved egress IPv4 (dotted quad). Everything else connect()s to -EPERM.
    #[arg(long, default_value = "127.0.0.1")]
    allow_connect: String,

    /// Comma-separated absolute paths of the ONLY binaries the lease may exec.
    #[arg(long, default_value = "/bin/sh,/bin/dash,/usr/bin/dash,/bin/bash,/usr/bin/bash,/usr/bin/cat,/usr/bin/curl,/bin/cat,/bin/curl")]
    allow_exec: String,

    /// Canary script run inside the lease. If empty, just hold the lease and stream violations.
    #[arg(long, default_value = "./canary.sh")]
    canary: String,
}

// Mirror of `struct inode_key` in the BPF program (repr(C), same field order/padding).
#[repr(C)]
#[derive(Clone, Copy)]
struct InodeKey {
    ino: u64,
    dev: u32,
    _pad: u32,
}

fn inode_key_for(path: &Path) -> Result<InodeKey> {
    let md = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    Ok(InodeKey {
        ino: md.ino(),
        dev: md.dev() as u32,
        _pad: 0,
    })
}

fn bytes_of<T: Copy>(v: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts((v as *const T) as *const u8, std::mem::size_of::<T>()) }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if unsafe { libc::geteuid() } != 0 {
        bail!("must run as root: loading BPF-LSM needs CAP_BPF + CAP_SYS_ADMIN");
    }
    if metafs_type(Path::new("/sys/fs/cgroup"))? != CGROUP2_MAGIC {
        bail!("/sys/fs/cgroup is not cgroup v2 (unified). Enable systemd/cgroup v2 in WSL — see README.");
    }

    // 1. Load + attach.
    let mut open_object = MaybeUninit::uninit();
    let skel_builder = LeaseLsmSkelBuilder::default();
    let open_skel = skel_builder
        .open(&mut open_object)
        .context("open skeleton")?;
    let mut skel = open_skel.load().context(
        "load skeleton — if this fails with -EINVAL the kernel likely lacks `bpf` in its active \
         LSM list; see preflight.sh output and the README's kernel-command-line fallback",
    )?;
    skel.attach().context("attach lsm programs")?;

    // 2. cgroup: create the dir, read its inode == cgroup id.
    let cgroup = &args.cgroup;
    if !cgroup.exists() {
        fs::create_dir(cgroup).with_context(|| format!("create cgroup {}", cgroup.display()))?;
    }
    let cgid: u64 = fs::metadata(cgroup)?.ino();
    println!("[lease] cgroup {} -> id {}", cgroup.display(), cgid);

    // 3. Seed maps.
    let one: u8 = 1;
    skel.maps.leased_cgroups
        .update(&cgid.to_ne_bytes(), &[one], MapFlags::ANY)
        .context("map: leased_cgroups")?;

    let shadow = inode_key_for(&args.protect)?;
    skel.maps.protected_inodes
        .update(bytes_of(&shadow), &[one], MapFlags::ANY)
        .context("map: protected_inodes")?;
    println!("[lease] protecting {} (ino {})", args.protect.display(), shadow.ino);

    let ip = ipv4_to_be_u32(&args.allow_connect)?;
    skel.maps.allowed_connect_ipv4
        .update(&ip.to_ne_bytes(), &[one], MapFlags::ANY)
        .context("map: allowed_connect_ipv4")?;
    println!("[lease] allowing egress only to {}", args.allow_connect);

    for exe in args.allow_exec.split(',').filter(|s| !s.is_empty()) {
        let p = Path::new(exe);
        if let Ok(k) = inode_key_for(p) {
            skel.maps.allowed_exec_inodes
                .update(bytes_of(&k), &[one], MapFlags::ANY)
                .with_context(|| format!("map: allowed_exec_inodes {exe}"))?;
            println!("[lease] allow-exec {} (ino {})", exe, k.ino);
        }
    }

    // 5. Ringbuf drain in the parent.
    let mut rb = RingBufferBuilder::new();
    rb.add(&skel.maps.violations, |data: &[u8]| {
        print_violation(data);
        0
    })
    .context("ringbuf add")?;
    let rb = rb.build().context("ringbuf build")?;

    // 4. Fork the canary into the leased cgroup.
    let child = unsafe { libc::fork() };
    if child < 0 {
        bail!("fork failed");
    }
    if child == 0 {
        // Child: join the cgroup, then exec the canary. Any failure here just exits nonzero.
        let procs = cgroup.join("cgroup.procs");
        let _ = fs::write(&procs, format!("{}", unsafe { libc::getpid() }));
        let sh = CString::new("/bin/sh").unwrap();
        let arg0 = CString::new("sh").unwrap();
        let script = CString::new(args.canary.clone()).unwrap();
        unsafe {
            libc::execv(
                sh.as_ptr(),
                [arg0.as_ptr(), script.as_ptr(), std::ptr::null()].as_ptr(),
            );
            libc::_exit(127);
        }
    }

    // Parent: pump violations until the child exits, then a short grace drain.
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let _ = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst));
    }
    let mut status: i32 = 0;
    loop {
        let _ = rb.poll(Duration::from_millis(100));
        let w = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if w == child || stop.load(Ordering::SeqCst) {
            break;
        }
    }
    for _ in 0..5 {
        let _ = rb.poll(Duration::from_millis(50));
    }

    println!("[lease] canary finished (child status {status:#x}). Lease released on exit.");
    Ok(())
}

fn print_violation(data: &[u8]) {
    // Must match `struct violation_event` in the BPF program.
    if data.len() < 8 + 4 + 4 + 4 + 16 {
        return;
    }
    let cgid = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let pid = u32::from_ne_bytes(data[8..12].try_into().unwrap());
    let hook = u32::from_ne_bytes(data[12..16].try_into().unwrap());
    let detail = u32::from_ne_bytes(data[16..20].try_into().unwrap());
    let comm_end = data[20..36].iter().position(|&b| b == 0).unwrap_or(16) + 20;
    let comm = String::from_utf8_lossy(&data[20..comm_end]);
    let what = match hook {
        1 => format!("exec denied (inode {detail})"),
        2 => format!("open denied (inode {detail})"),
        3 => format!("connect denied (dst {})", be_u32_to_ipv4(detail)),
        _ => "unknown".into(),
    };
    println!("  \x1b[31m-EPERM\x1b[0m  [{comm} pid {pid} cg {cgid}] {what}");
}

const CGROUP2_MAGIC: i64 = 0x63677270;

fn metafs_type(p: &Path) -> Result<i64> {
    let cpath = CString::new(p.as_os_str().to_string_lossy().as_bytes())?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(cpath.as_ptr(), &mut s) } != 0 {
        bail!("statfs {} failed", p.display());
    }
    Ok(s.f_type as i64)
}

fn ipv4_to_be_u32(s: &str) -> Result<u32> {
    let o: Vec<u8> = s.split('.').map(|p| p.parse::<u8>()).collect::<Result<_, _>>()
        .map_err(|_| anyhow::anyhow!("bad IPv4: {s}"))?;
    if o.len() != 4 {
        bail!("bad IPv4: {s}");
    }
    // Match raw in-memory byte layout of sin_addr.s_addr
    Ok(u32::from_ne_bytes([o[0], o[1], o[2], o[3]]))
}

fn be_u32_to_ipv4(val: u32) -> String {
    let b = val.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}
