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

use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

    /// SHA-256 of the BPF source that produced this run, recorded in the evidence file so proof
    /// of an older program is never mistaken for proof of the current one. run-canary.sh supplies it.
    #[arg(long, default_value = "unknown")]
    bpf_sha: String,

    /// Where to write the machine-checkable evidence file.
    #[arg(long, default_value = "evidence")]
    evidence_dir: PathBuf,
}

#[derive(Clone)]
struct Violation {
    pid: u32,
    hook: u32,
    detail: u32,
    comm: String,
}

fn hook_name(h: u32) -> &'static str {
    match h {
        1 => "exec",
        2 => "open",
        3 => "connect",
        _ => "unknown",
    }
}

/// Userspace `st_dev` and the kernel's `inode->i_sb->s_dev` encode the same device differently.
/// glibc packs major/minor for a 64-bit `dev_t`; the kernel packs `(major << 20) | minor` into 32
/// bits. Feeding `st_dev` straight into the key made EVERY (dev, ino) lookup miss: exec fell
/// closed (every binary denied, including allow-listed ones) and - the dangerous half - protected
/// inodes fell OPEN, because a missed lookup there means "not protected".
fn kernel_dev_from_st_dev(st_dev: u64) -> u32 {
    let major = ((st_dev >> 8) & 0xfff) | ((st_dev >> 32) & !0xfffu64);
    let minor = (st_dev & 0xff) | ((st_dev >> 12) & !0xffu64);
    (((major << 20) | (minor & 0xf_ffff)) & 0xffff_ffff) as u32
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn read_trimmed(path: &str) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unavailable".to_string())
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
        dev: kernel_dev_from_st_dev(md.dev()),
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

    // Kept so the run can detect the kernel denying something the lease explicitly permitted -
    // the exact shape of the (dev, ino) key bug this harness failed to catch on 2026-09-02.
    let mut allowed_exec_inos: HashSet<u64> = HashSet::new();
    for exe in args.allow_exec.split(',').filter(|s| !s.is_empty()) {
        let p = Path::new(exe);
        if let Ok(k) = inode_key_for(p) {
            skel.maps.allowed_exec_inodes
                .update(bytes_of(&k), &[one], MapFlags::ANY)
                .with_context(|| format!("map: allowed_exec_inodes {exe}"))?;
            allowed_exec_inos.insert(k.ino);
            println!("[lease] allow-exec {} (ino {})", exe, k.ino);
        }
    }

    // 5. Ringbuf drain in the parent. Violations are recorded, not merely printed, because the
    // verdict below is computed from them rather than read off the screen by a person.
    let collected: Arc<Mutex<Vec<Violation>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = collected.clone();
    let mut rb = RingBufferBuilder::new();
    rb.add(&skel.maps.violations, move |data: &[u8]| {
        if let Some(v) = parse_violation(data) {
            println!("  \x1b[31m-EPERM\x1b[0m  [{} pid {}] {}", v.comm, v.pid, describe(&v));
            if let Ok(mut g) = sink.lock() {
                g.push(v);
            }
        }
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

    // ---- Verdict. A proof harness that cannot fail proves nothing, so this one asserts. ----
    let violations = collected.lock().unwrap().clone();
    let child_exit = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };

    let mut hooks_seen: HashSet<u32> = HashSet::new();
    let mut denied_permitted: Vec<u32> = Vec::new();
    for v in &violations {
        hooks_seen.insert(v.hook);
        // A denial against an inode the lease allow-listed means the key the kernel builds and the
        // one userspace seeded disagree. Exec then fails closed and is visible; protected-inode
        // lookups fail OPEN and are not - so this check is the tripwire for both halves.
        if v.hook == 1 && allowed_exec_inos.contains(&(v.detail as u64)) {
            denied_permitted.push(v.detail);
        }
    }

    let mut failures: Vec<String> = Vec::new();
    if !denied_permitted.is_empty() {
        failures.push(format!(
            "kernel denied exec of inode(s) {denied_permitted:?} that the lease EXPLICITLY ALLOWED - \
             the (dev, ino) key built in-kernel does not match the one seeded from userspace"
        ));
    }
    if child_exit != 0 {
        failures.push(format!(
            "canary script exited {child_exit}, expected 0 - it did not run to completion, so the \
             permitted action was never demonstrated"
        ));
    }
    for h in [1u32, 2, 3] {
        if !hooks_seen.contains(&h) {
            failures.push(format!("no -EPERM observed from the {} hook", hook_name(h)));
        }
    }

    let verdict = if failures.is_empty() { "PASS" } else { "FAIL" };
    write_evidence(&args, &violations, child_exit, cgid, verdict, &failures)?;

    println!();
    if failures.is_empty() {
        println!("VERDICT: PASS - one permitted action completed and all three hooks returned -EPERM.");
        Ok(())
    } else {
        println!("VERDICT: FAIL");
        for f in &failures {
            println!("  - {f}");
        }
        std::process::exit(1);
    }
}

/// Writes the run's outcome as a committable artifact. The BPF source hash is recorded so proof of
/// an older program can never be mistaken for proof of the current one.
fn write_evidence(
    args: &Args,
    violations: &[Violation],
    child_exit: i32,
    cgid: u64,
    verdict: &str,
    failures: &[String],
) -> Result<()> {
    fs::create_dir_all(&args.evidence_dir)
        .with_context(|| format!("create {}", args.evidence_dir.display()))?;

    let kernel = read_trimmed("/proc/sys/kernel/osrelease");
    let path = args
        .evidence_dir
        .join(format!("canary-{}.json", kernel.replace('/', "_")));

    let violations_json = violations
        .iter()
        .map(|v| {
            format!(
                "    {{ \"hook\": \"{}\", \"pid\": {}, \"detail\": {}, \"comm\": \"{}\", \"described\": \"{}\" }}",
                hook_name(v.hook),
                v.pid,
                v.detail,
                json_escape(&v.comm),
                json_escape(&describe(v))
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");

    let failures_json = failures
        .iter()
        .map(|f| format!("    \"{}\"", json_escape(f)))
        .collect::<Vec<_>>()
        .join(",\n");

    let body = format!(
        "{{\n  \"schema\": 1,\n  \"verdict\": \"{verdict}\",\n  \"recorded_utc\": \"{}\",\n  \
         \"kernel_release\": \"{}\",\n  \"active_lsms\": \"{}\",\n  \"btf_present\": {},\n  \
         \"cgroup_id\": {cgid},\n  \"bpf_source_sha256\": \"{}\",\n  \"canary_exit_code\": {child_exit},\n  \
         \"violations\": [\n{}\n  ],\n  \"failures\": [\n{}\n  ]\n}}\n",
        utc_now(),
        json_escape(&kernel),
        json_escape(&read_trimmed("/sys/kernel/security/lsm")),
        Path::new("/sys/kernel/btf/vmlinux").exists(),
        json_escape(&args.bpf_sha),
        violations_json,
        failures_json
    );

    fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
    println!("[evidence] wrote {}", path.display());
    Ok(())
}

/// Seconds-resolution UTC, rather than pulling in a date crate for one timestamp.
fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tod = secs % 86_400;
    let mut days = (secs / 86_400) as i64;
    let mut year = 1970i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let months = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    while month < 12 && days >= months[month] {
        days -= months[month];
        month += 1;
    }
    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        days + 1,
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

fn describe(v: &Violation) -> String {
    match v.hook {
        1 => format!("exec denied (inode {})", v.detail),
        2 => format!("open denied (inode {})", v.detail),
        3 => format!("connect denied (dst {})", be_u32_to_ipv4(v.detail)),
        _ => "unknown".into(),
    }
}

fn parse_violation(data: &[u8]) -> Option<Violation> {
    // Must match `struct violation_event` in the BPF program.
    if data.len() < 8 + 4 + 4 + 4 + 16 {
        return None;
    }
    let pid = u32::from_ne_bytes(data[8..12].try_into().ok()?);
    let hook = u32::from_ne_bytes(data[12..16].try_into().ok()?);
    let detail = u32::from_ne_bytes(data[16..20].try_into().ok()?);
    let comm_end = data[20..36].iter().position(|&b| b == 0).unwrap_or(16) + 20;
    let comm = String::from_utf8_lossy(&data[20..comm_end]).to_string();
    Some(Violation { pid, hook, detail, comm })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned to values measured on the live guest (2026-09-02): /bin/sh and /etc/shadow both sit
    /// on st_dev 2096, which the kernel reports as s_dev 8388656. Passing st_dev through unconverted
    /// is what made every (dev, ino) lookup miss, so this is the regression guard for that bug.
    #[test]
    fn st_dev_converts_to_the_kernel_encoding() {
        assert_eq!(kernel_dev_from_st_dev(2096), 8_388_656);
    }

    #[test]
    fn encoding_round_trips_major_minor() {
        // st_dev 2096 == major 8, minor 48; kernel packs that as (8 << 20) | 48.
        assert_eq!(kernel_dev_from_st_dev(2096), (8u32 << 20) | 48);
        // A minor above 255 exercises the high bits glibc stores separately.
        let st_dev = (8u64 << 8) | (0x1_00u64 << 12) | 0x22;
        assert_eq!(kernel_dev_from_st_dev(st_dev), (8u32 << 20) | 0x122);
    }
}
