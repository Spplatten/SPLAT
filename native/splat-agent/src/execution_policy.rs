//! Opt-in, additive restrictions. A reviewed contract is compiled before fork; only raw syscalls
//! run after fork. Fixed BPF-LSM exec/egress checks remain in force. This generates seccomp cBPF,
//! not Rust source or a replacement LSM, and never infers authority from a tool's description.

use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, ffi::CString, io};

const READ_FILE: u64 = 1 << 2;
const WRITE_FILE: u64 = 1 << 1;
const EXECUTE: u64 = 1;
const READ_DIR: u64 = 1 << 3;
const TRUNCATE: u64 = 1 << 14;
// ABI 5 includes truncate and device ioctl. Never drop required rights on an older kernel.
const HANDLED_FS: u64 = (1 << 16) - 1;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Policy {
    schema_version: u32,
    architecture: String,
    syscalls: Vec<String>,
    file_grants: Vec<FileGrant>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FileGrant {
    path: String,
    access: Vec<String>,
    #[serde(default = "file_scope")]
    scope: String,
}

fn file_scope() -> String { "file".into() }

pub struct PreparedPolicy {
    paths: Vec<(CString, u64, bool)>,
    filter: Vec<libc::sock_filter>,
    pub sha256: String,
    pub landlock_abi: i32,
}

pub fn from_request(request: &serde_json::Value, enforcing: bool) -> Result<Option<PreparedPolicy>> {
    let value = request.get("executionPolicy").filter(|v| !v.is_null());
    let explicit = request.get("type").and_then(|v| v.as_str()) == Some("EXECUTE_POLICY");
    let agent = matches!(request.get("type").and_then(|v| v.as_str()), Some("EXECUTE_AGENT" | "EXECUTE_BOUND"));
    ensure!(!agent || enforcing, "agent execution requires an enforcing daemon; no development fallback");
    ensure!(agent || explicit == value.is_some(), "executionPolicy requires EXECUTE_POLICY and a non-null contract");
    let Some(value) = value else { return Ok(None); };
    ensure!(enforcing, "executionPolicy requires an enforcing daemon; no development fallback");
    let policy: Policy = serde_json::from_value(value.clone())?;
    Ok(Some(policy.compile(request.get("allowNetwork").and_then(|v| v.as_bool()).unwrap_or(false))?))
}

impl Policy {
    fn compile(&self, allow_network: bool) -> Result<PreparedPolicy> {
        ensure!(cfg!(target_arch = "x86_64") && self.architecture == "x86_64" && self.schema_version == 1,
            "executionPolicy supports schemaVersion 1 on x86_64 only");
        ensure!(!self.syscalls.is_empty() && self.syscalls.len() <= 128, "declare 1..128 syscalls");
        ensure!(self.file_grants.len() <= 64, "at most 64 file grants");
        let mut numbers = BTreeSet::new();
        for name in &self.syscalls {
            let number = syscall_number(name).ok_or_else(|| anyhow::anyhow!("unsupported syscall: {name}"))?;
            ensure!(numbers.insert(number), "duplicate syscall: {name}");
            ensure!(allow_network || !matches!(name.as_str(), "socket" | "connect" | "bind" | "listen"
                | "accept" | "accept4" | "sendto" | "recvfrom" | "sendmsg" | "recvmsg"),
                "network syscall {name} conflicts with allowNetwork=false");
        }
        // The child must be able to report exec failure and exit; these are explicit contract
        // entries, not a hidden baseline that widens a measured list behind the reviewer's back.
        for essential in ["execve", "exit_group", "write", "close"] {
            ensure!(self.syscalls.iter().any(|s| s == essential), "missing launch syscall: {essential}");
        }
        let mut paths = Vec::new();
        let mut seen = BTreeSet::new();
        for grant in &self.file_grants {
            ensure!(grant.path.starts_with('/') && grant.path.len() <= 4096
                && grant.path[1..].split('/').all(|p| !matches!(p, "" | "." | ".."))
                && seen.insert(&grant.path), "file grants require unique normalized absolute paths");
            let tree = match grant.scope.as_str() { "file" => false, "tree" => true, _ => bail!("unknown file grant scope") };
            ensure!(!grant.access.is_empty() && grant.access.len() <= 3, "invalid file access list");
            let mut rights = 0;
            let mut access_seen = BTreeSet::new();
            for access in &grant.access {
                ensure!(access_seen.insert(access), "duplicate file access");
                rights |= match access.as_str() {
                    "read" => READ_FILE | if tree { READ_DIR } else { 0 },
                    "write" if !tree => WRITE_FILE | TRUNCATE,
                    "execute" => EXECUTE,
                    _ => bail!("unknown access or writable tree; writes require an existing regular file"),
                };
            }
            paths.push((CString::new(grant.path.as_bytes())?, rights, tree));
        }
        let abi = unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u8>(), 0usize, 1u32) };
        ensure!(abi >= 5, "Landlock ABI 5 or later is required (observed {abi}); no weaker fallback");
        Ok(PreparedPolicy {
            paths, filter: compile_filter(&numbers), landlock_abi: abi as i32,
            sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)),
        })
    }
}

impl PreparedPolicy {
    /// Only in a fresh fork child, after entering the jail and dropping uid/gid. Resolve in that
    /// mount namespace: the parent's /tmp and /proc are different objects. Each O_PATH descriptor
    /// pins its object while the rule is added; no symlink or magic-link alias is accepted.
    pub unsafe fn apply(&self) -> io::Result<()> {
        let handled = HANDLED_FS;
        let ruleset = libc::syscall(libc::SYS_landlock_create_ruleset, &handled, 8usize, 0u32) as i32;
        if ruleset < 0 { return Err(io::Error::last_os_error()); }
        let result = self.add_rules(ruleset);
        if let Err(error) = result { libc::close(ruleset); return Err(error); }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            let error = io::Error::last_os_error(); libc::close(ruleset); return Err(error);
        }
        let restricted = libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32);
        let error = io::Error::last_os_error();
        libc::close(ruleset);
        if restricted != 0 { return Err(error); }
        let program = libc::sock_fprog { len: self.filter.len() as u16, filter: self.filter.as_ptr() as *mut _ };
        if libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    unsafe fn add_rules(&self, ruleset: i32) -> io::Result<()> {
        #[repr(C)]
        struct OpenHow { flags: u64, mode: u64, resolve: u64 }
        #[repr(C, packed)]
        struct PathBeneath { allowed_access: u64, parent_fd: i32 }
        for (path, rights, tree) in &self.paths {
            let how = OpenHow { flags: (libc::O_PATH | libc::O_CLOEXEC) as u64, mode: 0, resolve: 0x02 | 0x04 };
            let fd = libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, path.as_ptr(), &how, std::mem::size_of_val(&how)) as i32;
            if fd < 0 { return Err(io::Error::last_os_error()); }
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if libc::fstat(fd, stat.as_mut_ptr()) != 0 {
                let error = io::Error::last_os_error(); libc::close(fd); return Err(error);
            }
            let kind = stat.assume_init().st_mode & libc::S_IFMT;
            if kind != if *tree { libc::S_IFDIR } else { libc::S_IFREG } {
                libc::close(fd); return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
            let attr = PathBeneath { allowed_access: *rights, parent_fd: fd };
            let added = libc::syscall(libc::SYS_landlock_add_rule, ruleset, 1u32, &attr, 0u32);
            let error = io::Error::last_os_error();
            libc::close(fd);
            if added != 0 { return Err(error); }
        }
        Ok(())
    }
}

fn compile_filter(numbers: &BTreeSet<u32>) -> Vec<libc::sock_filter> {
    let load = |k| libc::sock_filter { code: 0x20, jt: 0, jf: 0, k };
    let equal = |k, jt, jf| libc::sock_filter { code: 0x15, jt, jf, k };
    let ret = |k| libc::sock_filter { code: 0x06, jt: 0, jf: 0, k };
    let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut filter = vec![load(4), equal(0xc000003e, 1, 0), ret(libc::SECCOMP_RET_KILL_PROCESS), load(0)];
    // Even a networked contract gets no AF_UNIX/NETLINK transfer channel. BPF-LSM still decides
    // which IPv4 destinations may be reached. io_uring, ptrace, bpf, mount and handle-open calls
    // are absent from the supported set, not opportunities to bypass file/socket mediation.
    filter.extend([equal(41, 0, 4), load(16), equal(libc::AF_INET as u32, 1, 0), ret(deny), load(0)]);
    for number in numbers { filter.extend([equal(*number, 0, 1), ret(libc::SECCOMP_RET_ALLOW)]); }
    // Unknown numbers, including x32's alternate ABI, have no matching allow entry.
    filter.push(ret(deny));
    filter
}

// Versioned x86_64 vocabulary. A trace outside this set is a review failure, never auto-authority.
// Numbers are the Linux x86_64 UAPI; architecture is checked before the syscall number is read.
fn syscall_number(name: &str) -> Option<u32> {
    Some(match name {
        "read" => 0, "write" => 1, "open" => 2, "close" => 3, "stat" => 4, "fstat" => 5,
        "lstat" => 6, "poll" => 7, "lseek" => 8, "mmap" => 9, "mprotect" => 10, "munmap" => 11,
        "brk" => 12, "rt_sigaction" => 13, "rt_sigprocmask" => 14, "rt_sigreturn" => 15,
        "ioctl" => 16, "pread64" => 17, "pwrite64" => 18, "readv" => 19, "writev" => 20,
        "access" => 21, "pipe" => 22, "select" => 23, "sched_yield" => 24, "mremap" => 25,
        "msync" => 26, "mincore" => 27, "madvise" => 28, "dup" => 32, "dup2" => 33,
        "nanosleep" => 35, "getpid" => 39, "sendfile" => 40, "socket" => 41, "connect" => 42,
        "accept" => 43, "sendto" => 44, "recvfrom" => 45, "sendmsg" => 46, "recvmsg" => 47,
        "shutdown" => 48, "bind" => 49, "listen" => 50, "getsockname" => 51, "getpeername" => 52,
        "setsockopt" => 54, "getsockopt" => 55, "clone" => 56, "fork" => 57, "vfork" => 58,
        "execve" => 59, "exit" => 60, "wait4" => 61, "uname" => 63, "fcntl" => 72,
        "flock" => 73, "fsync" => 74, "fdatasync" => 75, "truncate" => 76, "ftruncate" => 77,
        "getdents" => 78, "getcwd" => 79, "chdir" => 80, "fchdir" => 81, "readlink" => 89,
        "gettimeofday" => 96, "getrlimit" => 97, "getrusage" => 98, "sysinfo" => 99,
        "times" => 100, "getuid" => 102, "getgid" => 104, "geteuid" => 107, "getegid" => 108,
        "getppid" => 110, "getpgrp" => 111, "getgroups" => 115, "getresuid" => 118,
        "getresgid" => 120, "getpgid" => 121, "getsid" => 124, "sigaltstack" => 131,
        "statfs" => 137, "fstatfs" => 138, "arch_prctl" => 158, "gettid" => 186,
        "futex" => 202, "sched_getaffinity" => 204, "getdents64" => 217, "set_tid_address" => 218, "fadvise64" => 221,
        "clock_gettime" => 228, "clock_getres" => 229, "clock_nanosleep" => 230,
        "exit_group" => 231, "epoll_wait" => 232, "epoll_ctl" => 233, "openat" => 257,
        "newfstatat" => 262, "readlinkat" => 267, "faccessat" => 269, "pselect6" => 270,
        "ppoll" => 271, "set_robust_list" => 273, "splice" => 275, "epoll_pwait" => 281, "accept4" => 288,
        "eventfd2" => 290, "epoll_create1" => 291, "dup3" => 292, "pipe2" => 293,
        "preadv" => 295, "pwritev" => 296, "prlimit64" => 302, "getrandom" => 318,
        "execveat" => 322, "copy_file_range" => 326, "statx" => 332, "rseq" => 334,
        "clone3" => 435, "close_range" => 436, "openat2" => 437, "faccessat2" => 439,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::{fs::symlink, process::CommandExt}, path::PathBuf, process::Command};

    fn policy() -> Policy {
        serde_json::from_value(serde_json::json!({"schemaVersion":1,"architecture":"x86_64",
            "syscalls":["read","write","close","execve","exit_group"],"fileGrants":[]})).unwrap()
    }

    #[test]
    fn contract_cannot_be_smuggled_through_legacy_or_non_enforcing_requests() {
        for request in [
            serde_json::json!({"type":"EXECUTE_TOOL","executionPolicy":policy()}),
            serde_json::json!({"type":"EXECUTE_POLICY"}),
            serde_json::json!({"type":"EXECUTE_POLICY","executionPolicy":null}),
        ] { assert!(from_request(&request, true).is_err()); }
        assert!(from_request(&serde_json::json!({"type":"EXECUTE_POLICY","executionPolicy":policy()}), false).is_err());
        assert!(from_request(&serde_json::json!({"type":"EXECUTE_TOOL"}), true).unwrap().is_none());
        assert!(from_request(&serde_json::json!({"type":"EXECUTE_AGENT"}), false).is_err());
        assert!(from_request(&serde_json::json!({"type":"EXECUTE_AGENT","executionPolicy":policy()}), false).is_err());
        assert!(from_request(&serde_json::json!({"type":"EXECUTE_AGENT"}), true).unwrap().is_none());
        assert!(serde_json::from_value::<Policy>(serde_json::json!({"schemaVersion":1,
            "architecture":"x86_64","syscalls":[],"fileGrants":[],"magicInference":true})).is_err());
    }

    #[test]
    fn broad_or_ambiguous_contracts_are_refused_before_kernel_setup() {
        for name in ["ptrace", "io_uring_setup", "bpf", "mount", "open_by_handle_at", "seccomp", "socketpair", "999"] {
            let mut p = policy(); p.syscalls.push(name.into()); assert!(p.compile(false).is_err());
        }
        let mut network = policy(); network.syscalls.push("socket".into());
        assert!(network.compile(false).is_err());
        let mut repeated = policy(); repeated.syscalls.push("read".into());
        assert!(repeated.compile(false).is_err());
        for path in ["/", "/tmp/../etc/passwd", "/tmp//x", "/tmp/./x", "relative", "/tmp/x\0y"] {
            let mut p = policy(); p.file_grants.push(FileGrant { path:path.into(), access:vec!["read".into()], scope:file_scope() });
            assert!(p.compile(false).is_err());
        }
        let mut p = policy(); p.file_grants.push(FileGrant { path:"/tmp".into(), access:vec!["write".into()], scope:"tree".into() });
        assert!(p.compile(false).is_err());
    }

    #[test]
    fn generated_filter_refuses_alternate_abis_unknown_calls_and_local_sockets() {
        fn evaluate(filter: &[libc::sock_filter], arch: u32, number: u32, domain: u32) -> u32 {
            let (mut at, mut value) = (0, 0);
            loop {
                let instruction = filter[at];
                match instruction.code {
                    0x20 => value = match instruction.k { 0 => number, 4 => arch, 16 => domain, _ => panic!("offset") },
                    0x15 => at += if value == instruction.k { instruction.jt } else { instruction.jf } as usize,
                    0x06 => return instruction.k,
                    _ => panic!("opcode"),
                }
                at += 1;
            }
        }
        let filter = compile_filter(&BTreeSet::from([0, 1, 41, 59]));
        let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        assert_eq!(evaluate(&filter, 0xc000003e, 0, 0), libc::SECCOMP_RET_ALLOW);
        assert_eq!(evaluate(&filter, 0xc000003e, 41, libc::AF_INET as u32), libc::SECCOMP_RET_ALLOW);
        for domain in [libc::AF_UNIX, libc::AF_NETLINK, libc::AF_INET6] {
            assert_eq!(evaluate(&filter, 0xc000003e, 41, domain as u32), denied);
        }
        for number in [0x40000000, 425, 101, 321, 999] { assert_eq!(evaluate(&filter, 0xc000003e, number, 0), denied); }
        assert_eq!(evaluate(&filter, 0x40000003, 1, 0), libc::SECCOMP_RET_KILL_PROCESS);
    }

    struct Fixture { root: PathBuf, policy: Policy }
    impl Fixture {
        fn new() -> Self {
            let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let root = std::env::temp_dir().join(format!("splat-policy-{}-{unique}", std::process::id()));
            fs::create_dir(&root).unwrap();
            for name in ["readable", "writable", "sibling"] { fs::write(root.join(name), name).unwrap(); }
            let mut p = policy();
            p.syscalls = "read write close execve exit_group exit openat newfstatat fstat stat lstat access lseek pread64 mmap mprotect munmap brk rt_sigaction rt_sigprocmask rt_sigreturn ioctl readlink getcwd getdents64 getrandom getuid geteuid getgid getegid gettid getpid getppid getpgrp futex set_tid_address set_robust_list rseq arch_prctl prlimit64 fcntl getrlimit sysinfo clock_gettime sigaltstack clone wait4 madvise".split_whitespace().map(str::to_owned).collect();
            for (path, access, scope) in [
                (fs::canonicalize("/usr/bin/python3").unwrap(), vec!["read", "execute"], "file"),
                (PathBuf::from("/usr/lib"), vec!["read", "execute"], "tree"),
                (PathBuf::from("/etc/ld.so.cache"), vec!["read"], "file"),
                (root.join("readable"), vec!["read"], "file"),
                (root.join("writable"), vec!["write"], "file"),
            ] { p.file_grants.push(FileGrant { path:path.to_str().unwrap().into(), access:access.into_iter().map(str::to_owned).collect(), scope:scope.into() }); }
            Self { root, policy:p }
        }

        fn command(&self) -> Command {
            let mut command = Command::new("/usr/bin/python3");
            command.env_clear().env("LANG", "C");
            command.args(["-I", "-S", "-c", r#"
import ctypes, errno, os, socket, sys
root=sys.argv[1]
if 'SPLAT_EXPECT_UID' in os.environ:
    assert os.getuid() == int(os.environ['SPLAT_EXPECT_UID'])
    assert not os.path.exists('/mnt/c')
def denied(action, errors=(errno.EACCES, errno.EPERM)):
    try: action()
    except OSError as error: assert error.errno in errors, error
    else: raise AssertionError('undeclared access succeeded')
assert open(root+'/readable').read() == 'readable'
denied(lambda: open(root+'/readable','w'))
assert open(root+'/readable').read() == 'readable'
denied(lambda: open(root+'/sibling'))
denied(lambda: open(root+'/writable'))
with open(root+'/writable','w') as log: log.write('written')
denied(lambda: open(root+'/new-file','w'))
denied(lambda: os.unlink(root+'/readable'))
denied(lambda: os.execve('/usr/bin/true',['true'],{}))
denied(socket.socket, (errno.EPERM,))
libc=ctypes.CDLL(None,use_errno=True)
for number in (101,321,425,0x40000027):
    assert libc.syscall(number,0,0,0,0,0,0) == -1
    assert ctypes.get_errno() == errno.EPERM
pid=os.fork()
if pid == 0:
    denied(lambda: open(root+'/sibling'))
    denied(socket.socket, (errno.EPERM,))
    os._exit(0)
assert os.waitpid(pid,0)[1] == 0
print('file-read write-only no-network unknown-syscall exec-denial inherited-policy: PASS')
"#]).arg(&self.root);
            command
        }
    }
    impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

    #[test]
    #[ignore = "live unprivileged kernel component proof; needs Linux Landlock ABI >= 5 and Python"]
    fn kernel_file_and_syscall_contract_is_enforced_and_inherited() {
        let fixture = Fixture::new();
        let policy = fixture.policy.compile(false).unwrap();
        let mut command = fixture.command();
        unsafe { command.pre_exec(move || policy.apply()); }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(fs::read_to_string(fixture.root.join("writable")).unwrap(), "written");
        assert_eq!(fs::read_to_string(fixture.root.join("sibling")).unwrap(), "sibling");
        assert!(!fixture.root.join("new-file").exists());
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    #[test]
    #[ignore = "live kernel component proof; rejected grants must prevent exec"]
    fn kernel_missing_symlink_and_wrong_kind_grants_prevent_execution() {
        let fixture = Fixture::new();
        symlink(fixture.root.join("readable"), fixture.root.join("alias")).unwrap();
        for path in [fixture.root.join("missing"), fixture.root.join("alias"), fixture.root.clone()] {
            let mut p = fixture.policy.clone();
            p.file_grants.push(FileGrant { path:path.to_str().unwrap().into(), access:vec!["read".into()], scope:file_scope() });
            let policy = p.compile(false).unwrap();
            let mut command = fixture.command();
            unsafe { command.pre_exec(move || policy.apply()); }
            assert!(command.output().is_err());
            assert_eq!(fs::read_to_string(fixture.root.join("writable")).unwrap(), "writable");
        }
    }

    #[test]
    #[ignore = "root component proof; private child mount namespace, no installed daemon or BPF changes"]
    fn root_jail_privilege_drop_and_generated_policy_compose() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        use std::os::unix::fs::PermissionsExt;
        let fixture = Fixture::new();
        fs::set_permissions(fixture.root.join("writable"), fs::Permissions::from_mode(0o666)).unwrap();
        let base = fixture.root.join("roots");
        let plan = std::sync::Arc::new(crate::jail::JailPlan::prepare(&base, "policy-proof", &fixture.root, false, false, std::path::Path::new("/")).unwrap());
        let keep_plan = plan.clone();
        let policy = fixture.policy.compile(false).unwrap();
        let mut command = fixture.command();
        command.env("SPLAT_EXPECT_UID", "65534");
        unsafe { command.pre_exec(move || { crate::jail::enter(&plan)?; crate::drop_privileges(65534,65534)?; policy.apply() }); }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        drop(command); drop(keep_plan);
        assert_eq!(fs::read_to_string(fixture.root.join("writable")).unwrap(), "written");
        println!("jail + unprivileged uid + generated file/syscall policy: PASS");
    }

    #[test]
    #[ignore = "live kernel proof for the example manifest's guest-specific runtime files"]
    fn kernel_catalog_manifest_reads_only_the_declared_inputs() {
        let manifest: serde_json::Value = serde_json::from_str(include_str!("../../../examples/agent-manifests/guest-identity.contract.json")).unwrap();
        let policy: Policy = serde_json::from_value(manifest["tools"][0]["executionPolicy"].clone()).unwrap();
        for (paths, allowed) in [
            (vec!["/etc/os-release", "/proc/version", "/proc/uptime", "/proc/loadavg", "/proc/meminfo"], true),
            (vec!["/etc/passwd"], false),
        ] {
            let compiled = policy.compile(false).unwrap();
            let mut command = Command::new("/bin/cat");
            command.env_clear().env("LANG", "C.UTF-8").args(paths);
            unsafe { command.pre_exec(move || compiled.apply()); }
            let output = command.output().unwrap();
            assert_eq!(output.status.success(), allowed, "{}", String::from_utf8_lossy(&output.stderr));
            if allowed { assert!(String::from_utf8_lossy(&output.stdout).contains("MemTotal:")); }
            else { assert!(output.stdout.is_empty()); }
        }
    }
}
