//! Inputs inherited from the service are authority too; only the step's declared inputs survive.

use anyhow::{bail, Result};
use serde_json::Value;
use std::collections::BTreeMap;

pub fn environment(request: &Value) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::from([
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("HOME".into(), "/tmp".into()),
        ("TMPDIR".into(), "/tmp".into()),
    ]);
    if let Some(value) = request.get("environment") {
        let fields = value.as_object().ok_or_else(|| anyhow::anyhow!("environment must be an object"))?;
        if fields.len() > 16 { bail!("environment exceeds 16 entries"); }
        for (name, value) in fields {
            // Loader, interpreter and proxy variables can redirect execution before the intended
            // tool starts. Business inputs get a separate namespace, never an inherited PATH.
            let allowed = matches!(name.as_str(), "LANG" | "LC_ALL" | "TZ" | "TERM")
                || name.starts_with("SPLAT_PARAM_");
            if !allowed || name.len() > 64
                || !name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') {
                bail!("environment contains a variable outside the step-input allow-list");
            }
            let text = value.as_str().ok_or_else(|| anyhow::anyhow!("environment values must be strings"))?;
            if text.len() > 1024 || text.contains('\0') { bail!("environment value exceeds its limit or contains NUL"); }
            result.insert(name.clone(), text.into());
        }
    }
    Ok(result)
}

/// Called only in the fork child; a setuid image must not undo the workload identity decision.
pub fn no_new_privileges() -> std::io::Result<()> {
    let core_limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &core_limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Prepared on the child stack using only raw syscalls. Separate SysV IPC state plus a socket
/// filter prevents a secret descriptor from escaping the lease through SCM_RIGHTS or shared IPC.
pub fn isolate_secret_ipc() -> std::io::Result<()> {
    if unsafe { libc::unshare(libc::CLONE_NEWIPC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    no_new_privileges()?;
    restrict_secret_sockets()
}

fn restrict_secret_sockets() -> std::io::Result<()> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("secret socket filter needs an audited syscall ABI for this architecture");
    let load = |offset| libc::sock_filter { code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16, jt: 0, jf: 0, k: offset };
    let equal = |value, yes, no| libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, jt: yes, jf: no, k: value };
    let ret = |value| libc::sock_filter { code: (libc::BPF_RET | libc::BPF_K) as u16, jt: 0, jf: 0, k: value };
    let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let filter = [
        load(4), equal(ARCH, 1, 0), ret(libc::SECCOMP_RET_KILL_PROCESS), load(0),
        // x32 uses the same audit architecture and different syscall numbers; reject that ABI.
        libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16, jt: 0, jf: 1, k: 0x40000000 },
        ret(denied), equal(libc::SYS_socket as u32, 0, 4), load(16),
        equal(libc::AF_INET as u32, 1, 0), ret(denied), ret(libc::SECCOMP_RET_ALLOW),
        equal(libc::SYS_socketpair as u32, 0, 1), ret(denied),
        // io_uring can create sockets without passing through the socket syscall filter.
        equal(libc::SYS_io_uring_setup as u32, 0, 1), ret(denied), ret(libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn service_environment_does_not_reach_the_child() {
        let mut child = std::process::Command::new("/usr/bin/env");
        child.env("SPLAT_TEST_SERVICE_CREDENTIAL", "must-not-survive");
        let result = child.env_clear().envs(environment(&json!({})).unwrap()).output().unwrap();
        let text = String::from_utf8(result.stdout).unwrap();
        assert!(result.status.success());
        assert!(!text.contains("must-not-survive"));
        assert_eq!(text.lines().count(), 4);
        assert!(text.contains("PATH=/usr/bin:/bin"));
    }

    #[test]
    fn only_bounded_step_variables_can_be_added() {
        let env = environment(&json!({"environment":{"SPLAT_PARAM_REGION":"us-east", "TZ":"UTC"}})).unwrap();
        assert_eq!(env["SPLAT_PARAM_REGION"], "us-east");
        for name in ["LD_PRELOAD", "PYTHONPATH", "BASH_ENV", "HTTP_PROXY", "PATH", "HOME", "SPLAT_PARAM_BAD="] {
            let mut input = json!({"environment":{}});
            input["environment"][name] = json!("untrusted");
            assert!(environment(&input).is_err(), "{name}");
        }
        for value in [json!(null), json!(1), json!("x\0y"), json!("x".repeat(1025))] {
            assert!(environment(&json!({"environment":{"SPLAT_PARAM_X":value}})).is_err());
        }
    }

    #[test]
    fn privilege_escalation_and_file_core_dumps_are_disabled_before_exec() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("/bin/sh");
        child.args(["-c", "grep '^NoNewPrivs:' /proc/self/status; ulimit -c"]);
        unsafe { child.pre_exec(no_new_privileges); }
        let output = child.output().unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("NoNewPrivs:\t1"), "{text}");
        assert!(text.ends_with("\n0\n"), "{text}");
    }

    #[test]
    fn secret_socket_filter_blocks_local_transfer_and_retains_ipv4() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new("/usr/bin/python3");
        child.args(["-I", "-c", r#"
import errno, socket
for operation in [lambda: socket.socket(socket.AF_UNIX), lambda: socket.socket(socket.AF_NETLINK), socket.socketpair]:
    try: operation()
    except OSError as error: assert error.errno == errno.EPERM
    else: raise AssertionError('local socket allowed')
socket.socket(socket.AF_INET).close()
"#]);
        unsafe { child.pre_exec(|| { no_new_privileges()?; restrict_secret_sockets() }); }
        let output = child.output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }

    #[test]
    #[ignore = "root component proof; spawns only a synthetic child, without BPF or service changes"]
    fn root_secret_stdin_privilege_drop_and_private_ipc_work_together() {
        use std::os::unix::process::CommandExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let pool = crate::identities::IdentityPool::reserved(200000, 1, 65534, 65534).unwrap();
        let identity = pool.acquire().unwrap();
        let uid = identity.id();
        let mut bytes = crate::secret_memory::SecretBytes::new(16).unwrap();
        bytes.as_mut_slice().copy_from_slice(b"synthetic-secret");
        let (file, _resident) = bytes.stdin_file().unwrap();
        drop(bytes);
        let ipc = std::fs::read_link("/proc/self/ns/ipc").unwrap();
        let mut child = std::process::Command::new("/usr/bin/python3");
        child.env_clear().envs(environment(&json!({})).unwrap()).stdin(file);
        child.args(["-I", "-c", &format!(r#"
import errno, os, socket
assert os.getuid() == {uid}
assert os.read(0, 100) == b'synthetic-secret'
assert os.read(0, 1) == b''
assert os.readlink('/proc/self/ns/ipc') != {ipc:?}
for operation in [lambda: open('/proc/self/fd/0','rb'), lambda: socket.socket(socket.AF_UNIX)]:
    try: operation()
    except OSError as error: assert error.errno in (errno.EACCES, errno.EPERM)
    else: raise AssertionError('secret channel escaped')
"#, ipc = ipc.to_string_lossy())]);
        unsafe { child.pre_exec(move || { isolate_secret_ipc()?; crate::drop_privileges(uid, uid) }); }
        let output = child.output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.stdout.is_empty());
    }
}
