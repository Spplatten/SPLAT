// The guest-side ceiling: a root-owned policy every lease is intersected with, whoever asks.
//
// The daemon trusts anyone who proves possession of the token, and on WSL any Windows process
// running as the operator can read that token exactly as the bridge does. No transport closes
// that, so the answer is to make holding the token buy less: this file, written by
// `splat-mcp provision` into the guest where a stolen token cannot reach around it, says the most
// any lease may name - which executables, which endpoints, which paths are always protected, how
// long, how much. A request inside it proceeds; one outside it is refused before a cgroup exists,
// in the same words the daemon uses for a dimension nobody declared.
//
// Absent, the daemon runs without a ceiling and says so at startup and in HEALTH_RESPONSE. A host
// that has one is bounded by it even from its own bridge; the MCP host's egress policy is then
// the first of two checks rather than the only one.

use std::collections::BTreeSet;
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/splat/policy.json";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyFile {
    schema: u64,
    /// Every executable a lease names must start with one of these. Each must be absolute; a
    /// trailing '/' is added if missing, so "/usr/bin" cannot also admit "/usr/binx".
    allowed_exec_prefixes: Vec<String>,
    /// Existing ceilings keep refusing executable scratch until the operator opts in.
    #[serde(default)]
    allow_scratch_exec: bool,
    /// `a.b.c.d:port` endpoints. Absent means the ceiling does not bound egress; an empty list
    /// means no lease may reach the network at all.
    #[serde(default)]
    allowed_egress: Option<Vec<String>>,
    /// Unioned into every lease's protected paths. Each must resolve on the guest, or every lease
    /// is refused - which is the fail-closed shape a missing deny entry demands.
    #[serde(default)]
    always_protected_paths: Vec<String>,
    #[serde(default)]
    max_lease_duration_seconds: Option<u32>,
    #[serde(default)]
    limits: Option<LimitsFile>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LimitsFile {
    max_memory_bytes: Option<u64>,
    max_cpu_percent: Option<u32>,
    max_pids: Option<u32>,
}

#[derive(Debug)]
pub struct Ceiling {
    exec_prefixes: Vec<String>,
    allow_scratch_exec: bool,
    egress: Option<BTreeSet<(Ipv4Addr, u16)>>,
    protected: Vec<String>,
    max_duration: Option<u32>,
    pub max_memory_bytes: Option<u64>,
    pub max_cpu_percent: Option<u32>,
    pub max_pids: Option<u32>,
}

/// The dimensions of a request the ceiling bounds, borrowed from the parsed envelope.
pub struct Ask<'a> {
    pub exec_paths: &'a [String],
    pub allow_network: bool,
    pub egress_ips: &'a [String],
    pub egress_ports: &'a [u32],
}

impl Ceiling {
    /// The ceiling at `path`, or None when there is none. A file that is there but cannot be
    /// trusted - not root's, writable by anyone else, or not a policy this daemon understands - is
    /// an error, because a ceiling anyone can rewrite is no ceiling and the daemon must not serve
    /// as if it had one.
    pub fn load(path: &Path) -> Result<Option<Self>> {
        let md = match fs::metadata(path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        };
        if md.uid() != 0 {
            bail!("{} is owned by uid {}, not root; a ceiling anyone can rewrite is no ceiling", path.display(), md.uid());
        }
        if md.permissions().mode() & 0o022 != 0 {
            bail!("{} is mode {:o}; group- or world-writable, so a ceiling anyone can rewrite", path.display(), md.permissions().mode() & 0o777);
        }
        let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parse {}", path.display())).map(Some)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let file: PolicyFile = serde_json::from_str(text).context("not a policy this daemon understands")?;
        if file.schema != 1 {
            bail!("schema {} is not the 1 this daemon speaks", file.schema);
        }
        let mut exec_prefixes = Vec::new();
        for prefix in file.allowed_exec_prefixes {
            if !prefix.starts_with('/') || prefix.contains("/../") || prefix.ends_with("/..") {
                bail!("exec prefix {prefix:?} is not an absolute path without '..'");
            }
            exec_prefixes.push(if prefix.ends_with('/') { prefix } else { format!("{prefix}/") });
        }
        if exec_prefixes.is_empty() {
            bail!("allowedExecPrefixes names nothing, so no lease could run anything");
        }

        let egress = match file.allowed_egress {
            None => None,
            Some(list) => {
                let mut set = BTreeSet::new();
                for entry in list {
                    let (addr, port) = entry
                        .rsplit_once(':')
                        .with_context(|| format!("egress entry {entry:?} is not a.b.c.d:port"))?;
                    let addr: Ipv4Addr = addr.parse().with_context(|| format!("egress entry {entry:?} is not an IPv4 address"))?;
                    let port: u16 = port.parse().with_context(|| format!("egress entry {entry:?} has no port from 1 to 65535"))?;
                    if port == 0 {
                        bail!("egress entry {entry:?} names port 0");
                    }
                    set.insert((addr, port));
                }
                Some(set)
            }
        };

        let limits = file.limits.unwrap_or_default();
        Ok(Self {
            exec_prefixes,
            allow_scratch_exec: file.allow_scratch_exec,
            egress,
            protected: file.always_protected_paths,
            max_duration: file.max_lease_duration_seconds,
            max_memory_bytes: limits.max_memory_bytes,
            max_cpu_percent: limits.max_cpu_percent,
            max_pids: limits.max_pids,
        })
    }

    /// Whether `ask` fits under this ceiling; if not, why, naming the first thing outside it.
    pub fn check(&self, ask: &Ask) -> std::result::Result<(), String> {
        for path in ask.exec_paths {
            let p = Path::new(path);
            if !p.is_absolute() || p.components().any(|c| matches!(c, Component::ParentDir)) {
                return Err(format!("executable {path:?} is not an absolute path without '..'"));
            }
            if !self.exec_prefixes.iter().any(|prefix| path.starts_with(prefix.as_str())) {
                return Err(format!(
                    "executable {path:?} is outside the exec ceiling ({})",
                    self.exec_prefixes.join(", ")
                ));
            }
        }

        if ask.allow_network {
            if let Some(allowed) = &self.egress {
                for ip in ask.egress_ips {
                    let addr: Ipv4Addr = ip
                        .parse()
                        .map_err(|_| format!("egress address {ip:?} is not an IPv4 address"))?;
                    for port in ask.egress_ports {
                        let port = u16::try_from(*port).map_err(|_| format!("egress port {port} is not a port"))?;
                        if !allowed.contains(&(addr, port)) {
                            return Err(format!("endpoint {addr}:{port} is outside the egress ceiling"));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_scratch_exec(&self, requested: bool) -> std::result::Result<(), String> {
        if requested && !self.allow_scratch_exec {
            return Err("scratch execution is outside the exec ceiling (allowScratchExec is false)".into());
        }
        Ok(())
    }

    pub fn protected_paths(&self) -> &[String] {
        &self.protected
    }

    /// A lease is a grant, not a negotiation: the ceiling only ever shortens it.
    pub fn clamp_duration(&self, requested: u32) -> u32 {
        self.max_duration.map_or(requested, |max| requested.min(max))
    }

    /// The ceiling's memory, CPU and PID limits folded under the daemon's own.
    pub fn memory_ceiling(&self, daemon: u64) -> u64 {
        self.max_memory_bytes.map_or(daemon, |m| m.min(daemon))
    }

    pub fn cpu_ceiling(&self, daemon: u32) -> u32 {
        self.max_cpu_percent.map_or(daemon, |m| m.min(daemon))
    }

    pub fn pids_ceiling(&self, daemon: u32) -> u32 {
        self.max_pids.map_or(daemon, |m| m.min(daemon))
    }

    pub fn bounds_egress(&self) -> bool {
        self.egress.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"{
        "schema": 1,
        "allowedExecPrefixes": ["/usr/bin", "/bin/"],
        "allowedEgress": ["127.0.0.1:80", "1.1.1.1:443"],
        "alwaysProtectedPaths": ["/etc/gshadow"],
        "maxLeaseDurationSeconds": 60,
        "limits": { "maxMemoryBytes": 67108864 }
    }"#;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn scratch_execution_requires_an_explicit_operator_grant() {
        let closed = Ceiling::parse(POLICY).unwrap();
        assert!(closed.check_scratch_exec(true).is_err());
        assert!(closed.check_scratch_exec(false).is_ok());
        let open = Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["/bin/"],"allowScratchExec":true}"#).unwrap();
        assert!(open.check_scratch_exec(true).is_ok());
        assert!(Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["/bin/"],"allowScratchExec":"true"}"#).is_err());
    }

    #[test]
    fn a_request_inside_the_ceiling_passes() {
        let c = Ceiling::parse(POLICY).unwrap();
        let exec = strings(&["/usr/bin/curl", "/bin/sh"]);
        let ips = strings(&["127.0.0.1"]);
        assert_eq!(c.check(&Ask { exec_paths: &exec, allow_network: true, egress_ips: &ips, egress_ports: &[80] }), Ok(()));
    }

    #[test]
    fn an_executable_outside_the_prefixes_is_refused_by_name() {
        let c = Ceiling::parse(POLICY).unwrap();
        let exec = strings(&["/bin/sh", "/opt/agent/run"]);
        let err = c.check(&Ask { exec_paths: &exec, allow_network: false, egress_ips: &[], egress_ports: &[] }).unwrap_err();
        assert!(err.contains("/opt/agent/run") && err.contains("exec ceiling"), "{err}");
    }

    #[test]
    fn a_prefix_is_a_directory_not_a_string_prefix() {
        // "/usr/bin" in the file must not admit "/usr/binx/evil".
        let c = Ceiling::parse(POLICY).unwrap();
        let exec = strings(&["/usr/binx/evil"]);
        assert!(c.check(&Ask { exec_paths: &exec, allow_network: false, egress_ips: &[], egress_ports: &[] }).is_err());
    }

    #[test]
    fn dot_dot_cannot_walk_out_of_a_prefix() {
        let c = Ceiling::parse(POLICY).unwrap();
        let exec = strings(&["/usr/bin/../../opt/evil"]);
        let err = c.check(&Ask { exec_paths: &exec, allow_network: false, egress_ips: &[], egress_ports: &[] }).unwrap_err();
        assert!(err.contains("'..'"), "{err}");
    }

    #[test]
    fn an_endpoint_outside_the_egress_ceiling_is_refused_and_the_cross_product_is_what_is_checked() {
        let c = Ceiling::parse(POLICY).unwrap();
        let exec = strings(&["/bin/sh"]);
        // 127.0.0.1:80 and 1.1.1.1:443 are allowed; the lease would install 127.0.0.1:443 too.
        let ips = strings(&["127.0.0.1", "1.1.1.1"]);
        let err = c.check(&Ask { exec_paths: &exec, allow_network: true, egress_ips: &ips, egress_ports: &[80, 443] }).unwrap_err();
        assert!(err.contains("127.0.0.1:443") && err.contains("egress ceiling"), "{err}");
    }

    #[test]
    fn with_the_network_off_the_egress_ceiling_does_not_apply() {
        let c = Ceiling::parse(POLICY).unwrap();
        let exec = strings(&["/bin/sh"]);
        let ips = strings(&["8.8.8.8"]);
        assert_eq!(c.check(&Ask { exec_paths: &exec, allow_network: false, egress_ips: &ips, egress_ports: &[53] }), Ok(()));
    }

    #[test]
    fn an_absent_egress_list_leaves_egress_unbounded_and_an_empty_one_closes_it() {
        let open = Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["/bin/"]}"#).unwrap();
        let closed = Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["/bin/"],"allowedEgress":[]}"#).unwrap();
        let exec = strings(&["/bin/sh"]);
        let ips = strings(&["8.8.8.8"]);
        let ask = Ask { exec_paths: &exec, allow_network: true, egress_ips: &ips, egress_ports: &[53] };
        assert!(!open.bounds_egress() && open.check(&ask).is_ok());
        assert!(closed.bounds_egress() && closed.check(&ask).is_err());
    }

    #[test]
    fn the_ceiling_only_ever_shortens_and_lowers() {
        let c = Ceiling::parse(POLICY).unwrap();
        assert_eq!(c.clamp_duration(300), 60);
        assert_eq!(c.clamp_duration(10), 10);
        assert_eq!(c.memory_ceiling(256 * 1024 * 1024), 64 * 1024 * 1024);
        assert_eq!(c.cpu_ceiling(50), 50, "a limit the file does not set is the daemon's");
        assert_eq!(c.protected_paths(), &["/etc/gshadow".to_string()]);
    }

    #[test]
    fn a_policy_this_daemon_does_not_understand_is_refused_not_ignored() {
        assert!(Ceiling::parse(r#"{"schema":2,"allowedExecPrefixes":["/bin/"]}"#).is_err(), "another schema");
        assert!(Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["/bin/"],"allowUdp":true}"#).is_err(), "an unknown field");
        assert!(Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":[]}"#).is_err(), "nothing runnable");
        assert!(Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["bin/"]}"#).is_err(), "a relative prefix");
        assert!(Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["/bin/"],"allowedEgress":["1.1.1.1"]}"#).is_err(), "no port");
        assert!(Ceiling::parse(r#"{"schema":1,"allowedExecPrefixes":["/bin/"],"allowedEgress":["01.1.1.1:80"]}"#).is_err(), "a leading zero");
    }

    #[test]
    fn a_file_that_is_not_roots_or_that_others_can_write_is_refused_and_a_missing_one_is_none() {
        let dir = std::env::temp_dir().join(format!("splat_ceiling_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        assert!(Ceiling::load(&dir.join("absent.json")).unwrap().is_none());

        let path = dir.join("policy.json");
        fs::write(&path, POLICY).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let outcome = Ceiling::load(&path);
        if unsafe { libc::geteuid() } == 0 {
            assert!(outcome.unwrap().is_some(), "root's 0644 file is a ceiling");
        } else {
            assert!(outcome.unwrap_err().to_string().contains("not root"), "a file the tests own is not root's");
        }

        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Ceiling::load(&path).is_err(), "world-writable is refused whoever owns it");

        let _ = fs::remove_dir_all(&dir);
    }
}
