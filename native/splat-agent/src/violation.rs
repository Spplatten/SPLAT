// Structured kernel -EPERM violation event representation.
// Deserialized directly from the BPF-LSM ringbuffer.

use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawViolationEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub hook: u32,
    pub detail: u32,
    pub comm: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub hook: u32,
    pub detail: u64,
    pub detail_text: String,
    pub comm: String,
    pub timestamp_ms: u64,
}

impl ViolationEvent {
    pub fn from_raw(raw: &RawViolationEvent) -> Self {
        let comm_len = raw.comm.iter().position(|&b| b == 0).unwrap_or(16);
        let comm = String::from_utf8_lossy(&raw.comm[0..comm_len]).to_string();

        let detail_text = match raw.hook {
            1 => format!("bprm_check_security: denied execution of unleased binary (inode {})", raw.detail),
            2 => format!("file_open: denied access to protected sensitive file (inode {})", raw.detail),
            3 => format!("socket_connect: denied outbound network connection to unapproved IPv4 {}", be_u32_to_ipv4(raw.detail)),
            _ => format!("unspecified kernel hook violation (hook {}, detail {})", raw.hook, raw.detail),
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            cgroup_id: raw.cgroup_id,
            pid: raw.pid,
            hook: raw.hook,
            detail: raw.detail as u64,
            detail_text,
            comm,
            timestamp_ms: now,
        }
    }
}

pub fn be_u32_to_ipv4(be: u32) -> String {
    let b = be.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

pub fn ipv4_to_be_u32(s: &str) -> anyhow::Result<u32> {
    let parts: Vec<u8> = s.split('.')
        .map(|p| p.parse::<u8>())
        .collect::<Result<_, _>>()
        .map_err(|_| anyhow::anyhow!("invalid IPv4 address: {s}"))?;
    if parts.len() != 4 {
        anyhow::bail!("invalid IPv4 address: {s}");
    }
    Ok(u32::from_ne_bytes([parts[0], parts[1], parts[2], parts[3]]).to_be())
}