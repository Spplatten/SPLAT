// Structured kernel -EPERM violation event representation.
// Deserialized directly from the BPF-LSM ringbuffer.

use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawViolationEvent {
    pub cgroup_id: u64,
    pub ktime_ns: u64,
    pub seq: u64,
    pub pid: u32,
    pub hook: u32,
    pub detail: u32,
    pub comm: [u8; 16],
}

// Mirrors `struct violation_event` in lease_lsm.bpf.c: 8 + 8 + 8 + 4 + 4 + 4 + 16 = 52, padded to
// 56 by the u64s' alignment. The drain casts the ring buffer record straight to this type, so a
// layout that drifted would read the pid out of the hook and never say so. The lease keys already
// fail the build this way; this was the one struct crossing that boundary that did not.
const _: () = assert!(std::mem::size_of::<RawViolationEvent>() == 56);
const _: () = assert!(std::mem::align_of::<RawViolationEvent>() == 8);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub hook: u32,
    pub detail: u64,
    pub detail_text: String,
    pub comm: String,
    /// The daemon's wall clock when the record was drained, milliseconds since the Unix epoch.
    pub timestamp_ms: u64,
    /// The kernel's monotonic clock at the denial itself, nanoseconds since boot.
    pub ktime_ns: u64,
    /// The denial's number, taken before the record was reserved: a number never seen was dropped.
    pub seq: u64,
}

impl ViolationEvent {
    pub fn from_raw(raw: &RawViolationEvent) -> Self {
        let comm_len = raw.comm.iter().position(|&b| b == 0).unwrap_or(16);
        let comm = String::from_utf8_lossy(&raw.comm[0..comm_len]).to_string();

        let detail_text = match raw.hook {
            1 => format!("bprm_check_security: denied execution of unleased binary (inode {})", raw.detail),
            2 => format!("file_open: denied access to protected sensitive file (inode {})", raw.detail),
            // The hook reports 0 for an IPv6 destination, which it denies without an address to name;
            // an IPv4 connect to 0.0.0.0 reports the same word, so the text says both rather than
            // rendering a v6 denial as a v4 address nobody dialled.
            3 if raw.detail == 0 => "socket_connect: denied outbound network connection (IPv6 destination, or IPv4 0.0.0.0)".to_string(),
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
            ktime_ns: raw.ktime_ns,
            seq: raw.seq,
        }
    }
}

/// Renders the raw `sin_addr.s_addr` word the kernel reports back into dotted quad.
///
/// Must mirror [`ipv4_to_be_u32`] exactly: the octets sit in memory order, so they are read with
/// `to_ne_bytes`. Using `to_be_bytes` here reversed them on a little-endian host, and the denial of
/// 127.0.0.1 was recorded as "1.0.0.127" — in the audit ledger, which is the one place a wrong
/// address is worst. 1.1.1.1 hid it, being a byte-palindrome.
pub fn be_u32_to_ipv4(be: u32) -> String {
    let b = be.to_ne_bytes();
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
    // No byte swap. The BPF program reads sin_addr.s_addr straight out of the sockaddr, where the
    // address already sits in network order, and keys the map on that raw u32. Reading those bytes
    // on a little-endian host yields 127.0.0.1 as 0x0100007F. The `.to_be()` that used to be here
    // produced 0x7F000001 instead, so the seeded allow-list never matched what the kernel looked up
    // and EVERY destination was refused - including the one the lease existed to permit.
    //
    // Third instance of the same failure in this codebase: userspace and kernel disagreeing about an
    // encoding, with nothing comparing the two. See kernel_dev_from_st_dev in lease.rs for the first.
    Ok(u32::from_ne_bytes([parts[0], parts[1], parts[2], parts[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned to the values the kernel actually reported on 2026-09-03. The daemon denied its own
    /// permitted destination because it seeded 0x7F000001 while the ringbuf reported 0x0100007F for
    /// the same address — the byte order the BPF program keys on.
    #[test]
    fn ipv4_matches_the_raw_sockaddr_byte_order() {
        assert_eq!(ipv4_to_be_u32("127.0.0.1").unwrap(), 16_777_343); // 0x0100007F
        assert_eq!(ipv4_to_be_u32("1.1.1.1").unwrap(), 16_843_009); // 0x01010101
    }

    /// The daemon and the canary must agree; they load the same BPF program, so a divergence here
    /// means one of them silently enforces a different policy than the other.
    #[test]
    fn encoding_is_the_raw_octet_order_not_the_swapped_one() {
        let v = ipv4_to_be_u32("127.0.0.1").unwrap();
        assert_eq!(v.to_ne_bytes(), [127, 0, 0, 1], "octets must survive in memory order");
        assert_ne!(v, 2_130_706_433, "0x7F000001 is the swapped form the kernel never looks up");
    }

    /// The formatter and the parser must be inverses. They were not: a denial of 127.0.0.1 was
    /// written into the ledger as "1.0.0.127".
    #[test]
    fn rendering_round_trips_with_parsing() {
        for addr in ["127.0.0.1", "1.1.1.1", "10.20.30.40", "8.8.8.8"] {
            let raw = ipv4_to_be_u32(addr).unwrap();
            assert_eq!(be_u32_to_ipv4(raw), addr, "{addr} must survive parse then render");
        }
    }

    /// An IPv6 denial reaches the ring buffer with detail 0, which the old text rendered as a denial
    /// of "0.0.0.0" - an IPv4 address nobody dialled, in the ledger.
    #[test]
    fn a_detail_of_zero_on_the_connect_hook_is_not_rendered_as_an_ipv4_address() {
        let raw = RawViolationEvent {
            cgroup_id: 7,
            ktime_ns: 1_000,
            seq: 9,
            pid: 1,
            hook: 3,
            detail: 0,
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        };
        let event = ViolationEvent::from_raw(&raw);
        assert!(event.detail_text.contains("IPv6"), "{}", event.detail_text);
        assert!(!event.detail_text.contains("unapproved IPv4 0.0.0.0"), "{}", event.detail_text);
        assert_eq!(event.comm, "curl");
        assert_eq!((event.ktime_ns, event.seq), (1_000, 9), "the kernel's clock and number survive the decode");
    }

    #[test]
    fn rejects_malformed_addresses() {
        assert!(ipv4_to_be_u32("1.2.3").is_err());
        assert!(ipv4_to_be_u32("300.1.1.1").is_err());
    }
}
