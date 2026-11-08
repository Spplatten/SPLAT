//! Checked arithmetic for guest-running-time leases; no kernel or filesystem dependencies.
use std::time::Duration;

/// The lease lifetime a request is held to, in seconds. The admission validator bounds the kernel's
/// deadline by the same clamp, so a short request is not refused for the floor the writer applied.
pub const MIN_LEASE_SECONDS: u32 = 5;
pub const MAX_LEASE_SECONDS: u32 = 300;

pub fn resolve(now: u64, seconds: u32, approved: Option<u64>) -> Result<(u64, Duration), &'static str> {
    let duration = u64::from(seconds.clamp(MIN_LEASE_SECONDS, MAX_LEASE_SECONDS))
        .checked_mul(1_000_000_000).ok_or("duration overflow")?;
    let ceiling = now.checked_add(duration).ok_or("deadline overflow")?;
    let deadline = approved.unwrap_or(ceiling);
    if deadline <= now { return Err("approved deadline has expired"); }
    if deadline > ceiling { return Err("approved deadline exceeds configured duration"); }
    Ok((deadline, Duration::from_nanos(deadline - now)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn original_deadline_survives_installation_delay() {
        let d = 20_000_000_100;
        assert_eq!(resolve(457_000_100, 20, Some(d)), Ok((d, Duration::from_nanos(19_543_000_000))));
    }
    #[test] fn expired_approval_is_not_renewed() {
        assert!(resolve(100, 20, Some(100)).is_err());
        assert!(resolve(101, 20, Some(100)).is_err());
    }
    #[test] fn excessive_approval_is_refused() {
        assert!(resolve(100, 20, Some(20_000_000_101)).is_err());
    }
    #[test] fn overflow_is_refused() { assert!(resolve(u64::MAX - 1, 20, None).is_err()); }
    #[test] fn ungated_duration_contract_is_retained() {
        assert_eq!(resolve(100, 20, None).unwrap().0, 20_000_000_100);
        assert_eq!(resolve(100, 1, None).unwrap().0, 5_000_000_100);
        assert_eq!(resolve(100, u32::MAX, None).unwrap().0, 300_000_000_100);
    }
}
