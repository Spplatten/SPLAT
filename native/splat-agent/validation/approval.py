"""Mint an exact deadline before installation, on the guest's boot-time clock."""
import time


def lifetime(seconds, now_ns=None):
    if type(seconds) is not int or not 5 <= seconds <= 300:
        raise ValueError('duration must be an integer in 5..300 seconds')
    start = time.clock_gettime_ns(time.CLOCK_BOOTTIME) if now_ns is None else now_ns
    if type(start) is not int or not 0 <= start < 2**64:
        raise ValueError('invalid guest boot time')
    deadline = start + seconds * 1_000_000_000
    if deadline >= 2**64:
        raise ValueError('deadline overflow')
    return {'clock': 'guest-boottime', 'approvedAtBootNs': start,
            'deadlineBootNs': deadline, 'leaseDurationSeconds': seconds}
