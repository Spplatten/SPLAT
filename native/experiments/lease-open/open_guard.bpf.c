// Isolated lab program: NOT the shipping SPLAT map ABI and NOT permission to attach on a live host.
// The control-plane loader must install policy before releasing a child into this cgroup, retain
// an O_PATH fd for the protected inode, and keep the cgroup object alive through kill+drain.
#include "../../splat-agent/src/bpf/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// 32 bytes is a size claim, not proof of cache-line placement. bpf map element allocation and
// offsets decide actual alignment. No shared sensor may write this map or manufacture epochs.
struct open_lease {
    __u64 deadline_boot_ns;
    __u64 protected_ino;
    __u64 epoch;
    __u32 protected_dev;  // kernel s_dev encoding, not unconverted userspace st_dev
    __u32 denied_fmode;   // FMODE_READ=1, FMODE_WRITE=2; covers NEW opens, not inherited descriptors
};
_Static_assert(sizeof(struct open_lease) == 32, "open_lease ABI drift");
struct denial { __u64 cgroup, epoch, time_boot_ns; __u32 pid, reason; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH); // Default preallocation; never specify BPF_F_NO_PREALLOC.
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, struct open_lease);
} policies SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

static __always_inline void observe(__u64 cg, const struct open_lease *p, __u32 why, __u64 now)
{
    struct denial *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __u32 zero = 0;
        __u64 *d = bpf_map_lookup_elem(&drops, &zero);
        if (d) __sync_fetch_and_add(d, 1);
        return; // Telemetry failure NEVER changes the caller's already-selected -EPERM.
    }
    e->cgroup = cg; e->epoch = p->epoch; e->time_boot_ns = now;
    e->pid = bpf_get_current_pid_tgid() >> 32; e->reason = why;
    bpf_ringbuf_submit(e, 0);
}
SEC("lsm/file_open")
int BPF_PROG(splat_lab_open, struct file *file, int ret)
{
    if (ret) return ret; // Preserve a prior BPF-LSM denial; never turn it into allow.
    __u64 cg = bpf_get_current_cgroup_id();
    const struct open_lease *lease = bpf_map_lookup_elem(&policies, &cg);
    if (!lease) return 0; // Unregistered host workloads are outside the experiment.
    __u64 now = bpf_ktime_get_boot_ns(); // Match the daemon's clock; ktime_get_ns excludes suspend.
    __u32 reason = 0;
    if (now >= lease->deadline_boot_ns) reason = 1;
    else {
        struct inode *inode = BPF_CORE_READ(file, f_inode);
        if (!inode) reason = 2;
        else if (BPF_CORE_READ(inode, i_ino) == lease->protected_ino &&
                 BPF_CORE_READ(inode, i_sb, s_dev) == lease->protected_dev &&
                 (BPF_CORE_READ(file, f_mode) & lease->denied_fmode)) reason = 3;
    }
    if (!reason) return 0;
    observe(cg, lease, reason, now);
    return -1; // -EPERM: this is denial of an operation, NOT a process kill.
}
