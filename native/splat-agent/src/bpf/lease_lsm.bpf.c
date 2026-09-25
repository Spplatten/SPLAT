// SPLAT kernel canary: BPF-LSM policy that enforces a per-cgroup capability lease.
//
// This is the seed of Layer 3 in the SPLAT architecture. It proves the ONE claim the
// whole pitch rests on: an unconstrained agent process that steps outside its declared
// lease is stopped by the kernel with -EPERM, not by a user-space check it could skip.
//
// Enforcement is deliberately keyed on inode identity and destination address, NOT on resolved
// path strings. Full path resolution inside a BPF program is racy (TOCTOU) and expensive; the
// honest, defensible primitive is "this exact inode" / "this exact destination address".
// The README documents that boundary rather than hiding it.
//
// EVERY policy key carries the cgroup id. That is not decoration. The maps were previously keyed
// by the resource alone, with the cgroup only consulted to decide whether policy applied AT ALL -
// so two concurrent leases received the union of each other's permissions: a mission that
// allow-listed /usr/bin/python3 silently granted it to every other leased mission, and revoking
// one lease deleted a protected-inode entry another lease was still relying on. A per-mission
// capability lease that leaks across missions is not a capability lease.
//
// NOTE: native/splat-canary/src/bpf/lease_lsm.bpf.c is a deliberate fork of this file, frozen at
// the shape its recorded evidence was produced against. It proves the primitive; this one is the
// daemon's.
//
// Hooks:
//   bprm_check_security -> only allow-listed executable inodes may exec           (-EPERM)
//   file_open           -> protected inodes cannot be opened by a leased process  (-EPERM)
//   socket_connect      -> only allow-listed IPv4 /32 destinations are reachable  (-EPERM)
//   socket_sendmsg      -> the same, for a datagram that names its own destination (-EPERM)
//
// A process is "leased" iff its current cgroup id is present in leased_cgroups. Anything
// outside the lease is untouched, so the host and every other workload are unaffected.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL"; // BPF-LSM + ringbuf helpers require a GPL-compatible license.

#define AF_INET 2
#define AF_INET6 10
#define EPERM 1

// Inode identity. The (dev, ino) pair is unique across all mounts/filesystems.
struct inode_key {
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};

// A policy entry belongs to ONE lease. 24 bytes, natural 8-byte alignment; the Rust side mirrors
// this layout exactly and a size assertion in lease.rs fails the build if the two ever drift.
struct lease_inode_key {
    __u64 cgroup_id;
    __u64 ino;
    __u32 dev;
    __u32 _pad;
};

// An approved IPv4 ENDPOINT - address and port together, 16 bytes.
//
// The port used to be absent: the lease parsed allowedEgressPorts, carried them in its config, and
// never sent them to the kernel, so an approved host was approved on every port it listened on.
// `port` is kept in network byte order so it compares directly against sin_port with no byte swap
// in the hook.
struct lease_ipv4_key {
    __u64 cgroup_id;
    __u32 addr;
    __u16 port;
    __u16 _pad;
};

enum splat_hook {
    HOOK_EXEC = 1,
    HOOK_OPEN = 2,
    HOOK_CONNECT = 3,
    HOOK_SENDMSG = 4,
};

// One denial, as the daemon reads it: 56 bytes, 8-byte alignment, mirrored by RawViolationEvent in
// violation.rs with a size assertion. The record used to carry no time and no number, so a consumer
// could neither say when a denial happened nor tell that one had been lost.
struct violation_event {
    __u64 cgroup_id;
    __u64 ktime_ns; // bpf_ktime_get_ns() at the denial: the kernel's monotonic clock, not wall time
    __u64 seq;      // taken from `counters` BEFORE the reservation, so a number never delivered was dropped
    __u32 pid;
    __u32 hook;     // enum splat_hook
    __u32 detail;   // exec/open: inode number (low 32 bits); connect: destination IPv4 (network byte order)
    char comm[16];
};

enum splat_counter {
    COUNTER_NEXT_SEQ = 0, // the next sequence number; every denial takes one, delivered or not
    COUNTER_DROPPED = 1,  // denials the ring buffer had no room for. The -EPERM still happened
    COUNTER_MAX,
};

// Two words the daemon reads back: how many denials have been numbered and how many were never
// delivered. A denial the buffer dropped used to vanish without a trace; now it leaves a gap in the
// sequence and a count here.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

// cgroup id -> 1. Presence means "this cgroup holds a lease and is subject to policy".
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} leased_cgroups SEC(".maps");

// Inodes a given lease's processes may NOT open (e.g. /etc/shadow captured at lease time).
// Entries are per-lease, so revoking one lease cannot remove a protection another still holds.
// Sized for the 256 concurrent leases leased_cgroups admits, times a realistic protected set.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct lease_inode_key);
    __type(value, __u8);
} protected_inodes SEC(".maps");

// The only executable inodes a given lease may exec. Everything else is denied - including a
// binary some OTHER concurrent lease was granted.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct lease_inode_key);
    __type(value, __u8);
} allowed_exec_inodes SEC(".maps");

// The only IPv4 destinations (network byte order, /32) a given lease may connect() to.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct lease_ipv4_key);
    __type(value, __u8);
} allowed_connect_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} violations SEC(".maps");

// cgroup id -> how many denials this lease has caused. The ring buffer is how a denial is
// DESCRIBED; this is how many there were, and the two are not the same number once a record is
// dropped or a frame arrives after the caller has stopped reading.
//
// Without it the daemon could only report what it managed to forward, so a lease whose evidence was
// incomplete looked exactly like a lease that was never denied anything. On 2026-09-25 the root
// probe scored `udp_outside_the_lease_blocked` false while that same run's violation list held the
// denial: the kernel refused the datagram and the frame did not reach the session. The wall held
// and the receipt did not, which for this product is the worse half to get wrong.
//
// Keyed by cgroup because that is what the hooks have in hand. The daemon deletes the entry when it
// revokes the lease, so this map holds live leases only and cannot outgrow leased_cgroups.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} violation_counts SEC(".maps");

static __always_inline __u8 is_leased(__u64 cgid)
{
    return bpf_map_lookup_elem(&leased_cgroups, &cgid) != NULL;
}

static __always_inline void report(__u64 cgid, __u32 hook, __u32 detail)
{
    __u32 seq_key = COUNTER_NEXT_SEQ;
    __u32 dropped_key = COUNTER_DROPPED;
    __u64 *next_seq = bpf_map_lookup_elem(&counters, &seq_key);
    __u64 *dropped = bpf_map_lookup_elem(&counters, &dropped_key);
    if (!next_seq || !dropped) // An array lookup inside max_entries cannot fail; the verifier still asks.
        return;

    // Numbered before the reservation, so a dropped denial still consumes its number and the gap
    // is visible to a consumer. Two CPUs may deliver neighbouring numbers out of order; a number
    // that never arrives at all was dropped, and `dropped` says how many.
    __u64 seq = __sync_fetch_and_add(next_seq, 1);

    // Counted before the reservation too, and for this cgroup alone. This is the number the lease's
    // receipt is checked against: a caller that received fewer frames than this was told less than
    // the kernel did, and the EXIT frame says so rather than leaving the gap invisible.
    __u64 *seen = bpf_map_lookup_elem(&violation_counts, &cgid);
    if (seen) {
        __sync_fetch_and_add(seen, 1);
    } else {
        __u64 one = 1;
        // BPF_NOEXIST: two CPUs denying the first action of the same lease at once must not each
        // install a 1 and lose the other's. The loser's update fails and its denial is added below.
        if (bpf_map_update_elem(&violation_counts, &cgid, &one, BPF_NOEXIST) != 0) {
            seen = bpf_map_lookup_elem(&violation_counts, &cgid);
            if (seen) {
                __sync_fetch_and_add(seen, 1);
            }
        }
    }

    struct violation_event *e = bpf_ringbuf_reserve(&violations, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(dropped, 1);
        return;
    }
    e->cgroup_id = cgid;
    e->ktime_ns = bpf_ktime_get_ns();
    e->seq = seq;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->hook = hook;
    e->detail = detail;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
}

static __always_inline struct inode_key inode_key_of(struct inode *inode)
{
    struct inode_key k = {};
    k.ino = BPF_CORE_READ(inode, i_ino);
    k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    k._pad = 0;
    return k;
}

static __always_inline struct lease_inode_key lease_inode_key_of(__u64 cgid, struct inode *inode)
{
    struct lease_inode_key k = {};
    k.cgroup_id = cgid;
    k.ino = BPF_CORE_READ(inode, i_ino);
    k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
    k._pad = 0;
    return k;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(splat_bprm_check, struct linux_binprm *bprm, int ret)
{
    if (ret != 0) // An earlier LSM already denied; never override a deny into an allow.
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_leased(cgid))
        return 0;

    struct file *f = BPF_CORE_READ(bprm, file);
    struct inode *inode = f ? BPF_CORE_READ(f, f_inode) : NULL;
    if (!inode) {
        f = BPF_CORE_READ(bprm, executable);
        if (f)
            inode = BPF_CORE_READ(f, f_inode);
    }

    if (!inode) {
        report(cgid, HOOK_EXEC, 0);
        return -EPERM;
    }

    // Keyed by THIS lease. A binary another concurrent mission was granted is not on this
    // mission's allow-list, which is the whole point of a per-mission lease.
    struct lease_inode_key k = lease_inode_key_of(cgid, inode);
    if (bpf_map_lookup_elem(&allowed_exec_inodes, &k) != NULL)
        return 0; // On this lease's allow-list: permit.

    report(cgid, HOOK_EXEC, (__u32)k.ino);
    return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(splat_file_open, struct file *file, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_leased(cgid))
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct lease_inode_key k = lease_inode_key_of(cgid, inode);
    if (bpf_map_lookup_elem(&protected_inodes, &k) != NULL) {
        report(cgid, HOOK_OPEN, (__u32)k.ino);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(splat_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_leased(cgid))
        return 0;

    sa_family_t family = BPF_CORE_READ(address, sa_family);

    // IPv6 is DENIED outright for a leased process, not waved through.
    //
    // There is no v6 allow-list - the lease speaks in IPv4 /32s - so every AF_INET6 connect used to
    // return 0 here and reach the network unpoliced. That made `allowNetwork: false` mean "no IPv4",
    // which is not what it says, and left a dual-stacked host one getaddrinfo away from egress.
    // Denying is the only answer that matches the policy vocabulary; allowing v6 destinations needs
    // a v6 allow-list, and until there is one there is nothing to check an address against.
    if (family == AF_INET6) {
        report(cgid, HOOK_CONNECT, 0);
        return -EPERM;
    }

    // Anything else - AF_UNIX, AF_NETLINK - is NOT policed by this hook and is documented as such
    // in SUPPORTED_POLICY.md. Denying local IPC wholesale would break name resolution and logging
    // for the shipped catalogue; claiming it is contained when it is not would be worse than both.
    if (family != AF_INET)
        return 0;

    // An AF_INET address shorter than a sockaddr_in has no destination in it to check. Reading one
    // anyway would judge bytes past the caller's buffer, so it is refused rather than guessed.
    if (addrlen < (int)sizeof(struct sockaddr_in)) {
        report(cgid, HOOK_CONNECT, 0);
        return -EPERM;
    }

    struct sockaddr_in *in = (struct sockaddr_in *)address;
    __u32 daddr = BPF_CORE_READ(in, sin_addr.s_addr); // network byte order
    __u16 dport = BPF_CORE_READ(in, sin_port);        // network byte order

    struct lease_ipv4_key k = {};
    k.cgroup_id = cgid;
    k.addr = daddr;
    k.port = dport;
    k._pad = 0;
    if (bpf_map_lookup_elem(&allowed_connect_ipv4, &k) != NULL)
        return 0; // Approved endpoint FOR THIS LEASE - this address on this port.

    report(cgid, HOOK_CONNECT, daddr);
    return -EPERM;
}

// A datagram that carries its own destination, which socket_connect never sees.
//
// `sendto()` on an unconnected UDP socket names the address in the message rather than on the
// socket, so no connect happens and the hook above never fires. That left every leased process a
// full UDP path out - DNS included - while `allowNetwork: false` read as "no network". The same
// allow-list answers both: a datagram destination is an endpoint like any other.
//
// A message with NO destination of its own is on a connected socket, which socket_connect already
// judged at connect time; judging it again here would deny nothing new and cost a lookup per
// datagram on an already-approved path.
SEC("lsm/socket_sendmsg")
int BPF_PROG(splat_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size, int ret)
{
    if (ret != 0)
        return ret;

    __u64 cgid = bpf_get_current_cgroup_id();
    if (!is_leased(cgid))
        return 0;

    void *name = BPF_CORE_READ(msg, msg_name);
    if (!name)
        return 0; // Connected socket: socket_connect settled this one.

    int namelen = BPF_CORE_READ(msg, msg_namelen);

    // The kernel copied this sockaddr in before the hook ran (move_addr_to_kernel), so it is kernel
    // memory and its length is the one the kernel accepted, not the caller's claim.
    struct sockaddr_in in = {};
    if (namelen < (int)sizeof(in)) {
        // Too short to hold an IPv4 destination. It may still be an AF_UNIX path, which this hook
        // does not police, so read only the family and decide on that.
        sa_family_t short_family = 0;
        if (bpf_probe_read_kernel(&short_family, sizeof(short_family), name) != 0)
            return 0;
        if (short_family != AF_INET && short_family != AF_INET6)
            return 0;
        report(cgid, HOOK_SENDMSG, 0);
        return -EPERM;
    }

    if (bpf_probe_read_kernel(&in, sizeof(in), name) != 0)
        return 0; // Unreadable: nothing to judge, and the connect hook still guards connected paths.

    if (in.sin_family == AF_INET6) {
        report(cgid, HOOK_SENDMSG, 0); // As connect does: no v6 vocabulary, so no v6 destination.
        return -EPERM;
    }
    if (in.sin_family != AF_INET)
        return 0; // AF_UNIX and the rest: documented as not policed.

    struct lease_ipv4_key k = {};
    k.cgroup_id = cgid;
    k.addr = in.sin_addr.s_addr; // network byte order, as the connect hook keys it
    k.port = in.sin_port;
    k._pad = 0;
    if (bpf_map_lookup_elem(&allowed_connect_ipv4, &k) != NULL)
        return 0;

    report(cgid, HOOK_SENDMSG, in.sin_addr.s_addr);
    return -EPERM;
}
