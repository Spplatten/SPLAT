// SPLAT kernel canary: BPF-LSM policy that enforces a per-cgroup capability lease.
//
// This is the seed of Layer 3 in the SPLAT architecture. It proves the ONE claim the
// whole pitch rests on: an unconstrained agent process that steps outside its declared
// lease is stopped by the kernel with -EPERM, not by a user-space check it could skip.
//
// Enforcement is deliberately keyed on cgroup id + inode identity, NOT on resolved path
// strings. Full path resolution inside a BPF program is racy (TOCTOU) and expensive; the
// honest, defensible primitive is "this exact inode" / "this exact destination address".
// The README documents that boundary rather than hiding it.
//
// Hooks:
//   bprm_check_security -> only allow-listed executable inodes may exec           (-EPERM)
//   file_open           -> protected inodes cannot be opened by a leased process  (-EPERM)
//   socket_connect      -> only allow-listed IPv4 /32 destinations are reachable  (-EPERM)
//
// A process is "leased" iff its current cgroup id is present in leased_cgroups. Anything
// outside the lease is untouched, so the host and every other workload are unaffected.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL"; // BPF-LSM + ringbuf helpers require a GPL-compatible license.

#define AF_INET 2
#define EPERM 1

// Inode identity key. In a single rootfs/mount, inode number is invariant.
struct inode_key {
    __u64 ino;
};

enum splat_hook {
    HOOK_EXEC = 1,
    HOOK_OPEN = 2,
    HOOK_CONNECT = 3,
};

struct violation_event {
    __u64 cgroup_id;
    __u32 pid;
    __u32 hook;   // enum splat_hook
    __u32 detail; // exec/open: inode number; connect: destination IPv4 (network byte order)
    char comm[16];
};

// cgroup id -> 1. Presence means "this cgroup holds a lease and is subject to policy".
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u8);
} leased_cgroups SEC(".maps");

// Inodes that a leased process may NOT open (e.g. /etc/shadow captured at lease time).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct inode_key);
    __type(value, __u8);
} protected_inodes SEC(".maps");

// The only executable inodes a leased process may exec. Everything else is denied.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct inode_key);
    __type(value, __u8);
} allowed_exec_inodes SEC(".maps");

// The only IPv4 destinations (network byte order, /32) a leased process may connect() to.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_connect_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} violations SEC(".maps");

static __always_inline __u8 is_leased(__u64 cgid)
{
    return bpf_map_lookup_elem(&leased_cgroups, &cgid) != NULL;
}

static __always_inline void report(__u64 cgid, __u32 hook, __u32 detail)
{
    struct violation_event *e = bpf_ringbuf_reserve(&violations, sizeof(*e), 0);
    if (!e)
        return;
    e->cgroup_id = cgid;
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

    struct inode_key k = inode_key_of(inode);
    if (bpf_map_lookup_elem(&allowed_exec_inodes, &k) != NULL)
        return 0; // On the allow-list: permit.

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

    struct inode_key k = inode_key_of(inode);
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

    // Only police IPv4. AF_UNIX / AF_INET6 fall through to whatever other LSMs decided.
    sa_family_t family = BPF_CORE_READ(address, sa_family);
    if (family != AF_INET)
        return 0;

    struct sockaddr_in *in = (struct sockaddr_in *)address;
    __u32 daddr = BPF_CORE_READ(in, sin_addr.s_addr); // network byte order

    if (bpf_map_lookup_elem(&allowed_connect_ipv4, &daddr) != NULL)
        return 0; // Approved egress target.

    report(cgid, HOOK_CONNECT, daddr);
    return -EPERM;
}
