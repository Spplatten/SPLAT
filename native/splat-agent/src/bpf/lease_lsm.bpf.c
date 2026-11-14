// SPLAT kernel canary: BPF-LSM policy that enforces a per-cgroup capability
// lease.
//
// This is the seed of Layer 3 in the SPLAT architecture. It proves the ONE
// claim the whole pitch rests on: an unconstrained agent process that steps
// outside its declared lease is stopped by the kernel with -EPERM, not by a
// user-space check it could skip.
//
// Enforcement is deliberately keyed on inode identity and destination address,
// NOT on resolved path strings. Full path resolution inside a BPF program is
// racy (TOCTOU) and expensive; the honest, defensible primitive is "this exact
// inode" / "this exact destination address". The README documents that boundary
// rather than hiding it.
//
// EVERY policy key carries the cgroup id. That is not decoration. The maps were
// previously keyed by the resource alone, with the cgroup only consulted to
// decide whether policy applied AT ALL - so two concurrent leases received the
// union of each other's permissions: a mission that allow-listed
// /usr/bin/python3 silently granted it to every other leased mission, and
// revoking one lease deleted a protected-inode entry another lease was still
// relying on. A per-mission capability lease that leaks across missions is not
// a capability lease.
//
// NOTE: native/splat-canary/src/bpf/lease_lsm.bpf.c is a deliberate fork of
// this file, frozen at the shape its recorded evidence was produced against. It
// proves the primitive; this one is the daemon's.
//
// Hooks, each refusing with -EPERM:
//   bprm_check_security - only allow-listed executable inodes may exec
//   file_open           - protected inodes cannot be opened by a lease
//   socket_connect      - only allow-listed IPv4 endpoints are reachable
//   socket_sendmsg      - the same, for a datagram naming its destination
//   ptrace_access_check - a lease cannot inspect a task outside its cgroup
//   task_kill           - nor signal one
//   task_setscheduler   - nor change its scheduling or CPU affinity
//   task_setnice        - nor its nice value
//   task_setioprio      - nor its I/O priority
//   task_setrlimit      - nor its resource limits
//   unix_stream_connect - no AF_UNIX stream between two cgroups, one leased
//   unix_may_send       - nor an AF_UNIX datagram
//   socket_create       - a lease cannot create an AF_NETLINK socket
//
// A process is "leased" iff its current cgroup id is present in leased_cgroups.
// Anything outside the lease is untouched, so the host and every other workload
// are unaffected - with one exception, the two AF_UNIX hooks: they also refuse
// an unleased process reaching INTO a lease, and judge nothing else it does.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") =
    "GPL"; // BPF-LSM + ringbuf helpers require a GPL-compatible license.

#define AF_INET 2
#define AF_INET6 10
#define AF_NETLINK 16
#define EPERM 1

struct lease_state {
  __u64 deadline_ns;
  __u64 epoch;
};
// Inode identity. The (dev, ino) pair is unique across all mounts/filesystems.
struct inode_key {
  __u64 ino;
  __u32 dev;
  __u32 _pad;
};

// A policy entry belongs to ONE lease. 24 bytes, natural 8-byte alignment; the
// Rust side mirrors this layout exactly and a size assertion in lease.rs fails
// the build if the two ever drift.
struct lease_inode_key {
  __u64 cgroup_id;
  __u64 ino;
  __u32 dev;
  __u32 _pad;
};

// An approved IPv4 ENDPOINT - address and port together, 16 bytes.
//
// The port used to be absent: the lease parsed allowedEgressPorts, carried them
// in its config, and never sent them to the kernel, so an approved host was
// approved on every port it listened on. `port` is kept in network byte order
// so it compares directly against sin_port with no byte swap in the hook.
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
  // A leased task reaching a task outside its cgroup. Appended, never
  // renumbered: violation.rs and the C# KernelViolationHook read these values.
  HOOK_PTRACE = 5,
  HOOK_SIGNAL = 6,
  HOOK_SETSCHED = 7,
  HOOK_SETNICE = 8,
  HOOK_SETIOPRIO = 9,
  HOOK_SETRLIMIT = 10,
  // Local IPC. For the two AF_UNIX hooks the record is filed under the LEASE
  // involved, which is the peer's cgroup when the caller is unleased.
  HOOK_UNIX_CONNECT = 11,
  HOOK_UNIX_SEND = 12,
  HOOK_NETLINK = 13,
};

// One denial, as the daemon reads it: 56 bytes, 8-byte alignment, mirrored by
// RawViolationEvent in violation.rs with a size assertion. The record used to
// carry no time and no number, so a consumer could neither say when a denial
// happened nor tell that one had been lost.
struct violation_event {
  __u64 cgroup_id;
  __u64 ktime_ns; // bpf_ktime_get_ns() at the denial: the kernel's monotonic
                  // clock, not wall time
  __u64 seq; // taken from `counters` BEFORE the reservation, so a number never
             // delivered was dropped
  __u32 pid;    // the denied process, as its own pid namespace numbers it
  __u32 hook;   // enum splat_hook
  __u32 detail; // exec/open: inode number (low 32 bits); connect: destination
                // IPv4 (network byte order); task hooks: the target process,
                // numbered as `pid` is; AF_UNIX hooks: the peer socket's inode
                // number (low 32 bits); netlink: the protocol asked for
  char comm[16];
};

enum splat_counter {
  COUNTER_NEXT_SEQ =
      0, // the next sequence number; every denial takes one, delivered or not
  COUNTER_DROPPED =
      1, // denials the ring buffer had no room for. The -EPERM still happened
  COUNTER_MAX,
};

// Two words the daemon reads back: how many denials have been numbered and how
// many were never delivered. A denial the buffer dropped used to vanish without
// a trace; now it leaves a gap in the sequence and a count here.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, COUNTER_MAX);
  __type(key, __u32);
  __type(value, __u64);
} counters SEC(".maps");

// cgroup id -> deadline and reserved epoch. The deadline uses guest BOOTTIME;
// the epoch is not yet checked by the kernel and is not a generation guarantee.
//
// BOOTTIME does not advance while the host holds the WSL2 VM in standby, so a
// deadline measures the guest's running time, not wall time: a host sleep
// stretches a lease's wall-clock life by the length of the sleep.
//
// 256 is the daemon's lease capacity, LEASE_CAPACITY in identities.rs. The
// session limit and the private UID pool are both sized to it, so no admitted
// lease lacks an identity and no identity is reserved for a lease this map
// could never hold.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u64);
  __type(value, struct lease_state);
} leased_cgroups SEC(".maps");

// Inodes a given lease's processes may NOT open (e.g. /etc/shadow captured at
// lease time). Entries are per-lease, so revoking one lease cannot remove a
// protection another still holds. Sized for the 256 concurrent leases
// leased_cgroups admits, times a realistic protected set.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, struct lease_inode_key);
  __type(value, __u8);
} protected_inodes SEC(".maps");

// The only executable inodes a given lease may exec. Everything else is denied
// - including a binary some OTHER concurrent lease was granted.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, struct lease_inode_key);
  __type(value, __u8);
} allowed_exec_inodes SEC(".maps");

// Opt-in execution in ONE child-mounted overlay, never the host's backing
// filesystem. The privileged pre-exec child registers its fresh superblock
// before dropping privilege; the descriptor is close-on-exec. A cgroup cannot
// borrow another lease's scratch permission.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u64);
  __type(value, __u32);
} scratch_exec_devs SEC(".maps");

// The only IPv4 destinations (network byte order, /32) a given lease may
// connect() to.
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

// cgroup id -> how many denials this lease has caused. The ring buffer is how a
// denial is DESCRIBED; this is how many there were, and the two are not the
// same number once a record is dropped or a frame arrives after the caller has
// stopped reading.
//
// Without it the daemon could only report what it managed to forward, so a
// lease whose evidence was incomplete looked exactly like a lease that was
// never denied anything. On 2026-09-25 the root probe scored
// `udp_outside_the_lease_blocked` false while that same run's violation list
// held the denial: the kernel refused the datagram and the frame did not reach
// the session. The wall held and the receipt did not, which for this product is
// the worse half to get wrong.
//
// Keyed by cgroup because that is what the hooks have in hand. The daemon
// deletes the entry when it revokes the lease, so this map holds live leases
// only and cannot outgrow leased_cgroups.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, __u64);
  __type(value, __u64);
} violation_counts SEC(".maps");

enum lease_status {
  LEASE_UNPOLICIED = 0,
  LEASE_ACTIVE = 1,
  LEASE_EXPIRED = 2,
};

// Distinguish expiry denials from ordinary policy denials in retained evidence.
#define HOOK_EXPIRED_FLAG 0x100

static __always_inline enum lease_status check_lease(__u64 cgid) {
  struct lease_state *st = bpf_map_lookup_elem(&leased_cgroups, &cgid);
  if (!st) {
    return LEASE_UNPOLICIED;
  }
  __u64 now = bpf_ktime_get_boot_ns();
  if (now >= st->deadline_ns) {
    return LEASE_EXPIRED;
  }
  return LEASE_ACTIVE;
}

// A process id as the task's own pid namespace numbers it, which is the number
// the daemon, the lease and the operator's `ps` all use. task->tgid and
// bpf_get_current_pid_tgid() give the kernel's global id instead, and on WSL2
// every distro runs in a pid namespace of its own, so the two differ there: the
// 2026-11-09 root run's receipts named lease B as 1208 while B, its pid file
// and the probe all knew it by another number. On a host whose daemon runs in
// the initial namespace, level is 0 and this is the global id.
static __always_inline __u32 task_ns_tgid(struct task_struct *t) {
  struct pid *pid = BPF_CORE_READ(t, group_leader, thread_pid);
  unsigned int level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static __always_inline void report(__u64 cgid, __u32 hook, __u32 detail) {
  __u32 seq_key = COUNTER_NEXT_SEQ;
  __u32 dropped_key = COUNTER_DROPPED;
  __u64 *next_seq = bpf_map_lookup_elem(&counters, &seq_key);
  __u64 *dropped = bpf_map_lookup_elem(&counters, &dropped_key);
  if (!next_seq || !dropped) // An array lookup inside max_entries cannot fail;
                             // the verifier still asks.
    return;

  // Numbered before the reservation, so a dropped denial still consumes its
  // number and the gap is visible to a consumer. Two CPUs may deliver
  // neighbouring numbers out of order; a number that never arrives at all was
  // dropped, and `dropped` says how many.
  __u64 seq = __sync_fetch_and_add(next_seq, 1);

  // Counted before the reservation too, and for this cgroup alone. This is the
  // number the lease's receipt is checked against: a caller that received fewer
  // frames than this was told less than the kernel did, and the EXIT frame says
  // so rather than leaving the gap invisible.
  __u64 *seen = bpf_map_lookup_elem(&violation_counts, &cgid);
  if (seen) {
    __sync_fetch_and_add(seen, 1);
  } else {
    __u64 one = 1;
    // BPF_NOEXIST: two CPUs denying the first action of the same lease at once
    // must not each install a 1 and lose the other's. The loser's update fails
    // and its denial is added below.
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
  e->pid = task_ns_tgid((struct task_struct *)bpf_get_current_task());
  e->hook = hook;
  e->detail = detail;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  bpf_ringbuf_submit(e, 0);
}

static __always_inline struct inode_key inode_key_of(struct inode *inode) {
  struct inode_key k = {};
  k.ino = BPF_CORE_READ(inode, i_ino);
  k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
  k._pad = 0;
  return k;
}

static __always_inline struct lease_inode_key
lease_inode_key_of(__u64 cgid, struct inode *inode) {
  struct lease_inode_key k = {};
  k.cgroup_id = cgid;
  k.ino = BPF_CORE_READ(inode, i_ino);
  k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
  k._pad = 0;
  return k;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(splat_bprm_check, struct linux_binprm *bprm, int ret) {
  if (ret !=
      0) // An earlier LSM already denied; never override a deny into an allow.
    return ret;

  __u64 cgid = bpf_get_current_cgroup_id();
  enum lease_status st = check_lease(cgid);
  if (st == LEASE_UNPOLICIED) {
    return 0;
  }
  if (st == LEASE_EXPIRED) {
    report(cgid, HOOK_EXEC | HOOK_EXPIRED_FLAG, 0);
    return -EPERM;
  }

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

  // Keyed by THIS lease. A binary another concurrent mission was granted is not
  // on this mission's allow-list, which is the whole point of a per-mission
  // lease.
  struct lease_inode_key k = lease_inode_key_of(cgid, inode);
  if (bpf_map_lookup_elem(&allowed_exec_inodes, &k) != NULL)
    return 0; // On this lease's allow-list: permit.

  __u32 *scratch_dev = bpf_map_lookup_elem(&scratch_exec_devs, &cgid);
  if (scratch_dev && *scratch_dev == k.dev &&
      BPF_CORE_READ(inode, i_sb, s_magic) ==
          0x794c7630) // OVERLAYFS_SUPER_MAGIC
    return 0;

  report(cgid, HOOK_EXEC, (__u32)k.ino);
  return -EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(splat_file_open, struct file *file, int ret) {
  if (ret != 0)
    return ret;

  __u64 cgid = bpf_get_current_cgroup_id();
  enum lease_status st = check_lease(cgid);
  if (st == LEASE_UNPOLICIED) {
    return 0;
  }
  if (st == LEASE_EXPIRED) {
    report(cgid, HOOK_OPEN | HOOK_EXPIRED_FLAG, 0);
    return -EPERM;
  }

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
int BPF_PROG(splat_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen, int ret) {
  if (ret != 0)
    return ret;

  __u64 cgid = bpf_get_current_cgroup_id();
  enum lease_status st = check_lease(cgid);
  if (st == LEASE_UNPOLICIED) {
    return 0;
  }
  if (st == LEASE_EXPIRED) {
    report(cgid, HOOK_CONNECT | HOOK_EXPIRED_FLAG, 0);
    return -EPERM;
  }

  sa_family_t family = BPF_CORE_READ(address, sa_family);

  // IPv6 is DENIED outright for a leased process, not waved through.
  //
  // There is no v6 allow-list - the lease speaks in IPv4 /32s - so every
  // AF_INET6 connect used to return 0 here and reach the network unpoliced.
  // That made `allowNetwork: false` mean "no IPv4", which is not what it says,
  // and left a dual-stacked host one getaddrinfo away from egress. Denying is
  // the only answer that matches the policy vocabulary; allowing v6
  // destinations needs a v6 allow-list, and until there is one there is nothing
  // to check an address against.
  if (family == AF_INET6) {
    report(cgid, HOOK_CONNECT, 0);
    return -EPERM;
  }

  // AF_UNIX is not judged here. This hook sees the address, before the path
  // lookup; unix_stream_connect and unix_may_send below see the peer the lookup
  // resolved to, so a symlink cannot point a judged name somewhere else.
  if (family != AF_INET)
    return 0;

  // An AF_INET address shorter than a sockaddr_in has no destination in it to
  // check. Reading one anyway would judge bytes past the caller's buffer, so it
  // is refused rather than guessed.
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
// `sendto()` on an unconnected UDP socket names the address in the message
// rather than on the socket, so no connect happens and the hook above never
// fires. That left every leased process a full UDP path out - DNS included -
// while `allowNetwork: false` read as "no network". The same allow-list answers
// both: a datagram destination is an endpoint like any other.
//
// A message with NO destination of its own is on a connected socket, which
// socket_connect already judged at connect time; judging it again here would
// deny nothing new and cost a lookup per datagram on an already-approved path.
SEC("lsm/socket_sendmsg")
int BPF_PROG(splat_socket_sendmsg, struct socket *sock, struct msghdr *msg,
             int size, int ret) {
  if (ret != 0)
    return ret;

  __u64 cgid = bpf_get_current_cgroup_id();
  enum lease_status st = check_lease(cgid);
  if (st == LEASE_UNPOLICIED) {
    return 0;
  }
  if (st == LEASE_EXPIRED) {
    report(cgid, HOOK_SENDMSG | HOOK_EXPIRED_FLAG, 0);
    return -EPERM;
  }
  void *name = BPF_CORE_READ(msg, msg_name);
  if (!name)
    return 0; // Connected socket: socket_connect settled this one.

  int namelen = BPF_CORE_READ(msg, msg_namelen);

  // The kernel copied this sockaddr in before the hook ran
  // (move_addr_to_kernel), so it is kernel memory and its length is the one the
  // kernel accepted, not the caller's claim.
  struct sockaddr_in in = {};
  if (namelen < (int)sizeof(in)) {
    // Too short to hold an IPv4 destination. It may still be an AF_UNIX path,
    // which unix_may_send judges by its peer, so read only the family and
    // decide on that.
    sa_family_t short_family = 0;
    if (bpf_probe_read_kernel(&short_family, sizeof(short_family), name) != 0)
      return 0;
    if (short_family != AF_INET && short_family != AF_INET6)
      return 0;
    report(cgid, HOOK_SENDMSG, 0);
    return -EPERM;
  }

  if (bpf_probe_read_kernel(&in, sizeof(in), name) != 0)
    return 0; // Unreadable: nothing to judge, and the connect hook still guards
              // connected paths.

  if (in.sin_family == AF_INET6) {
    report(cgid, HOOK_SENDMSG,
           0); // As connect does: no v6 vocabulary, so no v6 destination.
    return -EPERM;
  }
  if (in.sin_family != AF_INET)
    return 0; // AF_UNIX: unix_may_send judges the resolved peer.

  struct lease_ipv4_key k = {};
  k.cgroup_id = cgid;
  k.addr =
      in.sin_addr.s_addr; // network byte order, as the connect hook keys it
  k.port = in.sin_port;
  k._pad = 0;
  if (bpf_map_lookup_elem(&allowed_connect_ipv4, &k) != NULL)
    return 0;

  report(cgid, HOOK_SENDMSG, in.sin_addr.s_addr);
  return -EPERM;
}

// Cross-lease isolation: a leased task may act on another task only when both
// are in the SAME cgroup.
//
// The four hooks above police what a lease reaches in the filesystem and on
// the network; none of them sees one task acting on another. The 2026-10-12
// root run recorded what that left open: two ordinary leases at one uid, and
// lease A signalled lease B and read B's private workspace through
// /proc/<pid>/cwd (evidence/lease-isolation-before.json). Per-lease uids now
// stop that at the DAC check, but DAC holds only while every lease has its own
// uid and no capability. These hooks run after DAC and decide on the cgroup
// alone, so a shared uid, a reused one, or CAP_KILL or CAP_SYS_PTRACE inside a
// lease does not reopen the path.
//
// The rule is cross-CGROUP, not cross-lease: another lease and an unleased
// host process are refused alike. An unleased actor is never policed, which is
// what lets the daemon reap a lease, and what keeps the cost to the rest of
// the system at one hash lookup per signal or ptrace check - task_kill and
// ptrace_access_check fire system-wide, not only for leases.
//
// An expired lease is policed identically. The decision does not depend on
// the deadline, so these denials never carry HOOK_EXPIRED_FLAG ("refused
// because the lease had expired"). Teardown is never blocked: the reaper is
// unleased, and cgroup.kill signals with SEND_SIG_PRIV, which skips task_kill.
//
// Two things the rule depends on, which the daemon's jail provides because no
// program here can:
//   - no CAP_PERFMON in a lease. perf_event_open() on a pid skips the ptrace
//     check entirely for a CAP_PERFMON caller, and mm_access() hands such a
//     caller another task's environ and maps after this program refused it
//     (seen 2026-11-09, from root). The jail empties the bounding set, so no
//     exec can grant it.
//   - /proc mounted hidepid=ptraceable. /proc/<pid>/status, cmdline and stat
//     are world-readable and reach no hook at all; hidepid routes the lookup
//     itself through ptrace_access_check.
//
// Not covered, and listed in SUPPORTED_POLICY.md: SIGIO and SIGURG through a
// file whose owner was set to another task (file_send_sigiotask sees whoever
// triggered the I/O, not who set the owner), and the credentials and cgroup id
// that PIDFD_GET_INFO returns with no LSM hook in its path.

// The target's cgroup v2 id, through the chain bpf_get_current_cgroup_id()
// reads for the caller: task->cgroups->dfl_cgrp->kn->id. BPF_CORE_READ goes
// through bpf_probe_read_kernel, so no pointer in the chain has to be trusted;
// a read that faults yields 0, which is no lease's cgroup, and is refused.
static __always_inline __u64 task_cgroup_id(struct task_struct *t) {
  return BPF_CORE_READ(t, cgroups, dfl_cgrp, kn, id);
}

static __always_inline int guard_cross_cgroup(struct task_struct *target,
                                              __u32 hook) {
  __u64 cgid = bpf_get_current_cgroup_id();
  // Presence, not the deadline: live and expired leases are policed the same.
  if (!bpf_map_lookup_elem(&leased_cgroups, &cgid))
    return 0; // Unleased: the host, the daemon, the reaper.
  if (task_cgroup_id(target) == cgid)
    return 0; // Its own processes: a lease signals and waits on its children.
  report(cgid, hook, task_ns_tgid(target));
  return -EPERM;
}

// PTRACE_ATTACH and SEIZE, process_vm_readv and writev, pidfd_getfd, kcmp,
// /proc/<pid>/{mem,environ,maps,fd,cwd,root,...} and, under hidepid, every
// /proc/<pid> lookup all pass through __ptrace_may_access. Threads of one
// process never reach the hook (same_thread_group returns first), and they
// share a cgroup, so the set allowed is the same.
SEC("lsm/ptrace_access_check")
int BPF_PROG(splat_ptrace_access, struct task_struct *child, unsigned int mode,
             int ret) {
  if (ret != 0)
    return ret;
  return guard_cross_cgroup(child, HOOK_PTRACE);
}

// kill, tkill, tgkill, rt_sigqueueinfo, rt_tgsigqueueinfo and
// pidfd_send_signal, none of which ptrace_access_check sees. A signal the
// kernel sends for itself (SIGCHLD to the daemon, anything SEND_SIG_PRIV)
// never comes here, so a lease's exit still reaches its parent.
SEC("lsm/task_kill")
int BPF_PROG(splat_task_kill, struct task_struct *p,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret) {
  if (ret != 0)
    return ret;
  // A non-NULL cred is a signal sent for a credential the kernel recorded
  // earlier - USB async I/O completing, possibly in softirq - so `current` is
  // whatever task was interrupted, not the sender, and its cgroup says nothing
  // about who signalled. The jail exposes no USB device, so no lease arms it.
  // kill() and every other syscall pass NULL (check_kill_permission).
  //
  // The word is read as a number, never tested as `cred`. The verifier types a
  // hook's pointer arguments as trusted and therefore never NULL, so to it
  // `if (cred)` is always true; it deleted the cgroup check below as dead code
  // and this program allowed every signal. The 2026-11-09 root run caught it:
  // root inside one lease signalled another while every other hook held.
  __u64 cred_word = 0;
  bpf_probe_read_kernel(&cred_word, sizeof(cred_word), &ctx[3]);
  if (cred_word)
    return 0;
  return guard_cross_cgroup(p, HOOK_SIGNAL);
}

// sched_setscheduler, sched_setparam, sched_setattr and sched_setaffinity on
// another task: degrading or pinning another lease's CPU. Joining a cgroup
// can call this hook too, but with the joiner's OLD cgroup as the actor, so
// the daemon's pre-exec child is still unleased when it joins.
SEC("lsm/task_setscheduler")
int BPF_PROG(splat_task_setsched, struct task_struct *p, int ret) {
  if (ret != 0)
    return ret;
  return guard_cross_cgroup(p, HOOK_SETSCHED);
}

// setpriority() on another task. Writing /proc/<pid>/autogroup also calls this
// hook, but with the WRITER as the task, so that path is judged against the
// writer's own cgroup and allowed; hidepid is what keeps another lease's
// /proc/<pid> out of reach.
SEC("lsm/task_setnice")
int BPF_PROG(splat_task_setnice, struct task_struct *p, int nice, int ret) {
  if (ret != 0)
    return ret;
  return guard_cross_cgroup(p, HOOK_SETNICE);
}

// ioprio_set() on another task.
SEC("lsm/task_setioprio")
int BPF_PROG(splat_task_setioprio, struct task_struct *p, int ioprio,
             int ret) {
  if (ret != 0)
    return ret;
  return guard_cross_cgroup(p, HOOK_SETIOPRIO);
}

// prlimit64() writing another task's limits. task_prlimit, the gate before it,
// is handed credentials rather than a task, so it cannot be keyed on the
// target's cgroup; this hook can.
SEC("lsm/task_setrlimit")
int BPF_PROG(splat_task_setrlimit, struct task_struct *p,
             unsigned int resource, struct rlimit *new_rlim, int ret) {
  if (ret != 0)
    return ret;
  return guard_cross_cgroup(p, HOOK_SETRLIMIT);
}

// Local IPC: an AF_UNIX connection or datagram between two DIFFERENT cgroups
// is refused when either side is leased (docs/LOCAL-IPC-POLICING.md).
//
// It is the cross-cgroup rule above, applied to socket peers. Pathname sockets
// were already mostly out of reach, because the jail exposes no directory a
// host daemon listens in. Abstract names were not: they belong to the network
// namespace, which every lease shares with the guest because egress policing
// depends on it, so every abstract listener in the guest was one connect()
// away, and two leases could open a channel the task hooks never saw.
//
// The rule is SYMMETRIC, and this is the one place the program judges an
// unleased caller: nothing outside a lease may connect or send into it. Without
// that half a lease could bind an abstract name a host tool expects and be
// handed what the tool sends. Unleased-to-unleased traffic is never judged,
// and both hooks fire system-wide - unix_may_send on every datagram, every
// /dev/log line included - so the common path is one probe-read chain and at
// most two hash lookups.
//
// Like the task hooks, the decision does not depend on the deadline, so these
// denials never carry HOOK_EXPIRED_FLAG.
//
// Not covered (docs/LOCAL-IPC-POLICING.md, "What stays open"): a lease binding
// an abstract name before the host daemon that wants it - it receives nothing,
// but the daemon's bind fails - and /proc/net. A stream a lease inherited
// already connected is not judged either, since no hook sees a stream send;
// the daemon hands a workload stdin, stdout and stderr and nothing else.

// The cgroup a socket was CREATED in: sk_cgrp_data is set once, by
// cgroup_sk_alloc(), to its creator's default-hierarchy cgroup, and kn->id is
// the id bpf_get_current_cgroup_id() returns. So the peer names its own lease
// and the rule needs no map of its own. A read that faults yields 0, which is
// no cgroup's id: a leased caller is then refused and an unleased one allowed.
static __always_inline __u64 sock_cgroup_id(struct sock *sk) {
  return BPF_CORE_READ(sk, sk_cgrp_data.cgroup, kn, id);
}

static __always_inline int guard_unix_peer(struct sock *peer, __u32 hook) {
  __u64 actor = bpf_get_current_cgroup_id();
  __u64 other = sock_cgroup_id(peer);
  if (actor == other)
    return 0; // One cgroup: a lease talking to itself, or two host processes.
  // Presence, not the deadline, as guard_cross_cgroup reads it.
  int actor_leased = bpf_map_lookup_elem(&leased_cgroups, &actor) != NULL;
  if (!actor_leased && !bpf_map_lookup_elem(&leased_cgroups, &other))
    return 0; // Neither side is a lease.
  // Filed under the lease involved, so its session carries the receipt even
  // when the refused caller was a host process; pid and comm name that caller.
  report(actor_leased ? actor : other, hook,
         (__u32)BPF_CORE_READ(peer, sk_socket, file, f_inode, i_ino));
  return -EPERM;
}

// SOCK_STREAM and SOCK_SEQPACKET connect(), pathname and abstract, from a
// syscall or io_uring. `other` is the listener the lookup resolved to, held
// under its state lock; this program does not sleep. socketpair(2) never comes
// here.
SEC("lsm/unix_stream_connect")
int BPF_PROG(splat_unix_connect, struct sock *sock, struct sock *other,
             struct sock *newsk, int ret) {
  if (ret != 0)
    return ret;
  return guard_unix_peer(other, HOOK_UNIX_CONNECT);
}

// SOCK_DGRAM: connect(), and every send, to a named peer or a connected one.
// `other` is never tested for NULL - the verifier would delete the branch, as
// it did in task_kill - and its sock is read with a probe read, not trusted.
SEC("lsm/unix_may_send")
int BPF_PROG(splat_unix_send, struct socket *sock, struct socket *other,
             int ret) {
  if (ret != 0)
    return ret;
  return guard_unix_peer(BPF_CORE_READ(other, sk), HOOK_UNIX_SEND);
}

// A lease cannot create an AF_NETLINK socket, whatever the protocol. It holds
// no capability, so everything that changes kernel state was already refused;
// what this closes is the read-only dumps (every interface, address and socket
// in the guest) and the parser of every netlink family as attack surface. The
// cost is `ip`, `hostname -I` and getifaddrs(), accepted by the operator on
// 2026-11-13; getaddrinfo() falls back and still resolves.
//
// A socket the kernel opens for itself (kern != 0) is not a lease's request,
// whatever task it happened to be created under.
SEC("lsm/socket_create")
int BPF_PROG(splat_socket_create, int family, int type, int protocol, int kern,
             int ret) {
  if (ret != 0)
    return ret;
  if (family != AF_NETLINK || kern)
    return 0;
  __u64 cgid = bpf_get_current_cgroup_id();
  // Presence, not the deadline: an expired lease gets no netlink either.
  if (!bpf_map_lookup_elem(&leased_cgroups, &cgid))
    return 0;
  report(cgid, HOOK_NETLINK, (__u32)protocol);
  return -EPERM;
}
