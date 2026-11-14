# Local IPC policing: AF_UNIX and AF_NETLINK (design)

**This page is a plan. Nothing in it is built.** It is work queue item 3, the last large row in
the *Not policed* table of [SUPPORTED_POLICY.md](../native/splat-agent/SUPPORTED_POLICY.md). That
row stays as it is until a root run proves what is built from this page.

## What is open today

Measured on 2026-11-13, without root, in Ubuntu 26.04.1 on kernel 6.18.33.2.

**Pathname sockets are already mostly out of reach.** The jail's root holds `/usr`, `/bin`,
`/sbin`, `/lib*` and `/etc`, the working directory, a private `/tmp` (since #43, not yet root-proven) and `/proc`. `/run` and
`/var` are absent, and that is where host daemons keep their sockets: D-Bus, journald and
`/dev/log`, systemd-resolved, nscd, the secret broker. Not one socket exists under the
directories the jail exposes. A lease can still meet a pathname socket that is:
- in its working directory, when that is a host directory another process uses;
- one of its own, which is allowed by design.

**Abstract sockets are reachable.** An abstract AF_UNIX name (`@name`) belongs to the *network
namespace*, not the filesystem. The jail does not unshare the network namespace, because egress
policing depends on the shared one. Every abstract name bound anywhere in the guest is therefore
reachable from every lease. One was listening at the time of measurement. Two leases can also
open an abstract channel between themselves, which the cross-lease task hooks do not see.

**Netlink is open.** A lease can create any AF_NETLINK socket. It holds no capabilities, so
everything that changes kernel state is already refused (`CAP_NET_ADMIN`). What remains is:
- read-only dumps: interfaces and addresses (`NETLINK_ROUTE`), every socket in the guest
  (`NETLINK_SOCK_DIAG`) and device events;
- kernel attack surface: every netlink family's parser is reachable from inside a lease.

**`/proc/net` repeats most of what netlink tells.** With netlink refused, `ss` fell back to
`/proc/net/tcp` and still listed the daemon's port. `/proc/net` is per network namespace, so
it shows every TCP, UDP and UNIX socket in the guest, other leases' included. Neither hook below
closes that; see *What stays open*.

## The rule

**A local-socket connection or datagram between two different cgroups is refused when either side
is leased.** It is the cross-lease rule of [#39](https://github.com/Spplatten/SPLAT/pull/39),
applied to socket peers, and it is symmetric:
- a lease cannot reach a host daemon or another lease over AF_UNIX, pathname or abstract;
- nothing outside a lease can connect into it. Without that half, a lease could bind an abstract
  name a host tool expects and receive what the tool sends.

Unleased-to-unleased traffic is never judged, and neither is anything inside one lease.
socketpair(2), Python multiprocessing's `/tmp` listener (measured: it is a pathname socket in the
lease's own `/tmp`) and a tool talking to its own helper all stay allowed.

**A leased process cannot create an AF_NETLINK socket**, whatever the protocol. Sockets the kernel
opens for itself (`kern != 0`) are not judged.

There is no allow-list in v1. A lease that needs a host socket would also need the jail to bind
that socket's path in, and nothing in the catalogue asks for one. That is a separate feature,
with its own lease field and its own row in the refusal matrix.

## Hooks

All three exist in the running kernel's BTF with these arguments:

| Program | Hook | Covers |
| --- | --- | --- |
| `splat_unix_connect` | `lsm/unix_stream_connect(sock, other, newsk)` | `SOCK_STREAM` and `SOCK_SEQPACKET` connects, pathname and abstract, from a syscall or io_uring |
| `splat_unix_send` | `lsm/unix_may_send(sock, other)` | `SOCK_DGRAM`: `connect`, and every `sendto`/`sendmsg` to a named peer |
| `splat_socket_create` | `lsm/socket_create(family, type, protocol, kern)` | AF_NETLINK creation |

The peer's cgroup comes from the peer socket itself. `sk->sk_cgrp_data.cgroup` is set when the
socket is created, to its creator's cgroup (the probe confirms it), and its `kn->id` is the id `bpf_get_current_cgroup_id()`
returns. So the rule needs no new map: only `leased_cgroups`, which every program already reads.

```c
static __always_inline __u64 sock_cgroup_id(struct sock *sk) {
  return BPF_CORE_READ(sk, sk_cgrp_data.cgroup, kn, id);
}

static __always_inline int guard_unix_peer(struct sock *peer, __u32 hook) {
  __u64 actor = bpf_get_current_cgroup_id();
  __u64 other = sock_cgroup_id(peer);
  if (actor == other)
    return 0; // one cgroup: a lease talking to itself, or two host processes
  int actor_leased = bpf_map_lookup_elem(&leased_cgroups, &actor) != NULL;
  int peer_leased = bpf_map_lookup_elem(&leased_cgroups, &other) != NULL;
  if (!actor_leased && !peer_leased)
    return 0; // neither side is a lease
  // The receipt goes to the lease involved; detail names the peer socket's inode.
  report(actor_leased ? actor : other, hook,
         (__u32)BPF_CORE_READ(peer, sk_socket, file, f_inode, i_ino));
  return -EPERM;
}
```

Implementation notes:
- The two lessons of the 2026-11-09 root runs apply here too.
  - Never test a hook's pointer argument: the verifier assumes it is non-NULL and deletes the
    branch. `unix_may_send` therefore reads `other->sk` through `BPF_CORE_READ`.
  - Any pid in a receipt comes from `task_ns_tgid()`.
- `unix_stream_connect` runs with the listener's state lock held. The programs are non-sleepable
  and use only map lookups, probe reads and the ring buffer, as the other ten do.
- **Cost.** Both AF_UNIX hooks fire system-wide, and `unix_may_send` on every datagram, so on every
  `/dev/log` line any host process writes. That is one probe-read chain and up to two hash lookups
  per event. The milestone should measure it beside the `task_kill` figure.

Hook ids 11 (`HOOK_UNIX_CONNECT`), 12 (`HOOK_UNIX_SEND`) and 13 (`HOOK_NETLINK`, with the
protocol number as its detail) are appended. They need entries in `violation.rs` and in the C#
`KernelViolationHook` (bound by `KernelViolationHook_NamesEveryHookTheKernelProgramReports`). The
validator's `Hook` grows from 10 to 13. All three new hooks decide on `LeasedCgroups` alone, so
`check_bindings`' shared-map rule covers them, as it does the task hooks.

The existing `socket_connect` and `socket_sendmsg` programs keep returning 0 for AF_UNIX: the
new hooks judge the resolved peer, after the path lookup, which also defeats a symlink pointing
somewhere else.

## What breaks

Measured with `socket(AF_NETLINK)` refused by seccomp, as the hook would refuse it:

| Still works | Breaks |
| --- | --- |
| `getaddrinfo`, with `AI_ADDRCONFIG` too | `ip`, which cannot open its socket |
| `getent hosts`, `curl` | `hostname -I` |
| Python `multiprocessing` (`Pool`, forkserver start method) | Python `socket.if_nameindex()`, `getifaddrs()` users such as `psutil.net_if_addrs` |
| `ss`, which falls back to `/proc/net` | |

The AF_UNIX rule breaks nothing measured. The jail already hides every host socket path, and the
only abstract name listening in the guest is not one a tool would use.

Before building, the Linux templates in the catalogue need a census for `ip`, `hostname -I` and
interface enumeration.

## What stays open, to be listed as not policed

- `/proc/net/{tcp,udp,unix,dev,route}`: every socket and interface in the guest, other leases' too,
  readable from inside the jail. A private network namespace is the full answer, and it costs the
  egress model.
- **Abstract-name squatting.** A lease can bind an abstract name first, so a host daemon that binds
  it later fails. It cannot receive a connection on it.
- **Datagrams between processes of one lease, and their `SCM_RIGHTS`**, by design.
- **Netlink sockets the kernel opens for itself.**

## The root proof

This is a new probe section, batched into the next milestone with the private `/tmp` (#43) and a
first run inside the SPLAT Guest.

**Refused, each with EPERM and a receipt in the acting lease's session:**
- lease X connecting to a host abstract stream listener;
- lease X sending a datagram to a host abstract receiver, which must receive nothing;
- lease B connecting to lease A's abstract listener;
- an unleased process connecting into lease X's listener, with the receipt in X's session;
- lease X creating `NETLINK_ROUTE` and `NETLINK_SOCK_DIAG` sockets.

**Controls that must succeed:**
- a host client reaching the same host listeners;
- a second process inside lease X reaching X's own listener;
- an unleased process creating a netlink socket;
- `getaddrinfo("localhost", AI_ADDRCONFIG)` inside lease X.

Each refusal is scored on EPERM alone. ENOENT or ECONNREFUSED would mean the peer was not
there, not that it was refused.

## Decisions for the operator

1. **Netlink: refuse all (recommended), or allow `NETLINK_ROUTE`?** Refusing all closes the most
   kernel attack surface and matches what "network off" reads as. It costs `ip`, `hostname -I` and
   interface enumeration. Allowing `NETLINK_ROUTE` keeps them, and leaks little that `/proc/net`
   does not already show.
2. **The symmetric half (recommended: yes).** Refusing host processes that connect into a lease
   closes impersonation by an abstract name. It is the first rule in the program that judges an
   unleased caller, though only when the other side is a lease.
3. **No allow-list in v1 (recommended).** Add one, with the jail binding the socket path, only
   when a template needs a host socket.
