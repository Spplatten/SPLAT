# What a SPLAT lease actually enforces

The daemon accepts a policy envelope with a dozen fields. Some are enforced by the kernel, some are
enforced by the daemon in userspace, and some it cannot enforce at all. This file is the difference,
and it is the list the daemon refuses against: a request naming something in the **Refused** section
is turned away rather than accepted and dropped.

That distinction is the whole point. A field parsed into a lease and then ignored is worse than an
absent feature, because the caller reads its own request back as accepted — which is how
`readOnlyFs` and `overlayFs.enableCow` travelled on every compiled template for months while
nothing on the far end consumed either one.

Protocol version 2. Anything else is refused; see `main.rs`.

---

## Enforced in the kernel (BPF-LSM)

| Dimension | Hook | What is checked |
| --- | --- | --- |
| Executable identity | `bprm_check_security` | `(cgroup id, dev, ino)` against this lease's allow-list. Every exec, including one an already-running permitted tool performs. |
| Protected files | `file_open` | `(cgroup id, dev, ino)` against this lease's deny-list. |
| IPv4 egress | `socket_connect` | `(cgroup id, address, port)` — the destination must be an endpoint this lease approved. |
| IPv6 egress | `socket_connect` | **Denied outright** for a leased process. The lease vocabulary has no v6 allow-list, so there is nothing an address could be checked against. |

Policy is keyed per lease. Two concurrent missions do not see each other's permissions, and
revoking one does not remove an entry another still holds.

## Enforced by the daemon, not the kernel

| Dimension | Where | What is checked |
| --- | --- | --- |
| Memory, CPU, PID ceilings | cgroup v2 | Written to `memory.max`, `cpu.max`, `pids.max`, then **read back**; a controller that did not take the clamp fails the request. |
| Lease lifetime | expiry reaper | On expiry the cgroup is killed and drained *before* its policy is withdrawn. |
| Caller identity | `authToken` | A root-owned 0600 shared secret, compared in fixed time. |
| Workload privilege | `pre_exec` | `setgroups` / `setresgid` / `setresuid` before exec; a drop that fails fails the spawn. |
| Command coherence | request | A command absent from its own lease's `allowedExecPaths` is refused before it reaches the kernel. |

## Refused — the daemon will not accept these

| Field | Why |
| --- | --- |
| `readOnlyFs: true` | No mount namespace is established for the workload, so a read-only root cannot be imposed on it. |
| `overlayFs.enableCow: true` | The overlay would mount in the daemon's own mount namespace, and a merged directory handed to a child as its working directory is a starting point rather than a jail — the tool can `cd /` out of it. `cow.rs` holds the mount code; what is missing is `unshare(CLONE_NEWNS)` plus `pivot_root` in the pre-exec closure. |
| `protocolVersion` ≠ 2 | A version 1 envelope carried arguments as a pre-quoted string that the daemon then split on whitespace. There is no correct way to reconstruct it here. |
| Any `argv` that is not an array | Same reason. |

## Not policed, and not claimed to be

These are reachable by a leased process. They are listed so nobody has to discover them.

| Gap | Consequence |
| --- | --- |
| **UDP to an unconnected socket** | `socket_connect` does not fire for `sendto()` on an unconnected UDP socket. A `socket_sendmsg` hook would close it; it is not written, and shipping an unverified BPF program that the loader might reject would take the whole substrate down rather than tighten it. |
| **AF_UNIX / AF_NETLINK** | Local IPC is untouched. Denying it wholesale would break name resolution and logging for the shipped catalogue; a per-socket allow-list is the real answer and does not exist. A leased tool can talk to any local daemon socket its uid can reach. |
| **Inherited file descriptors** | The hooks fire on `open` and `connect`. A descriptor the tool inherits was opened by the daemon, before any of them ran. |
| **Filesystem writes outside the workspace** | The deny-list names specific inodes. It is not a jail: everything not named is reachable at the workload's uid, which is why the privilege drop matters more than the deny-list does. |
| **Ambient reads** | `file_open` denies a listed inode. It does not confine reads to an allow-list — the policy is a denylist, and a denylist is not a boundary. |

## What has been proven, and where

| Claim | Evidence |
| --- | --- |
| The kernel vetoes an out-of-lease exec, open and connect | `../splat-canary/evidence/canary-*.json` — one lease at a time, on a real BPF-LSM kernel |
| The daemon refuses to run without live enforcement | `evidence/fail-closed-probe.json` |
| An unauthenticated caller cannot execute | `evidence/peer-auth-probe.json` |
| Arguments survive the wire byte for byte | `evidence/wire-contract-probe.json` |
| The three hooks hold *through the daemon*, under root | `evidence/daemon-probe.json` — **stale**: recorded against a kernel program that has since been re-keyed per lease. Re-run `probe-daemon.sh` against a root daemon to restore it. |

Per-lease keying, the port check and the IPv6 denial are verified at the key layer and in userspace.
**None of them has been loaded into a kernel yet** — the same root run that refreshes
`daemon-probe.json` is what turns them from correct-looking into proven.
