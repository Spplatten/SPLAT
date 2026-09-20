# What a SPLAT lease actually enforces

The daemon accepts a policy envelope with a dozen fields. Some are enforced by the kernel, some are
enforced by the daemon in userspace, and some it cannot enforce at all. This file is the difference,
and it is the list the daemon refuses against: a request naming something in the **Refused** section
is turned away rather than accepted and dropped.

That distinction is the whole point. A field parsed into a lease and then ignored is worse than an
absent feature, because the caller reads its own request back as accepted — which is how
`readOnlyFs` and `overlayFs.enableCow` travelled on every compiled template for months while
nothing on the far end consumed either one.

Protocol version 3. Anything else is refused; see `main.rs`, and `docs/SCHEMA.md` for the frames.

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
| Caller identity | protocol 3 handshake | A root-owned 0600 shared secret that never crosses the wire. Every connection opens with `HELLO`, and the daemon answers with an HMAC-SHA256 over the caller's nonce and its own, which the caller checks before it sends anything more. Every request then travels in an `AUTHENTICATED` frame whose proof covers both nonces, its place on the connection and its exact bytes, checked in fixed time before the request is parsed. Required on **every** request, `HEALTH_CHECK` included since 2026-09-11: that answer carries `enforcing`, the kernel version and the live lease count, so leaving it open told an unauthenticated caller exactly when this daemon would run work it cannot contain. |
| Workload privilege | `pre_exec` | `setgroups` / `setresgid` / `setresuid` before exec; a drop that fails fails the spawn. |
| Command coherence | request | A command absent from its own lease's `allowedExecPaths` is refused before it reaches the kernel. |

## Refused — the daemon will not accept these

| Field | Why |
| --- | --- |
| `readOnlyFs: true` | No mount namespace is established for the workload, so a read-only root cannot be imposed on it. |
| `overlayFs.enableCow: true` | The overlay would mount in the daemon's own mount namespace, and a merged directory handed to a child as its working directory is a starting point rather than a jail — the tool can `cd /` out of it. `cow.rs` holds the mount code; what is missing is `unshare(CLONE_NEWNS)` plus `pivot_root` in the pre-exec closure. |
| `protocolVersion` ≠ 3 | A version 1 envelope carried arguments as a pre-quoted string that the daemon then split on whitespace. There is no correct way to reconstruct it here. |
| A first frame that is not a `HELLO`, or a request outside an `AUTHENTICATED` frame | Protocol 2 put the token itself in every request, so a caller handed it to whatever answered on the port — and while the daemon was down, any process in the guest could answer. Refused even with the right token, so capturing one is worth nothing, and the connection is closed. |
| Any `argv` that is not an array | Same reason. |
| A request frame over **1 MiB** | The frame is read through a cap and the connection is closed. `read_line` grows until it meets a newline, and that ran *before* the auth check — so anything that could open the socket could make a root process allocate without bound by never sending one. The tail is not re-read: parsing on from the middle of a refused frame would turn it into a series of accepted ones. |
| A missing `allowedExecPaths`, or a missing `allowedEgressIps` / `allowedEgressPorts` while `allowNetwork` is true | These used to take a default the daemon chose — 127.0.0.1 on ports 80 and 443, and `/bin/sh`, `/bin/ping`, `/usr/bin/curl` — so a caller that omitted a field received a lease wider than it asked for, and the kernel enforced that faithfully. An **empty** list is still accepted and means "nothing permitted": that is a decision. A missing key is the absence of one. |

## Not policed, and not claimed to be

These are reachable by a leased process. They are listed so nobody has to discover them.

| Gap | Consequence |
| --- | --- |
| **UDP to an unconnected socket** | `socket_connect` does not fire for `sendto()` on an unconnected UDP socket. A `socket_sendmsg` hook would close it; it is not written, and shipping an unverified BPF program that the loader might reject would take the whole substrate down rather than tighten it. |
| **AF_UNIX / AF_NETLINK** | Local IPC is untouched. Denying it wholesale would break name resolution and logging for the shipped catalogue; a per-socket allow-list is the real answer and does not exist. A leased tool can talk to any local daemon socket its uid can reach. |
| **Inherited file descriptors** | The hooks fire on `open` and `connect`. A descriptor the tool inherits was opened by the daemon, before any of them ran. |
| **Filesystem writes outside the workspace** | The deny-list names specific inodes. It is not a jail: everything not named is reachable at the workload's uid, which is why the privilege drop matters more than the deny-list does. |
| **Ambient reads** | `file_open` denies a listed inode. It does not confine reads to an allow-list — the policy is a denylist, and a denylist is not a boundary. On WSL that includes the Windows drives. `/mnt/c` is mounted with every mode bit open, so the workload's `nobody` reaches the Windows user's profile: on 2026-09-18, `nobody` read a public key in that profile's `.ssh` folder and passed the read check on the private key beside it. A mount namespace without `/mnt` would close it (P2). Until then, an `[automount]` umask of 077 in the guest's `/etc/wsl.conf` shuts `nobody` out of the Windows drives; the runbook's 1.6 has the line. |

## What has been proven, and where

Everything in the two "enforced" tables above is proven against a root daemon on kernel
6.18.33.2, in one run, recorded in `evidence/daemon-probe.json`. That file carries the SHA-256 of
the BPF source it exercised, and `DocumentationDriftTests` fails the build if the README claims
enforcement while the hash does not match what ships — so the proof cannot outlive the program.

| Claim | Evidence |
| --- | --- |
| Out-of-lease exec, open and connect are vetoed **through the daemon**, under root | `evidence/daemon-probe.json` (verdict PASS, 17 checks) |
| The same holds for a request that entered through the product: an MCP client's `run_command`, through `splat-mcp` and the C# bridge | `evidence/last-hop-probe.json` (verdict PASS) — an undeclared exec and a connect outside the lease refused, with the permitted command and the permitted endpoint as controls |
| A lease dimension nobody declared is refused rather than defaulted | `evidence/daemon-probe.json` — a missing `allowedExecPaths`, and a missing egress list with the network on, are both turned away before a cgroup exists |
| A protected file is denied by the LEASE, not by file permissions | same run — a control reads `/etc/hostname` (644) unprotected, the leased run is refused with a kernel violation |
| Two concurrent leases do not lend each other permissions | same run — B is denied an executable A holds live |
| An approved host is not approved on every port | same run — `:9999` refused on a lease naming `:80` |
| IPv6 is denied rather than waved through | same run |
| The workload runs as `nobody`, not as the daemon's root | same run — `uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)` |
| Expiry kills the workload rather than unpolicing it | same run — killed 5.3s into a 60s sleep |
| The kernel vetoes an out-of-lease exec, open and connect, standalone | `../splat-canary/evidence/canary-*.json` — one lease at a time |
| The daemon refuses to run without live enforcement | `evidence/fail-closed-probe.json` |
| An unauthenticated caller cannot execute | `evidence/peer-auth-probe.json` |
| Arguments survive the wire byte for byte | `evidence/wire-contract-probe.json` |

What that run does **not** cover is everything in the *Not policed* table above. A PASS means the
declared boundary holds, not that the boundary is complete.

One thing it found that no amount of userspace testing would have: the memory, CPU and PID clamps
had never applied. `splat_leases` never delegated its controllers to its children, so
`mission_X/memory.max` did not exist, and the clamp write was discarded with `let _ = fs::write`.
The first real lease a real daemon tried to provision refused, and named the file.
