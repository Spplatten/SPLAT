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
| IPv4 datagrams | `socket_sendmsg` | The same allow-list, for a datagram that names its own destination — a `sendto` on an unconnected socket, which never reaches `socket_connect`. A message with no destination of its own is on a socket `connect` already judged. **Consequence: a leased tool's DNS query is a destination like any other.** A lease with the network on and no resolver on port 53 can reach its addresses by IP and cannot look a name up; `doctor` says so, and nothing adds a resolver on the caller's behalf. |
| IPv6 egress | `socket_connect`, `socket_sendmsg` | **Denied outright** for a leased process. The lease vocabulary has no v6 allow-list, so there is nothing an address could be checked against. |

Policy is keyed per lease. Two concurrent missions do not see each other's permissions, and
revoking one does not remove an entry another still holds.

## Enforced by the daemon, not the kernel

| Dimension | Where | What is checked |
| --- | --- | --- |
| The workload's root | mount namespace and `pivot_root`, in `pre_exec` | A root holding `/usr`, `/bin`, `/sbin`, `/lib*` and `/etc` read-only, the working directory, a fresh `/tmp`, `/proc` and six device nodes. `/home`, `/root`, `/mnt`, `/var`, `/opt` and `/sys` are absent, not hidden. **Built 2026-09-20, pending the root probe** - see the note below. |
| `readOnlyFs` | the same | The working directory bound read-only as well. Refused only by a daemon that is not enforcing, which jails nothing. |
| Memory, CPU, PID ceilings | cgroup v2 | Written to `memory.max`, `cpu.max`, `pids.max`, then **read back**; a controller that did not take the clamp fails the request. |
| Lease lifetime | expiry reaper | On expiry the cgroup is killed and drained *before* its policy is withdrawn. |
| Caller identity | protocol 3 handshake | A root-owned 0600 shared secret that never crosses the wire. Every connection opens with `HELLO`, and the daemon answers with an HMAC-SHA256 over the caller's nonce and its own, which the caller checks before it sends anything more. Every request then travels in an `AUTHENTICATED` frame whose proof covers both nonces, its place on the connection and its exact bytes, checked in fixed time before the request is parsed. Required on **every** request, `HEALTH_CHECK` included since 2026-09-11: that answer carries `enforcing`, the kernel version and the live lease count, so leaving it open told an unauthenticated caller exactly when this daemon would run work it cannot contain. Since 2026-09-23 the answers prove themselves too: a caller that asks in its `HELLO` receives every later frame in a `PROVEN` wrapper whose proof covers both nonces, the frame's number on the connection and its exact bytes, and the `CHALLENGE` that agreed to it is proven under a label of its own, so the agreement cannot be stripped off in transit. A caller that does not ask is answered unwrapped, as before. |
| Workload privilege | `pre_exec` | `setgroups` / `setresgid` / `setresuid` before exec; a drop that fails fails the spawn. |
| A mission's workspace | `ephemeralWorkspace`, before the cgroup exists | A governed mission's working directory, made by the daemon directly under its missions root (`--missions-root`, default `/var/lib/splat/missions`), one path component named like a mission id, owned by the workload at mode 0700, and removed after the workload exits and its cgroup is drained; `EXIT` says whether it went. A request refused after the directory was made - a lease that could not be installed, a command outside its own lease, a jail that could not be prepared - removes it with the refusal and says so on the same `EXIT`. A request naming a workspace anywhere else is refused before anything is made. The `LEASE` frame that follows reports the cgroup, the clamps its controllers took, whether the daemon is enforcing, the jail, the workspace and the workload's uid, so the bridge records what was installed rather than what was asked. **Built 2026-09-24, pending the root probe.** |
| Outcome attribution | `outcome.rs`, an RSA key at `/etc/splat/outcome.key`, root-owned 0600 | Every `EXIT` carries the guest's signature over a fixed-order text naming what the lease did: mission, cgroup, whether the daemon was enforcing, the workload's uid, the exit code, the kernel's denial count and how much of it was reported, and the workspace's fate. What it proves is narrow and worth stating: the text came from a process holding this guest's key, so nothing between the guest and a bundle altered it. It does **not** prove the guest is honest - root in the guest can sign a lie, which is the same boundary named under **Not policed** below. RSA rather than Ed25519 because the bundle's own `verify_proofs.py` and `verify_proofs.ps1` already check PKCS#1 v1.5 with nothing but their standard libraries; a second primitive would mean hand-rolled curve arithmetic in three languages for a stranger to trust. A daemon that cannot establish a key still contains, and says its outcomes are unsigned. **Built 2026-09-25, pending the root probe.** |
| Command coherence | request | A command absent from its own lease's `allowedExecPaths` is refused before it reaches the kernel. |
| The lease ceiling | `/etc/splat/policy.json`, root-owned, read at startup | The most any lease may name on this host, whoever holds the token: executables under the listed directories only, endpoints from the listed set (or unbounded when the file names none), paths always protected, a duration and clamps the request can only lower. A request outside it is refused before a cgroup exists. Written by `splat-mcp provision --apply [--egress ...]`; absent, the daemon says so at startup and in `HEALTH_RESPONSE`. A file that is not root's or that others can write stops the daemon from starting. |

## Refused — the daemon will not accept these

| Field | Why |
| --- | --- |
| `overlayFs.enableCow: true` | The overlay is not yet mounted inside the workload's namespace. `cow.rs` holds the mount code and `jail.rs` now holds the namespace; joining them, so the merged directory is the working directory the jail binds, is the next step. |
| `protocolVersion` ≠ 3 | A version 1 envelope carried arguments as a pre-quoted string that the daemon then split on whitespace. There is no correct way to reconstruct it here. |
| A first frame that is not a `HELLO`, or a request outside an `AUTHENTICATED` frame | Protocol 2 put the token itself in every request, so a caller handed it to whatever answered on the port — and while the daemon was down, any process in the guest could answer. Refused even with the right token, so capturing one is worth nothing, and the connection is closed. |
| Any `argv` that is not an array | Same reason. |
| A request frame over **1 MiB** | The frame is read through a cap and the connection is closed. `read_line` grows until it meets a newline, and that ran *before* the auth check — so anything that could open the socket could make a root process allocate without bound by never sending one. The tail is not re-read: parsing on from the middle of a refused frame would turn it into a series of accepted ones. |
| Anything outside the lease ceiling, when the guest has one | An executable outside its directories, an endpoint outside its set, a path with `..`. Refused in the ceiling's own words, naming the first thing outside it. The token proves who is asking; it does not raise what may be asked for. |
| A missing `allowedExecPaths`, or a missing `allowedEgressIps` / `allowedEgressPorts` while `allowNetwork` is true | These used to take a default the daemon chose — 127.0.0.1 on ports 80 and 443, and `/bin/sh`, `/bin/ping`, `/usr/bin/curl` — so a caller that omitted a field received a lease wider than it asked for, and the kernel enforced that faithfully. An **empty** list is still accepted and means "nothing permitted": that is a decision. A missing key is the absence of one. |

## Not policed, and not claimed to be

These are reachable by a leased process. They are listed so nobody has to discover them.

| Gap | Consequence |
| --- | --- |
| **AF_UNIX / AF_NETLINK** | Local IPC is untouched. A per-socket allow-list keyed on the socket's inode is the real answer and does not exist. A leased tool can talk to any local daemon socket its uid can reach — including a resolver that answers over one, which is how a name lookup can still succeed on a host where `systemd-resolved` is reached that way rather than over UDP. |
| **Raw and packet sockets** | Creating one needs `CAP_NET_RAW`, which a workload dropped to `nobody` does not have, so nothing policies it and nothing needs to. Not a claim about a workload that keeps capabilities: this daemon does not run one. |
| **Inherited file descriptors** | The hooks fire on `open` and `connect`. A descriptor the tool inherits was opened by the daemon, before any of them ran. |
| **Filesystem writes and reads outside the jail's contents** | Closed by the jail since 2026-09-20, pending its proof: the workload's root holds the system directories read-only, its working directory, a fresh `/tmp`, `/proc` and six device nodes, and nothing else. `/etc` travels whole and read-only; what `nobody` may not read there is still denied by mode, and the inode deny-list still applies inside the jail because bind mounts keep inode identity. Until the probe has run, treat the deny-list as the boundary it was: on 2026-09-18, `nobody` read a public key in the Windows user's `.ssh` folder through `/mnt/c`. Two things close that today: `/mnt` is absent from the jail, and `splat-mcp provision --apply` now writes the `[automount]` umask of 077 into the guest's `/etc/wsl.conf` when it is missing, which shuts `nobody` out of the Windows drives for anything not jailed once WSL restarts. |

## What has been proven, and where

Everything in the two "enforced" tables above is proven against a root daemon on kernel
6.18.33.2, in one run, recorded in `evidence/daemon-probe.json`. That file carries the SHA-256 of
the BPF source it exercised, and `DocumentationDriftTests` fails the build if the README claims
enforcement while the hash does not match what ships — so the proof cannot outlive the program.

> **Pending since 2026-09-20.** The program changed that day — each denial record gained the
> kernel's clock, a sequence number and a drop counter, and the connect hook refuses an AF_INET
> address too short to hold one — so the daemon and last-hop evidence below name the program as it
> was, not as it ships. The same day the daemon gained the jail above, which `probe-daemon.sh` now
> checks with five results of its own, none yet recorded. On 2026-09-24 the daemon gained the
> mission workspace and the `LEASE` frame above, which no root run has seen either. The README's
> claims are withdrawn until `probe-daemon.sh` and `probe-last-hop.ps1` are re-run under root;
> `docs/GUIDE-operator.md` has the steps.

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
