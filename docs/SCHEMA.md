<!-- Companion to ARCHITECTURE-linux-substrate.md. The three contracts a lease crosses, as the code
     defines them: the kernel's binary layouts, the daemon's JSON line protocol, and the C# records
     the bridge maps them to. Layouts were measured on 2026-09-20 with clang 21 against
     lease_lsm.bpf.c as it stood that evening, after the record gained its clock, number and drop
     counter. The recorded root evidence predates that change and is pending re-run; see
     GUIDE-operator.md. Where this file and the code disagree, the code wins and this file has the
     bug. -->

# Wire protocol and contract specification — the Linux lease

A lease crosses three boundaries, and each has a different kind of contract:

| Boundary | Carried as | Held to the code by |
| --- | --- | --- |
| **A.** Kernel ↔ daemon | C structs in BPF map keys and a ring buffer record | `#[repr(C)]` mirrors in [`lease.rs`](../native/splat-agent/src/lease.rs) and [`violation.rs`](../native/splat-agent/src/violation.rs), with `const` size assertions that fail the build |
| **B.** Daemon ↔ bridge | Newline-delimited JSON over loopback TCP, protocol 3 | HMAC test vectors asserted on both sides: [`auth.rs`](../native/splat-agent/src/auth.rs) and [`WslAgentSessionTests`](../tests/MissionController.Tests/WslAgentSessionTests.cs) |
| **C.** Bridge ↔ control plane | C# records in `MissionController.Core` | [`WslLeasedExecutorWireTests`](../tests/MissionController.Tests/WslLeasedExecutorWireTests.cs), which drive the bridge against a stand-in daemon |

Only what a test or a build assertion holds is written here as a guarantee. Everything else is a
description of the code as it stands, and the last section lists what the protocol does **not**
promise.

---

## A. Kernel ↔ daemon: binary layouts

All integers are in the host's native byte order (x86-64: little-endian) **except** the two fields
copied verbatim from a `sockaddr_in`, which stay in network byte order and are compared as raw
bytes on both sides. Hash-map keys are compared byte for byte, so every `_pad` field must be zero;
both sides write it explicitly.

### `struct lease_inode_key` — key of `allowed_exec_inodes` and `protected_inodes`

24 bytes, 8-byte alignment. Value: one `__u8`, always `1`.

| Offset | Size | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `cgroup_id` | The lease. The kernfs inode number of the lease's cgroup directory, which is what `bpf_get_current_cgroup_id()` returns on the unified hierarchy |
| 8 | 8 | `ino` | `inode->i_ino` |
| 16 | 4 | `dev` | `inode->i_sb->s_dev`, packed `(major << 20) \| minor`. **Not** glibc's `st_dev`; [`kernel_dev_from_st_dev`](../native/splat-agent/src/lease.rs) converts |
| 20 | 4 | `_pad` | Zero |

### `struct lease_ipv4_key` — key of `allowed_connect_ipv4`

16 bytes, 8-byte alignment. Value: one `__u8`, always `1`.

| Offset | Size | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `cgroup_id` | The lease |
| 8 | 4 | `addr` | `sin_addr.s_addr` as it sits in memory: octets in dotted-quad order. `127.0.0.1` is the bytes `7F 00 00 01`, which a little-endian host reads as `0x0100007F` |
| 12 | 2 | `port` | `sin_port`, network byte order. Port 443 is the bytes `01 BB` |
| 14 | 2 | `_pad` | Zero |

### `leased_cgroups` — presence means policed

Key: `__u64` cgroup id, native byte order. Value: `__u8` `1`. A cgroup absent from this map is
allowed everything by every hook; that is why the daemon kills a workload **before** removing its
entry.

### `struct violation_event` — one ring-buffer record per denial

56 bytes, 8-byte alignment. Written by `report()` in [`lease_lsm.bpf.c`](../native/splat-agent/src/bpf/lease_lsm.bpf.c), read by the cast in `main.rs`.

| Offset | Size | Field | Meaning |
| --- | --- | --- | --- |
| 0 | 8 | `cgroup_id` | The lease that was denied |
| 8 | 8 | `ktime_ns` | `bpf_ktime_get_ns()` at the denial: the kernel's monotonic clock, nanoseconds since boot. Not wall time |
| 16 | 8 | `seq` | The denial's number, taken from `counters[0]` **before** the reservation. Global across every lease |
| 24 | 4 | `pid` | The thread-group id (`bpf_get_current_pid_tgid() >> 32`) |
| 28 | 4 | `hook` | `1` exec (`bprm_check_security`), `2` open (`file_open`), `3` connect (`socket_connect`), `4` datagram (`socket_sendmsg`) |
| 32 | 4 | `detail` | Exec and open: the **low 32 bits** of the inode number. Connect and datagram: the destination IPv4 address in network byte order, or `0` for an IPv6 destination or an address too short to hold one |
| 36 | 16 | `comm` | The task's `comm`, NUL-terminated within the 16 bytes |
| 52 | 4 | — | Padding. Unspecified; the reservation is not zeroed, so a consumer must not read it |

The ring buffer (`violations`) is `BPF_MAP_TYPE_RINGBUF` of 1 MiB. Records are delivered in
reservation order. When the buffer is full, `bpf_ringbuf_reserve` returns NULL and the denial is
**not recorded** — the `-EPERM` still happens — but its number was already taken, so the sequence
shows a gap, and `counters[1]` is incremented.

### `counters` — two words the daemon reads back

`BPF_MAP_TYPE_ARRAY`, key `__u32`, value `__u64`, two entries. `[0]` is the next sequence number;
`[1]` is the count of denials dropped for want of room. Both are updated with a fetching atomic
add, which is why the program is compiled for the v3 instruction set (kernel 5.12 or later).

### Map capacities

| Map | `max_entries` | What bounds it |
| --- | --- | --- |
| `leased_cgroups` | 256 | Concurrent leases |
| `protected_inodes` | 8192 | Leases × protected paths (the daemon adds two of its own to every lease) |
| `allowed_exec_inodes` | 8192 | Leases × exec paths |
| `allowed_connect_ipv4` | 4096 | Leases × addresses × ports, since the daemon installs the cross product |

A map update that fails for want of room fails the lease, which is rolled back and refused rather
than installed partially ([`LeaseManager::register_lease`](../native/splat-agent/src/lease.rs)).

---

## B. Daemon ↔ bridge: protocol 3

- Transport: TCP, `127.0.0.1:50051` in the guest, reached from Windows through WSL2 localhost
  forwarding.
- Framing: one JSON object per line, `\n`-terminated, UTF-8 **without** a byte-order mark. A
  request frame longer than 1 MiB (excluding the newline) is refused and the connection closed.
  The bridge holds the same cap the other way: a daemon frame that passes 1 MiB without ending is
  abandoned with the connection.
- Protocol version: `3`. A first frame that is not a `HELLO`, or any request outside an
  `AUTHENTICATED` frame, closes the connection.

### Handshake

| Direction | Frame |
| --- | --- |
| bridge → daemon | `{"type":"HELLO","protocolVersion":3,"clientNonce":"<64 hex>","proveFrames":true}` |
| daemon → bridge | `{"type":"CHALLENGE","protocolVersion":3,"serverNonce":"<64 hex>","serverProof":"<64 hex>","framesProven":true}` |

Nonces are 32 bytes from the kernel's CSPRNG. Hex is lowercase on the wire; the daemon's parser
also accepts uppercase, and refuses anything that is not exactly 64 hex digits.

The bridge checks `serverProof` in fixed time **before sending anything else**. A listener that
took the daemon's port learns one nonce and nothing more.

`proveFrames` and `framesProven` date from 2026-09-23 (roadmap 2.6). A bridge that sends the first
asks for every frame the daemon answers with to be proven; a daemon that agrees says so with the
second and proves its `CHALLENGE` under the `daemon+frames` label below, so the agreement is in the
proof and a relay that stripped the field would leave a `CHALLENGE` the bridge refuses. A daemon that
predates the field ignores it, proves its `CHALLENGE` under the plain label, and answers unwrapped;
the bridge accepts that and reports `FramesProven` as false, which `doctor` prints.

### Proofs

The key is the UTF-8 bytes of the token as written in `/etc/splat/agent.token` (64 lowercase hex
characters). The token itself never crosses the wire.

```
daemon_proof  = HMAC-SHA256(key, "splat-agent/3 daemon"        || 0x00 || clientNonce || serverNonce)   # framesProven absent
daemon_proof  = HMAC-SHA256(key, "splat-agent/3 daemon+frames" || 0x00 || clientNonce || serverNonce)   # framesProven: true
request_proof = HMAC-SHA256(key, "splat-agent/3 request" || 0x00 || clientNonce || serverNonce
                                 || sequence as big-endian u64 || request bytes)
frame_proof   = HMAC-SHA256(key, "splat-agent/3 frame"   || 0x00 || clientNonce || serverNonce
                                 || sequence as big-endian u64 || frame bytes)
```

`sequence` starts at 0 on each connection and increments once per **accepted** `AUTHENTICATED`
frame, so a proof is good for one request, in one place, on one connection. The request is proven
over its exact bytes, before any of them is parsed; that is why it travels as a string. The
daemon's frames are numbered the same way, from 0 for the first frame after the `CHALLENGE`, and
proven over their exact bytes for the same reason.

Test vectors, asserted on both sides (token `0123456789abcdef` × 4; client nonce bytes `00..1f`;
server nonce bytes `20..3f`; request `{"type":"HEALTH_CHECK"}`):

| Proof | Value |
| --- | --- |
| daemon, `framesProven` absent | `52265f2b72fe6c7801c6ffadbd9745a0a69bb165d31d71f31007e81f1c01ea7d` |
| daemon, `framesProven: true` | `c1fb43f8ecb070c29c61eb34189d0917d3c0738dd7f120920c9607fc71661d3d` |
| request, sequence 0 | `835749efc2b9219f33027ab8571edebb135df57a55b6a0fbc79e1cc68c42c5aa` |
| request, sequence 1 | `2bb2251468dd196a6a88d2684c95beacdf2954864d0555e0143a124c30ca755d` |
| frame, sequence 0, over `{"type":"EXIT","exitCode":0}` | `a8105556e4245abee3c9221c484065cef75ada4422251d572ee802ddae1f08f4` |
| frame, sequence 1, over the same | `1787bcf29e2992298a87cfa606ff26f6afe6e496f61b95f42f3ff8e4baf6f3bf` |

### Requests

Every request after the handshake is wrapped:

```json
{"type":"AUTHENTICATED","proof":"<64 hex>","request":"<the request, as a JSON string>"}
```

**`HEALTH_CHECK`** — `{"type":"HEALTH_CHECK"}`. Answered with one frame:

| Field | Type | Meaning |
| --- | --- | --- |
| `type` | `"HEALTH_RESPONSE"` | |
| `enforcing` | bool | The daemon holds live BPF map handles. **The field to gate on**: reachable is not enforcing |
| `bpfLsmActive` | bool | Same observation as `enforcing` |
| `cgroupV2Active` | bool | `/sys/fs/cgroup/cgroup.controllers` exists |
| `overlayFsSupported` | bool | `overlay` is in `/proc/filesystems` — informational; the daemon refuses overlay leases regardless |
| `kernelVersion` | string | `/proc/sys/kernel/osrelease` |
| `activeLeaseCount` | int | Leases in the daemon's table |
| `ceiling` | bool | A lease ceiling bounds every request on this host (section D). Absent from daemons before 2026-09-21 |

**`EXECUTE_TOOL`** — one lease and one command. The daemon refuses, rather than defaults, any
dimension the caller did not declare.

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `type` | `"EXECUTE_TOOL"` | yes | |
| `protocolVersion` | `3` | yes | Anything else refused |
| *(the whole request)* | | | Intersected with the lease ceiling (section D) when the guest has one; outside it, refused |
| `missionId` | string | no (`"default"`) | Names the cgroup `splat_leases/mission_<id>` |
| `command` | string | yes | Absolute path. Must appear in `allowedExecPaths` |
| `argv` | string[] | yes | Verbatim arguments; an empty array is "no arguments". Anything but an array is refused |
| `workingDirectory` | string | no (`/tmp`) | Falls back to `/tmp` if absent on disk |
| `allowNetwork` | bool | no (`false`) | |
| `allowedEgressIps` | string[] of dotted quads | when `allowNetwork` | Installed × `allowedEgressPorts`. Empty means nothing permitted. The same list governs datagrams, so a resolver must appear here on port 53 for a name lookup to succeed |
| `allowedEgressPorts` | int[] | when `allowNetwork` | 1–65535 |
| `readOnlyFs` | bool | no | The working directory is bound read-only inside the jail. Refused only by a daemon that is not enforcing |
| `missionId` (again) | | | Letters, digits, `-`, `_` and `.` only: it names a cgroup and a jail root |
| `protectedPaths` | string[] | no | Unioned with the daemon's `/etc/shadow` and `/etc/sudoers`; a path that does not resolve refuses the lease |
| `allowedExecPaths` | string[] | yes | The only executables, including the command itself |
| `leaseDurationSeconds` | int | no (`30`) | Clamped to 5–300 |
| `limits.maxMemoryBytes` | int | no | Ceiling 268435456 (256 MiB); a request may only lower it |
| `limits.maxCpuPercent` | int | no | Ceiling 50 |
| `limits.maxPids` | int | no | Ceiling 100 |
| `overlayFs.enableCow` | bool | no | `true` is **refused** |
| `ephemeralWorkspace` | bool | no (`false`) | The daemon makes `workingDirectory` for this lease and removes it at the lease's end. Accepted only for a directory directly under the daemon's missions root (`--missions-root`, default `/var/lib/splat/missions`) named by one component of letters, digits, `-`, `_` and `.`; anywhere else is **refused**. Daemons before 2026-09-24 ignore the field and fall back to `/tmp` for a directory that is not there |

**`EXECUTE_BOUND`** uses the same lease fields and adds `executionContext`, an exact JSON string
with `agentId`, `contractSha256`, `tenantId`, `callerId` and `taskId`. Optional delegation fields
are `parentTaskId`, `delegationSha256`, `requestingAgentId` and `requestingContractSha256`.
The trusted host supplies these labels after authentication; they are not independent guest-side
identity verification. This operation requires enforcement, authenticated reply frames and signing.
An optional `executionPolicy` supplies the explicit Landlock/seccomp contract.

While a bound workload runs, its owning authenticated session may send
`{"type":"CANCEL","missionId":"<same mission UUID>"}` in its next sequenced request frame.
The daemon kills and drains the cgroup while its policy is installed, then emits its signed EXIT.
Outcome v2 appends `executionPolicySha256` (`none` without an explicit policy), `executionContext`,
`effectivePolicySha256`, `workloadDrained` and `cancellationAccepted` to the v1 canonical fields.
The same values appear on EXIT; the host verifies their signature and invocation binding before
claiming confirmed termination. A disconnect without that receipt remains unconfirmed to the host.

The answer is a stream, in this order: one `LEASE` (daemons since 2026-09-24; earlier ones send
none), then zero or more `STDOUT`, `STDERR` and `VIOLATION` frames, then exactly one `EXIT`. Every
`VIOLATION` belonging to the lease precedes `EXIT`, and since 2026-09-25 that is checked rather
than timed: after the child exits the daemon drains the ring buffer until the number of frames it
has sent for this cgroup reaches the kernel's own count for it, and only then writes `EXIT`. The
old form waited a flat 250 ms and hoped, which on a loaded machine lost a datagram denial that the
kernel had already made. A three-second deadline still bounds the wait, and `violationsComplete`
says which of the two ended it.

| Frame | Fields | Notes |
| --- | --- | --- |
| `LEASE` | `missionId`, `cgroupId`, `cgroupPath`, `enforcing`, `limitsReadBack`, `limits.{maxMemoryBytes,maxCpuPercent,maxPids}`, `jailed`, `readOnlyFs`, `workspace`, `workspaceCreated`, `workloadUid` | What was installed, before the tool's first byte. `enforcing` is a real cgroup under live BPF map handles; `limitsReadBack` says whether `limits` are the controllers' own values (a real cgroup) or the request as lowered (the non-enforcing path, which is not a readback). `workspace` is the working directory the tool runs in, `workspaceCreated` whether this lease made it |
| `STDOUT` / `STDERR` | `data`: string | At most 64 KiB of text per frame. Not line-aligned: a longer line arrives as several frames, which the bridge concatenates. A multi-byte character is never split across frames |
| `VIOLATION` | `cgroupId`, `pid`, `hook`, `detail` (u64 holding the record's u32), `detailText`, `comm`, `timestampMs`, `ktimeNs`, `seq` | Only events for **this** lease's cgroup. `timestampMs` is the daemon's clock, milliseconds since the Unix epoch, taken when the event was drained; `ktimeNs` and `seq` are the record's own. Daemons before 2026-09-20 omit all three |
| `EXIT` | `exitCode`: int; `violationsDropped`: int; `violationsCounted`: int; `violationsReported`: int; `violationsComplete`: bool; `workspaceRemoved`: bool; `outcomeCanonical`: string; `outcomeSignature`: base64; `outcomeKeyId`: hex; `outcomePublicKey`: base64 | The child's exit status; `-1` when it died by signal, could not be spawned, or the request was refused. `violationsDropped` is how far the kernel's drop counter moved while this lease ran, across every lease on the host; anything but `0` means the `VIOLATION` frames above are incomplete. `violationsCounted` is what the kernel counted for THIS lease's cgroup, read out of the program's own map after the workload exited; `violationsReported` is how many `VIOLATION` frames this connection was actually sent; `violationsComplete` is true only when every counted refusal was reported and nothing was dropped. All three are absent from a daemon with no live program - it refused nothing because it refuses nothing, and a confident zero there would be the same lie in reverse. `workspaceRemoved` is present only when the lease made its workspace, and says whether it is gone - on a request refused after the workspace was made as well, where it follows the refusal's `STDERR` with no `LEASE` frame before it. The last four are the guest's own signature over what this lease did (roadmap 2.5): `outcomeCanonical` is the exact text signed - a pipe-delimited, fixed-order record of the fields above, carried verbatim because four implementations have to agree on the bytes and rebuilding a canonical form in each of them is where that agreement is lost - and the rest are PKCS#1 v1.5 over SHA-256, the same primitive every run-record bundle already verifies with its standard library alone. Absent from a daemon with no key, where the record says the outcome is unsigned rather than implying anyone checked it. The signature proves the text came from a process holding that guest's key, not that the guest was honest: root in the guest can sign a lie, which is the boundary the substrate already has |

A refused request (policy the daemon cannot enforce, an undeclared dimension, a command outside its
own lease, a cgroup or map that could not be provisioned) is answered with a `STDERR` frame whose
`data` begins `SPLAT refused` and an `EXIT` of `-1`; the connection stays open. An authentication
failure or an oversized frame is answered with a `STDERR` frame and the connection is **closed**. A
request of an unknown `type` is answered with a `STDERR` refusal naming the type, and the
connection stays open.

### The daemon's frames

On a connection whose `CHALLENGE` said `framesProven`, every frame the daemon sends after it — the
`HEALTH_RESPONSE`, every `STDOUT`, `STDERR`, `VIOLATION` and `EXIT`, and every refusal — travels
wrapped:

```json
{"type":"PROVEN","proof":"<64 hex>","frame":"<the frame, as a JSON string>"}
```

The bridge checks the proof in fixed time over the frame's exact bytes and for its number on the
connection before it parses any of them, and hands the frame inside up to its caller. A frame that
does not prove itself — unwrapped, proven under another connection's nonces, or proven for a place
already taken, which is what a replay or a reordering looks like — ends the session: what came
before it stands, and nothing after it is read. The bridge reports it as a `TransportError`, and
`WslAgentSessionTests` holds the refusal to the vectors above.

On a connection whose `CHALLENGE` did not say so — a daemon older than 2026-09-23 — the frames
travel bare and are believed on the strength of the handshake, as they always were. The bridge
says which kind of session it got (`WslAgentSession.FramesProven`), the health check carries it,
and `doctor` prints it. A transport that carries peer identity is still separate work (roadmap 2.4).

---

## C. Bridge ↔ control plane: the C# records

Defined in [`Interfaces.cs`](../src/MissionController.Core/Interfaces.cs); mapped to the envelope
by [`WslLeasedExecutor`](../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs).

| `LeaseSpec` | Envelope field | Note |
| --- | --- | --- |
| `MissionId` (Guid) | `missionId` | `D` format |
| `WorkingDirectory` | `workingDirectory` | |
| `AllowNetwork` | `allowNetwork` | |
| `AllowedEgressIps` | `allowedEgressIps` | |
| `AllowedEgressPorts` | `allowedEgressPorts` | |
| `ReadOnlyFs` | `readOnlyFs` | `run_command` passes its caller's `readOnlyFs`; the template compiler sends `false` |
| `ProtectedInodes[].SourcePath` | `protectedPaths` | `InodeNumber` and `DeviceId` are `0` and never sent: an inode number read on Windows means nothing in the guest |
| `AllowedExecInodes[].SourcePath` | `allowedExecPaths` | Same |
| `LeaseDurationSeconds` | `leaseDurationSeconds` | Also the bridge's local deadline, floored at 5 s |
| `Limits.*` | `limits.*` | |
| `OverlayFs` | `overlayFs` | Sent with `enableCow: false` when present |

`LeaseViolationEvent` is the `VIOLATION` frame one to one: `Hook` is `KernelViolationHook`
(`Exec = 1`, `Open = 2`, `Connect = 3`, `SendDatagram = 4`, `Unspecified = 0`), `TimestampUtc` is `timestampMs`
when the daemon sent one, else the host's clock at receipt, and `Sequence` and `KernelTimeNs` are
`seq` and `ktimeNs`, `0` from a daemon that predates them. A non-zero `violationsDropped` in
`EXIT` is written into `StandardError` as a `[KERNEL_EVENTS_DROPPED]` line, and a `violationsComplete`
of `false` as a `[KERNEL_EVENTS_INCOMPLETE]` one. `LeaseOutcome` carries all four numbers, and the
mission's run record carries them as `KernelRefusals`, `KernelRefusalsReported` and
`KernelRefusalEvidenceComplete`: a record that lists two refusals and cannot say whether there was a
third is a sample of the containment, not evidence of it. The signature fields ride into the record as
`GuestSignedOutcome`, `GuestOutcomeSignature`, `GuestOutcomeKeyId` and `GuestOutcomePublicKey`, and both
`verify_proofs.py` and `verify_proofs.ps1` check them - so a lease outcome edited between the guest and the
bundle fails in a stranger's hands, not just in ours.

`ProcessExecutionResult` after a lease:

| `ExitCode` | `TerminalReason` | Meaning |
| --- | --- | --- |
| the `EXIT` value | `ExplicitExit` | The child ended, or the daemon refused (`-1`) |
| `-1` | `AbruptDisconnect` | The connection closed before `EXIT` |
| `-2` | `LocalDeadlineExpired` | The bridge's own deadline fired; `TimedOut` is `true`. Closing the connection makes the daemon kill the workload |
| `-3` | `CallerCancelled` | The caller's token was cancelled |
| `-1` | `TransportError` | Connect, token or handshake failed, or a frame did not prove itself; `StandardError` says which |

`FinalMetrics` is always `JobResourceMetrics.Unavailable`: the `EXIT` frame carries no cgroup
accounting, and the bridge reports the absence rather than a number nobody measured.

`ProcessExecutionResult.Lease` is the `LEASE` frame one to one (`LeaseOutcome`), with `WorkspaceRemoved`
taken from `EXIT`; null from a daemon that sent no `LEASE`, except a refusal that removed the workspace it had made, which is an outcome marked not installed and carrying nothing but the directory's fate. `LimitsReadBack` is `limits` as a
`JobLimitsReadback` only when `limitsReadBack` was true. A governed mission run through
`LinuxLeaseSubstrate` writes both into its run facts as the substrate's applied controls and the
kernel-held limits, beside the Windows path's job-object readback.

### Timestamp origins

| Where | Clock | Meaning |
| --- | --- | --- |
| Kernel record, `ktime_ns` | kernel, monotonic | The denial itself, in nanoseconds since the guest booted. Comparable between records; not a wall-clock time |
| `VIOLATION.timestampMs` | daemon, `SystemTime::now()` | When the event was drained — the ring buffer is polled every ~100 ms, so up to that much after the denial |
| `LeaseViolationEvent.TimestampUtc` | `timestampMs`, else host | |
| Ledger row | host, at append | Written by the MCP handler after the lease ends |

---

## D. The lease ceiling: `/etc/splat/policy.json`

Root-owned, mode 0644 or tighter, read by the daemon at startup and written by
`splat-mcp provision --apply`. Every `EXECUTE_TOOL` is intersected with it after the declared
checks and before a cgroup exists; a request outside it is refused naming the first offender.
Parsed by [`ceiling.rs`](../native/splat-agent/src/ceiling.rs), which rejects a field it does not
know, a schema it does not speak, a file that is not root's, and one that group or world can write.

```json
{
  "schema": 1,
  "allowedExecPrefixes": ["/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/"],
  "allowedEgress": ["127.0.0.1:80", "203.0.113.7:443"],
  "alwaysProtectedPaths": ["/etc/shadow", "/etc/gshadow"],
  "maxLeaseDurationSeconds": 300,
  "limits": { "maxMemoryBytes": 268435456, "maxCpuPercent": 50, "maxPids": 100 }
}
```

| Field | Rule |
| --- | --- |
| `schema` | `1` |
| `allowedExecPrefixes` | Absolute directories; a trailing `/` is added, so `/usr/bin` admits `/usr/bin/x` and not `/usr/binx`. Every entry of a request's `allowedExecPaths` must start with one. Required, and not empty |
| `allowedEgress` | `a.b.c.d:port` entries. **Absent**: egress is not bounded by the ceiling. **Empty**: no lease may reach the network. Present: every `(address, port)` of the request's cross product must be in it, when `allowNetwork` is true |
| `alwaysProtectedPaths` | Unioned into every lease's protected paths before the caller's; each must resolve on the guest or every lease is refused |
| `maxLeaseDurationSeconds` | The request's duration is shortened to this |
| `limits` | Each present value lowers the daemon's own ceiling for that clamp; the request can lower it further |

---

## What is not guaranteed

- **Sequence numbers are global and taken before reservation.** They count every denial on the
  host, not one lease's; two CPUs can deliver neighbouring numbers out of order; a number that
  never arrives was dropped. They restart at 0 when the daemon loads the program.
- **`ktime_ns` is monotonic, not wall time.** It says how far apart two denials were, and nothing
  about the date; `timestampMs` is the daemon's wall clock some 100 ms later.
- **Drops are counted, not attributed.** `violationsDropped` is the host-wide count's movement
  during one lease; a busy neighbour's denials can put a number in another lease's `EXIT`.
- **`detail` truncates the inode number** to 32 bits. The denial is real; the number in the text
  may not be the whole inode number on a filesystem that uses the high bits.
- **`STDOUT` and `STDERR` interleave arbitrarily** relative to each other; each is ordered within
  itself.
- **Frames from a daemon that did not say `framesProven`** are not proven, and are accepted. A
  daemon that said so is held to it: one frame that does not prove itself ends the connection.
- **Changing any layout in section A** requires updating the `const` assertions in `lease.rs` and
  `violation.rs`, re-running the canary and the daemon probe as root, and committing the evidence;
  `DocumentationDriftTests` withdraws the README's enforcement claim until that is done.
