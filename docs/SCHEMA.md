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
| 28 | 4 | `hook` | `1` exec (`bprm_check_security`), `2` open (`file_open`), `3` connect (`socket_connect`) |
| 32 | 4 | `detail` | Exec and open: the **low 32 bits** of the inode number. Connect: the destination IPv4 address in network byte order, or `0` for an IPv6 destination or an address too short to hold one |
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
| bridge → daemon | `{"type":"HELLO","protocolVersion":3,"clientNonce":"<64 hex>"}` |
| daemon → bridge | `{"type":"CHALLENGE","protocolVersion":3,"serverNonce":"<64 hex>","serverProof":"<64 hex>"}` |

Nonces are 32 bytes from the kernel's CSPRNG. Hex is lowercase on the wire; the daemon's parser
also accepts uppercase, and refuses anything that is not exactly 64 hex digits.

The bridge checks `serverProof` in fixed time **before sending anything else**. A listener that
took the daemon's port learns one nonce and nothing more.

### Proofs

The key is the UTF-8 bytes of the token as written in `/etc/splat/agent.token` (64 lowercase hex
characters). The token itself never crosses the wire.

```
daemon_proof  = HMAC-SHA256(key, "splat-agent/3 daemon"  || 0x00 || clientNonce || serverNonce)
request_proof = HMAC-SHA256(key, "splat-agent/3 request" || 0x00 || clientNonce || serverNonce
                                 || sequence as big-endian u64 || request bytes)
```

`sequence` starts at 0 on each connection and increments once per **accepted** `AUTHENTICATED`
frame, so a proof is good for one request, in one place, on one connection. The request is proven
over its exact bytes, before any of them is parsed; that is why it travels as a string.

Test vectors, asserted on both sides (token `0123456789abcdef` × 4; client nonce bytes `00..1f`;
server nonce bytes `20..3f`; request `{"type":"HEALTH_CHECK"}`):

| Proof | Value |
| --- | --- |
| daemon | `52265f2b72fe6c7801c6ffadbd9745a0a69bb165d31d71f31007e81f1c01ea7d` |
| request, sequence 0 | `835749efc2b9219f33027ab8571edebb135df57a55b6a0fbc79e1cc68c42c5aa` |
| request, sequence 1 | `2bb2251468dd196a6a88d2684c95beacdf2954864d0555e0143a124c30ca755d` |

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

**`EXECUTE_TOOL`** — one lease and one command. The daemon refuses, rather than defaults, any
dimension the caller did not declare.

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `type` | `"EXECUTE_TOOL"` | yes | |
| `protocolVersion` | `3` | yes | Anything else refused |
| `missionId` | string | no (`"default"`) | Names the cgroup `splat_leases/mission_<id>` |
| `command` | string | yes | Absolute path. Must appear in `allowedExecPaths` |
| `argv` | string[] | yes | Verbatim arguments; an empty array is "no arguments". Anything but an array is refused |
| `workingDirectory` | string | no (`/tmp`) | Falls back to `/tmp` if absent on disk |
| `allowNetwork` | bool | no (`false`) | |
| `allowedEgressIps` | string[] of dotted quads | when `allowNetwork` | Installed × `allowedEgressPorts`. Empty means nothing permitted |
| `allowedEgressPorts` | int[] | when `allowNetwork` | 1–65535 |
| `readOnlyFs` | bool | no | `true` is **refused** (no mount namespace) |
| `protectedPaths` | string[] | no | Unioned with the daemon's `/etc/shadow` and `/etc/sudoers`; a path that does not resolve refuses the lease |
| `allowedExecPaths` | string[] | yes | The only executables, including the command itself |
| `leaseDurationSeconds` | int | no (`30`) | Clamped to 5–300 |
| `limits.maxMemoryBytes` | int | no | Ceiling 268435456 (256 MiB); a request may only lower it |
| `limits.maxCpuPercent` | int | no | Ceiling 50 |
| `limits.maxPids` | int | no | Ceiling 100 |
| `overlayFs.enableCow` | bool | no | `true` is **refused** |

The answer is a stream, in this order: zero or more `STDOUT`, `STDERR` and `VIOLATION` frames,
then exactly one `EXIT`. Every `VIOLATION` belonging to the lease precedes `EXIT`; the daemon waits
250 ms after the child exits and flushes the ring buffer before it writes `EXIT`.

| Frame | Fields | Notes |
| --- | --- | --- |
| `STDOUT` / `STDERR` | `data`: string | At most 64 KiB of text per frame. Not line-aligned: a longer line arrives as several frames, which the bridge concatenates. A multi-byte character is never split across frames |
| `VIOLATION` | `cgroupId`, `pid`, `hook`, `detail` (u64 holding the record's u32), `detailText`, `comm`, `timestampMs`, `ktimeNs`, `seq` | Only events for **this** lease's cgroup. `timestampMs` is the daemon's clock, milliseconds since the Unix epoch, taken when the event was drained; `ktimeNs` and `seq` are the record's own. Daemons before 2026-09-20 omit all three |
| `EXIT` | `exitCode`: int; `violationsDropped`: int | The child's exit status; `-1` when it died by signal, could not be spawned, or the request was refused. `violationsDropped` is how far the kernel's drop counter moved while this lease ran, across every lease on the host; anything but `0` means the `VIOLATION` frames above are incomplete |

A refused request (policy the daemon cannot enforce, an undeclared dimension, a command outside its
own lease, a cgroup or map that could not be provisioned) is answered with a `STDERR` frame whose
`data` begins `SPLAT refused` and an `EXIT` of `-1`; the connection stays open. An authentication
failure or an oversized frame is answered with a `STDERR` frame and the connection is **closed**. A
request of an unknown `type` is answered with a `STDERR` refusal naming the type, and the
connection stays open.

### What the daemon's own frames carry

Nothing: after the handshake the daemon's frames are not authenticated. On loopback nothing sits
between the two ends, and the handshake settled who is at each. A transport that carries peer
identity is the work that would change this.

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
| `ReadOnlyFs` | `readOnlyFs` | Always `false` from every live caller |
| `ProtectedInodes[].SourcePath` | `protectedPaths` | `InodeNumber` and `DeviceId` are `0` and never sent: an inode number read on Windows means nothing in the guest |
| `AllowedExecInodes[].SourcePath` | `allowedExecPaths` | Same |
| `LeaseDurationSeconds` | `leaseDurationSeconds` | Also the bridge's local deadline, floored at 5 s |
| `Limits.*` | `limits.*` | |
| `OverlayFs` | `overlayFs` | Sent with `enableCow: false` when present |

`LeaseViolationEvent` is the `VIOLATION` frame one to one: `Hook` is `KernelViolationHook`
(`Exec = 1`, `Open = 2`, `Connect = 3`, `Unspecified = 0`), `TimestampUtc` is `timestampMs`
when the daemon sent one, else the host's clock at receipt, and `Sequence` and `KernelTimeNs` are
`seq` and `ktimeNs`, `0` from a daemon that predates them. A non-zero `violationsDropped` in
`EXIT` is written into `StandardError` as a `[KERNEL_EVENTS_DROPPED]` line.

`ProcessExecutionResult` after a lease:

| `ExitCode` | `TerminalReason` | Meaning |
| --- | --- | --- |
| the `EXIT` value | `ExplicitExit` | The child ended, or the daemon refused (`-1`) |
| `-1` | `AbruptDisconnect` | The connection closed before `EXIT` |
| `-2` | `LocalDeadlineExpired` | The bridge's own deadline fired; `TimedOut` is `true`. Closing the connection makes the daemon kill the workload |
| `-3` | `CallerCancelled` | The caller's token was cancelled |
| `-1` | `TransportError` | Connect, token or handshake failed; `StandardError` says which |

`FinalMetrics` is always `JobResourceMetrics.Unavailable`: the `EXIT` frame carries no cgroup
accounting, and the bridge reports the absence rather than a number nobody measured.

### Timestamp origins

| Where | Clock | Meaning |
| --- | --- | --- |
| Kernel record, `ktime_ns` | kernel, monotonic | The denial itself, in nanoseconds since the guest booted. Comparable between records; not a wall-clock time |
| `VIOLATION.timestampMs` | daemon, `SystemTime::now()` | When the event was drained — the ring buffer is polled every ~100 ms, so up to that much after the denial |
| `LeaseViolationEvent.TimestampUtc` | `timestampMs`, else host | |
| Ledger row | host, at append | Written by the MCP handler after the lease ends |

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
- **Frames after the handshake are not proven** by the daemon.
- **Changing any layout in section A** requires updating the `const` assertions in `lease.rs` and
  `violation.rs`, re-running the canary and the daemon probe as root, and committing the evidence;
  `DocumentationDriftTests` withdraws the README's enforcement claim until that is done.
