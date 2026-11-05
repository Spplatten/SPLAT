# Decoupled sensor-to-enforcer integration

SPLAT must decide before the protected operation completes. An asynchronous sensor can cancel
future work; it cannot reverse a completed read or retroactively protect an inherited descriptor.
This is a hardened interoperability prototype, not a production-qualified connector or a measured
sub-millisecond response system. It does not establish SOC 2 compliance.

## 1. Physical model and architectural position

The kernel checks preinstalled authority. The sensor describes observations. A separately authenticated
collector may request a monotone reduction in authority for an already admitted task. No sensor
binary, sensor BPF program, shared tail-call table or proprietary agent memory is modified.

Implemented prototype: one immutable task binding per sidecar, an authenticated HTTPS input,
a one-row SQLite cancellation mailbox, the existing SPLAT A2A control interface, and a separate
LogScale structured-ingest exporter. The mailbox coalesces all matching alerts into the same
cancellation. The source token cannot name another task or mint, renew or widen a lease.

The cold path intentionally allocates for HTTPS, JSON, SQL and requests. Durability precedes HTTP
202. It is not a zero-allocation hot path. A separate fixed-record Rust SPSC primitive demonstrates
allocation-free push/pop but is NOT connected to the sidecar or mapped into another process.
This places the current implementation toward pragmatic interoperability; a native mapped transport,
automatic admission binding and independent receipt verification remain engineering work.

## 2. Topology and ownership

```mermaid
flowchart TD
    S["Falco or Falcon sensor"] --> C["Trusted collector and identity enrichment: required"]
    C --> H["HTTPS sidecar: fixed admitted task"]
    H --> Q["Durable cancellation mailbox"]
    Q --> A["Authenticated SPLAT A2A owner"]
    A --> D["Existing daemon cancellation and drain"]
    D --> K["SPLAT-owned policy and BPF-LSM hooks"]
    Q --> X["Independent outcome export worker"]
    X --> L["LogScale structured ingest"]
```

- **S/C:** Falco's own JSON alert goes straight to the sidecar's `/v1/falco/alerts`, attributed by
  lease cgroup (below); no collector. Falcon IOA data and any other sensor still need a collector that
  validates provenance and enriches identity at observation time; that collector is not implemented.
- **H/Q:** implemented in the new sidecar; only its exact configured task can be canceled.
- **A/D/K:** existing repository control/enforcement path, not newly reproved by this prototype.
- **X/L:** implemented HTTPS request formatting; no live LogScale account was exercised.

Falco's documented JSON includes rule, time, hostname, source and output_fields. Falco has no field
for a guest boot ID or a cgroup inode, so it cannot fill the normalized tuple below. It does print
`thread.cgroups`, and SPLAT names a lease's cgroup by its task: GetTask's extension metadata carries
`leaseCgroup`, `/splat_leases/mission_<task GUID>`, the directory the daemon creates exclusively
(`native/splat-agent/src/cgroup.rs`) and an enforcing daemon refuses to run a lease without. The
A2A test `ApprovedDelegationPinsTheLeaseAndPersistsAttributableTaskEvidence` checks the reported
path against the admitted lease and against those two lines of `cgroup.rs`. Other sensors use the
versioned normalized contract by default. An opt-in Falcon adapter also accepts a single JSON event
through a reviewed, hash-pinned field mapping; it still requires a trusted admission binding and
relay. See the [Falcon operator procedure](FALCON-SIDECAR.md) for configuration, identity and
evidence limits.
See [Falco output channels](https://falco.org/docs/concepts/outputs/channels/).

The admission owner must retain the task UUID and establish node, guest boot ID, cgroup ID, host-
namespace PID and process start ticks before releasing the workload, using trusted host-namespace
observations. StartTicks means Linux /proc/PID/stat field 22, in boot-relative
clock ticks. A Falcon/Windows creation timestamp is a different representation and cannot simply
be copied into that field. Resolve the cross-platform identity at the trusted admission boundary.
Register descendants from
trusted lifecycle evidence; the prototype matches one process, not an entire inferred process tree.
Never enrich a delayed PID by reading whichever process occupies it now. A Linux registrar should
retain pidfds/cgroup descriptors; a Windows registrar should retain process handles and creation
times. Neither registrar is supplied by this patch. The sidecar never signals an alert-supplied PID:
its only action targets an immutable A2A task UUID, which also limits PID-reuse damage.

### Falco binding: the lease cgroup instead of the tuple

A binding with a `falco` object (`onDrop`, `maxSilenceMs`, optionally a pinned `leaseCgroup`) leaves
`boot`, `cgroup`, `pid` and `startTicks` out, and `Check` refuses one that carries both identities.
At startup the sidecar calls GetTask, takes `leaseCgroup` from SPLAT's answer, refuses a task that is
already terminal or a pin that disagrees, and only then fingerprints the mailbox and listens. The cgroup
holds every descendant, the unprivileged workload cannot leave it, and its name carries a GUID, so
PID recycling has nothing to confuse: `proc.pid` is never read. `FalcoAdapter.Classify` decides:

| Authenticated Falco event | Result |
| --- | --- |
| Bound rule, `source` syscall, `thread.cgroups` naming the lease or a path below it | admits `falco:<uuid, or SHA-256 of the alert>` |
| Bound rule naming another lease, a host process, or `thread.cgroups` null | 204, nothing admitted |
| Bound rule that is not a syscall rule or does not print `%thread.cgroups` | 409, a misconfiguration made loud |
| `Falco internal: syscall event drop` (`source` internal) | `onDrop: revoke` admits `falco-drop:...`; `tolerate` does not |
| `Falco internal: metrics snapshot` whose `scap.n_drops` or `falco.outputs_queue_num_drops` moved, or whose `falco.start_ts` changed, since the previous snapshot | `revoke` admits `falco-drop:...` or `falco-restart:...` |
| Nothing from the bound hostname for `maxSilenceMs`, on a monotonic clock | admits `falco-silence` |
| All four parser slots still busy after a one-second wait | 429; `revoke` also admits `sidecar-saturated` |
| Any event from another hostname | 204, and it does not count as the node speaking |

`thread.cgroups` is `subsys=path` entries joined by single spaces (libsinsp,
`sinsp_filtercheck_thread.cpp`). Under cgroup v2 a controller not enabled on the lease cgroup reports
the nearest ancestor that has it; the daemon enables memory, cpu and pids on lease cgroups, so those
entries should reach the lease. Every entry that names a lease must name the same one. Falco raises
its drop alert only above `syscall_event_drops.threshold` and through a token bucket
(`event_drops.cpp`), which is why the snapshot counters are read too; `simulate_drops: true` exercises
the drop path. The first snapshot only sets a baseline.

What the Falco side needs, none of it exercised against a live Falco here: the bound rule prints
`%thread.cgroups`; `json_output: true`; `metrics.enabled` and `output_rule: true` at an interval
below `maxSilenceMs`, or a quiet node reads as silence; Falco in the guest's root cgroup namespace,
since a namespaced Falco prints paths relative to its own root and nothing attributes; and a sender
that adds the sidecar's `Authorization: Bearer` header, such as Falcosidekick's webhook output with
`customheaders`. The sidecar listens on Windows loopback while Falco runs in the WSL guest, so that hop
needs mirrored networking or a relay. `--check-falco-event <binding.json> <alert.json>` classifies one
captured alert offline: run it on a real alert from the node before trusting a binding.

## 3. Pass 1 and pass 2 implementation

Pass 1: `src/splat-alert-sidecar/minimal-cancel.ps1` invokes the existing CancelTask RPC for a
disposable admitted task. It uses the task owner's token, normal TLS validation, the required
A2A extension header and a bounded timeout. The result must be inspected for termination evidence;
a successful HTTP response is not sufficient.

Pass 2: `src/splat-alert-sidecar/` is a standalone .NET 10 executable. The repository targets
.NET 10; introducing .NET 9 for this adapter would split the build contract. It binds only to
127.0.0.1 over HTTPS, requires an independent 32-byte random alert token, rejects browser Origin,
limits bodies to 16 KiB, connections to 16 and simultaneous admitted handlers to four. A request waits
up to one second for a handler before it is refused, so a sensor's burst becomes latency, not loss.

Startup arguments are admission-binding JSON, SQLite mailbox path and HTTPS PFX path, plus an
approved profile JSON path in Falcon mode. A Falcon binding without its profile refuses startup;
that mode exposes `/v1/falcon/alerts` rather than the normalized `/v1/alerts` route. Environment
inputs are SPLAT_ALERT_TOKEN (base64 32 bytes), SPLAT_ALERT_CERT_PASSWORD (when needed),
SPLAT_A2A_CALLER_TOKEN, and optionally SPLAT_LOGSCALE_INGEST_URL plus SPLAT_LOGSCALE_INGEST_TOKEN.
Protect those inputs and the mailbox directory with operator ACLs. The A2A credential should be the
one `splat/RegisterSensor` issues for the bound task, which reads and cancels that task only
([sensor registration](A2A-TEMPLATE-BRIDGE.md#sensor-registration)); the task owner's own credential
still works, but whoever reads it can also start new work under every skill the owner holds.
The listener certificate must validate for 127.0.0.1; no certificate bypass is installed.
Disable automatic HTTP redirects. The loopback service is not a public cloud-webhook endpoint:
a separately secured collector/relay is required.

State transitions: idle -> pending only after a SQLite FULL-synchronous commit; duplicates retain
the first alert. A worker polls GetTask before CancelTask to recover ambiguous request responses.
Pending ends as host-reports-drain, terminal-without-drain-proof, or expired-unresolved. A terminal
state never upgrades itself on a duplicate. The exporter retries independently and marks exported
only on LogScale HTTP 200. A stable record ID supports receiver deduplication; exactly-once delivery
is not claimed. Sensor events beyond the first are not archived by this coalescing mailbox.

The worker polls at 25 ms and backs off to 1.6 s after failures. Therefore this implementation
does NOT satisfy sub-millisecond telemetry-to-revocation. It demonstrates bounded identity,
durability and outcome semantics first. A faulted worker stops intake. Export failures do not
block control calls; disk admission failures return 503 and concurrency pressure returns 429.
Those responses require retry at the collector. No response says an alert restored authority.

## 4. Kernel experiment and benchmark contract

`native/experiments/lease-open/open_guard.bpf.c` is separate lab source. It does not replace the
shipping 16-byte `struct lease_state` (`__u64 deadline_ns` and a reserved `__u64 epoch` the kernel does
not yet check, `native/splat-agent/src/bpf/lease_lsm.bpf.c`).
Its 32-byte open_lease holds a BOOTTIME deadline, protected inode,
epoch, kernel device number and denied read/write f_mode bits. Preallocated hash entries are installed
before launch and remain immutable during a workload. Do not edit a multiword policy in place and
assume readers see an atomic transaction. Do not delete a live policy: a missing entry means the
cgroup is outside the experiment. Drain first; retain the cgroup and an O_PATH reference to the
protected inode to prevent object recycling.

The hook preserves a prior BPF-LSM return value, denies expired registered leases, and returns
-EPERM for a matching protected inode/access mode. Its 1 MiB denial ring is observational; a failed
reservation increments a per-CPU drop counter and cannot change the denial. It does not govern
existing file descriptors, mmap, arbitrary writes, all child authority or all path replacements.
No native loader, admission registrar or reproof was executed here. The source is not a deployable
kernel feature until the loader lifetime rules and native negative controls are verified.

BOOTTIME and MONOTONIC are not interchangeable: the latter excludes Linux suspend. Guest BOOTTIME
still does not prove that WSL host sleep advances a VM clock; retain the measured host-sleep limit.
A 32-byte value is not automatically cache-line aligned. BPF ringbuf reservation itself uses an
internal spinlock; describe the user-space SPSC primitive separately from the kernel ring.

Use a public dummy key fixture, never real SSH credentials. Its exact contents for the supplied
measurement utility are the ASCII line SPLAT_PUBLIC_DUMMY_KEY_DO_NOT_USE followed by LF.

1. Baseline: the dummy read succeeds. Record elapsed syscall samples with all other sensors fixed.
2. Preinstalled lease: the same attempted open returns EPERM while a separate permitted-file control
   still succeeds. Separate policy rejection from process termination; do not call this a kill.
3. Reaction: a real sensor produces an alert and the collector requests cancellation. Record observation,
   collector receipt, durable admission, control request, daemon enforcement and drain acknowledgement.
   A synthetic delayed timer is not a measured Falcon/Falco latency.

`measure_open.py` retains every duration and errno, p50/p95/p99, kernel, architecture and source
hash. Its metric includes userspace/Python, scheduling, the syscall and all hooks. It is not isolated
BPF execution time. Hash the loaded program, policy, benchmark and installed daemon too; record CPU,
affinity, governor, kernel configuration, boot ID and sample ordering in the native run bundle.
No 12 ms, 380 ms, 3.8 us or sub-microsecond result is asserted. All are proposed measurements.

## 5. Syntax and identifier breakdown

| Identifier | Operational role |
| --- | --- |
| Binding | Operator-owned immutable admission record; Check rejects malformed/expired configuration; Fingerprint binds one mailbox to that exact configuration. |
| TaskId, ListenPort, A2aPort | Fixed cancellation target and loopback endpoints, never selected by an alert. |
| Node, Boot, Cgroup, Pid, StartTicks | Identity tuple; boot and creation generation prevent treating a recycled PID/cgroup number as sufficient evidence. |
| Source, Rule, ExpiresUnixMs | Exact allow-listed sensor/rule and binding validity ceiling; no alert can extend the native lease. |
| Alert.Version, AlertId, ObservedUnixMs | Schema version, bounded sensor evidence identifier and replay-age filter. Source/rule/identity fields must match Binding. Wall-clock freshness is not kernel deadline enforcement. |
| Credentials, SHA256, FixedTimeEquals | Separate credential loading and bounded constant-time digest comparison; HTTPS still supplies transport authenticity. |
| Latch, slot, binding, state | One persistent control row and its immutable binding fingerprint; Admit commits the first signal, Read recovers it, Finish records a conservative terminal outcome. |
| alert, observed, received, reported | First evidence ID, sensor time, local acceptance time and independent export marker. |
| Control.Call, GetTask, CancelTask | Existing authenticated A2A operations. JSON-RPC id, result.id and version are checked; request params.id comes only from Binding. |
| A2A-Version, A2A-Extensions | Existing repository protocol/contract headers; no new privileged daemon API is exposed. |
| workloadTerminationConfirmed | Trusted host report only; signed native receipt verification remains separate. |
| ExportAsync, tags, events, timestamp, attributes | LogScale structured-ingest envelope. splat.record_id is stable across retry; HTTP 200 means ingestion-queue acceptance, not final retention. |
| ArrayPool, SemaphoreSlim, CancellationTokenSource | Cold-path body-buffer ownership, bounded concurrent admission and read/request time budgets. They are not kernel hot-path primitives. |
| SqliteConnection, FULL synchronous, owner FileStream | Durable coalescing mailbox and exclusive worker ownership; local administrator/storage compromise remains outside its guarantee. |
| open_lease, policies | Experimental 32-byte value and default-preallocated BPF_MAP_TYPE_HASH keyed by cgroup. Fixed 256-entry capacity; admission must fail if installation fails. |
| deadline_boot_ns, epoch | Expiry in the guest boot clock and correlation generation; epoch is not an atomic multi-map commit mechanism. |
| protected_ino, protected_dev, denied_fmode | Stable protected object and requested read/write-open mask; convert userspace device encoding correctly. |
| file_open, BPF_PROG, BPF_CORE_READ | LSM interception, typed trampoline convention, and CO-RE field reads using BTF. |
| bpf_get_current_cgroup_id, bpf_ktime_get_boot_ns | Current enforcement domain and the deadline clock; no packet parsing or network send occurs here. |
| bpf_get_current_pid_tgid, bpf_ringbuf_reserve/submit | Diagnostic PID and bounded ring reservation/publication. PID is evidence, not control authority. |
| events, denial, drops | BPF_MAP_TYPE_RINGBUF records and BPF_MAP_TYPE_PERCPU_ARRAY loss accounting. Emit failure never permits a denied operation. |
| AlertRecord, binding_hi/lo, boot_hi/lo | Rust fixed 64-byte record and binary correlation identities; not the HTTP ABI. |
| cgroup, start_ticks, observed_boot_ns, pid, reason | Native record's identity/time/reason fields; collector mapping and authentication remain external. |
| Producer, Consumer, Ring, Slots | Single-owner Rust transport handles and preallocated storage; no shared-memory process mapping is implemented. |
| AtomicU64 head/tail, Acquire/Release | Slot ownership publication and reuse ordering. wrapping_sub handles counter rollover within bounded occupancy. |
| UnsafeCell, MaybeUninit, Arc | Interior slot memory, explicitly initialized records, and startup-only shared allocation; unsafe Sync relies on exactly one producer and consumer. |
| Counter, repr(align(64)), CAPACITY | Separate 64-byte-aligned counters and 1024 records; 64-byte cache lines are a target assumption, not universal hardware truth. |
| try_push, try_pop | Bounded nonblocking native operations; full returns the original record, empty returns None. No implicit drop, sleep or allocation. |
| os.open/read/fstat/close, perf_counter_ns | Dummy-file benchmark operations and userspace duration measurement, not a kernel-only profiler. |
| leaseCgroup (A2A metadata), LinuxLeaseSubstrate.LeaseCgroupPath | SPLAT's statement of the guest cgroup a task's lease runs in; the one place the host spells the daemon's naming. |
| FalcoScope, LeaseCgroup, OnDrop, MaxSilenceMs | The Falco binding's identity (resolved from GetTask, optionally pinned) and its two blindness policies; Valid accepts only SPLAT's canonical lowercase spelling. |
| FalcoAdapter.Classify | Falco alert to an id to admit, or null for authentic traffic about something else; throws for malformed (400) or unattributable bound-rule (409) events. |
| LeaseOf | Reads the lease out of `thread.cgroups`; refuses a thread that names two. |
| Continuity, _sensorStart, _losses | Snapshot-to-snapshot comparison of Falco's process identity and loss counters, under a lock. |
| Silent, WatchAsync, Environment.TickCount64 | Sensor-silence detection on a monotonic clock and the one-shot watchdog that admits it. |
| sidecar-saturated, falco-drop, falco-restart, falco-silence | Mailbox ids that record why a fail-closed binding revoked without a rule match. |

## 6. Failure and contention audit

The hot path has bounded map lookups, field reads and optional denial emission. No JSON, SQL,
gRPC or network I/O belongs there. Worst-case latency is not established by source shape:
collect verifier logs, translated/JIT instruction counts and loaded-program statistics on the target
kernel. Prior BPF-LSM denial is preserved, and overall LSM ordering/enablement must be recorded;
a Falco tracing attachment is not the same operation as an LSM denial.

Win32 Job Objects enforce process/resource constraints; they are not an openat-equivalent file
authorization hook. The Windows filesystem boundary additionally relies on restricted tokens,
ACLs and the execution design. Do not transfer a Linux BPF timing result to Job Objects.

The lab ring consumes 1 MiB plus metadata; per-CPU counters grow with configured CPU count.
Map allocation includes keys, hash metadata and per-entry overhead, not merely 256 x 32 bytes.
The SPSC payload is 64 KiB, with padded counters and Arc metadata. Producer/consumer ownership avoids
a shared increment on every event, but head/tail visibility still transfers cache lines. Benchmark
NUMA placement and batches before claiming throughput. The shipping global denial sequence can also
be a contention point. .NET/TLS/SQLite RSS and GC pauses must be measured separately.

Chosen failure policy: expiry enforcement remains local; observability loss must not widen an
existing lease. A Falco binding makes the running lease's side of that choice explicit: `onDrop:
revoke` and a `maxSilenceMs` cancel the task on evidence that the sensor missed events (ring-buffer
or output-queue drops, a Falco restart, silence, or the sidecar's own saturation), and `tolerate`
with no silence limit keeps it running. Two blind spots stay fail-open whatever the binding says:
the sidecar's own death, and a sender refused at Kestrel's connection limit, which no handler sees.
The in-kernel deadline is what bounds a lease then. Refusing NEW work when the sensor is unhealthy
would need a trusted admission gate; that gate is not supplied here. External alerts must never
mint fresh authority, even when marked high confidence.

## Evidence and next 30 days

Initial evidence: `private/sidecar-2026-11-04/`. Native ring: 4 passing tests, including 100,000 allocation-
counted push/pop pairs and concurrent transfer. Sidecar: 28 passing in-process checks using real
SQLite transactions, reopen recovery, identity changes, expiry, duplicate admission and outcome
semantics. These are not live HTTPS, vendor, A2A, native-kernel or crash/power-loss proofs.

At that initial run, the normal sidecar build was blocked by NU1900 (NuGet vulnerability feed unavailable). A diagnostic
compile with only NU1900 demoted locally produced zero compiler errors and two audit warnings;
the repository warning policy was not edited. That diagnostic was not a release gate pass. WSL returned
E_ACCESSDENIED; the installed Windows clang advertises no BPF target. The benchmark Python parses
but has not produced results. Independent loopback diagnostics recorded TCP permission denial
and a UDP receive timeout, consistent with the earlier seven socket-test failures, not a waiver.

The 2026-11-05 follow-up supersedes the initial sidecar build blocker: the normal Release build
passed with zero warnings/errors, followed by all 74 checks, including the Falcon parser and real
HTTP handler with SQLite. These remain in-process tests, not live TLS or vendor delivery evidence.
The shipping daemon and MCP last hop separately have committed PASS records against `d5bb4cad`;
those records do not prove the experimental hook or the sensor-to-cancellation chain. Current
checks, provenance and remaining gates are in the
[reconciliation follow-up](audits/2026-11-05-reconciliation-follow-up.md).

2026-11-05, Falco binding: `packaging/test-alert-sidecar.ps1` builds the sidecar and runs
`--self-test`, which passed 137 checks (`FalcoChecks` adds the lease-attribution, time, drop, restart,
silence, watchdog and HTTP cases); `dotnet build -warnaserror` reported zero warnings, so NU1900 did
not recur. Four deliberate mutants (accepting any lease, accepting a non-canonical lease spelling,
ignoring a moved loss counter, answering foreign traffic with 409) each failed it. The suite runs the
same checks in `AlertSidecarSelfTests`; dropping the Falco group (74 ran) and admitting any lease
(assertion 102) each failed it. With the [admission registrar](TRUSTED-ADMISSION-REGISTRAR.md)'s
group merged the self-test runs 204 checks, and the suite fails below that. Still synthetic: no
alert from a running Falco has been classified yet.

- Days 1-7: authoritative admission binding/descendant lifecycle registration, scoped collector
  credentials, and independent native receipt verification. Preserve the existing lease ABI.
- Days 8-14: one real Falco rule and one customer-authorized Falcon/LogScale pipeline; schema/version
  fixtures, revocation ownership tests, clock skew and delayed/PID-reuse negative controls.
- Days 15-21: controlled Linux kernel proof, crash recovery, full mailbox/disk/network failures,
  sensor coexistence, and the three-act dummy-key experiment with raw distributions.
- Days 22-30: reproducible pilot package, installation/rollback/support runbook and scoped trials.
  Recruit 5-10 design partners around a measured workload and existing sensor deployment; count
  completed pilots and verified enforcement, not promised acquisition interest.

A strategic acquisition is a possible business outcome, not an engineering invariant or a promised
exit. Start with an integration customers can verify and operate.

Primary references: [LogScale ingest](https://library.humio.com/logscale-api/api-ingest.html),
[structured request format](https://library.humio.com/logscale-gdi/popular-ingest-methods-http-https-api-setup.html),
[BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html), [BPF ring buffers](https://docs.kernel.org/bpf/ringbuf.html),
and [Linux clock semantics](https://man7.org/linux/man-pages/man2/clock_gettime.2.html).
