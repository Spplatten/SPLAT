<!-- Track A governance template, added 2026-09-23 with the status-gate record
     (audits/2026-09-23-status-gate-and-gap-analysis.md). Copy this file to
     docs/rfcs/RFC-NNNN-<slug>.md, fill every section or write "n/a — <reason>" in it, and delete
     the guidance in <angle brackets>. A section left as guidance fails review. DocumentationDriftTests
     reads every .md at the top of docs/, so an RFC that lives there must keep its relative links
     resolving and must not promise latency the benchmark did not measure; an RFC under docs/rfcs/
     is not scanned, and should hold itself to the same rule anyway. -->

# RFC-NNNN — <title: the boundary this moves, in one line>

> **How to write one.** An RFC here is a claim about a boundary and who enforces it after the
> change. The reviewer's first question is always the one [`ARCHITECTURE.md`](ARCHITECTURE.md)
> asks of every layer — *kernel object, kernel LSM hook, a check in SPLAT's process, or nobody* —
> and the second is what evidence will show the boundary holding. Write the evidence plan before
> the design; a design without a probe is a wish. The rules the tree holds itself to are in
> [`CONTEXT.md`](CONTEXT.md); this template exists so that an RFC cannot skip one by accident.

## 0. Metadata

| Field | Value |
| --- | --- |
| RFC number | `RFC-NNNN` — next free number in `docs/rfcs/`; never reused |
| Title | <what changes, which boundary, who enforces it after> |
| Author | <name>; co-authors if any |
| Status | `Draft` → `In review` → `Accepted` → `Implemented` → `Superseded by RFC-MMMM` |
| Target milestone | <roadmap phase and row, e.g. `P2 · 2.7`>; link the row in [`ROADMAP.md`](ROADMAP.md) |
| Subsystem tag | one of `bpf` · `agent` · `bridge` · `mcp` · `core` · `windows` · `data` · `net` · `ui` · `packaging` · `docs` |
| Tree read at | <commit hash> on <date> — every "today" sentence below was checked against this tree |
| Owner of each step | *agent* — can be done without a person; *you* — needs `sudo`, an install, money, a signature or a decision ([`ROADMAP.md`](ROADMAP.md) vocabulary) |
| Related findings | `Fnn` / `AG-Fnn` ids from [the clinical audit](audits/2026-09-04-clinical-audit.md) and [the antigravity audit](audits/2026-09-05-antigravity-deep-audit.md); identifiers are append-only |
| Supersedes / superseded by | — |
| Reviewers and sign-off | <who, and the date each signed> |

## 1. Summary

<Three sentences. (1) What changes. (2) Which boundary it moves, and from which enforcer to which.
(3) What evidence file will show it holding, and which document's claim it lets us make or forces
us to withdraw.>

## 2. Problem statement, with the evidence that it is one

| | |
| --- | --- |
| The defect or gap, as observed | <a probe result, a failing test, a commit, a measured number — never "it seems". Quote the file and the field> |
| What today's code does | <the exact behaviour, with `path:line` references into the tree named in §0> |
| The invariant it violates or leaves unmet | <one of: fail closed and say so · refuse what cannot be enforced · scrub at the boundary · every refusal leaves evidence · never present simulation as output · measure then claim · name the tier in the message — from [`ARCHITECTURE.md`](ARCHITECTURE.md#invariants)> |
| Who can reach it today | <which tier of the [threat model](THREAT-MODEL.md): A catalog sensor · B MCP tool an outside AI drives · C the one template that dials out> |
| What it costs to leave open | <the concrete consequence, measured where possible: "21 of 33 templates answer differently" is a cost; "reduced security" is not> |

## 3. Architectural continuum placement

Every layer in this repository sits between two ends, and the map in
[`ARCHITECTURE.md`](ARCHITECTURE.md#architectural-continuum-map) records where each one is and why.
State where this change puts its layer, and defend it on what the layer has to *hold*, not on how
enterprise it looks.

**The two ends, so the words mean the same thing to everyone:**

- **Deliberate pragmatism** — one process, static dispatch, a struct laid out the way the kernel
  lays it out, a serializer-free boundary. Chosen when the boundary is on a latency- or
  safety-critical path and a seam there would only add a place to be wrong. Examples in the tree:
  the CO-RE reads in [`lease_lsm.bpf.c`](../native/splat-agent/src/bpf/lease_lsm.bpf.c); the
  `#[repr(C)]` cast of the ring-buffer record in
  [`violation.rs`](../native/splat-agent/src/violation.rs); the mission engine's one sequence.
- **Decoupled enterprise architecture** — an interface with more than one implementation or a test
  double behind it, a versioned wire contract, a remote sink. Chosen when two languages, two
  machines or a trust boundary meet, or when a test has to stand something in. Examples: the
  daemon ↔ bridge line protocol; `ILeasedExecutor`; `BpfMapSync`.

| | Today | After this RFC | Why |
| --- | --- | --- | --- |
| Placement of the affected layer | <coupled / decoupled, and to what> | <coupled / decoupled, and to what> | <the property the layer has to hold that decides it> |

**Trade-off analysis.** Fill every row; "n/a" needs a reason.

| Criterion | Pragmatic option | Decoupled option | Which this RFC picks, and the measurement or argument |
| --- | --- | --- | --- |
| Hot-path cost | <instructions, syscalls, copies per event / per exec / per open> | <same> | <measured with `src/splat-bench`, a `cargo bench`, or `bpftool prog` stats — a number nobody ran is an estimate and is labelled one> |
| Verifier and kernel cost | <instruction count, stack, helpers> | — | |
| Trust boundary crossed | <none / process / VM / machine> | | <a boundary crossed needs a proof over exact bytes, as protocol 3 has> |
| Number of real implementations | <1 / 2 / n> | | <an interface with one implementation exists for a test double or not at all> |
| Testability | <what a unit test can see> | <what a stand-in lets a test see> | |
| Drift risk between the two sides | <how a layout or vocabulary change is caught: `const` assert, test vector, drift test> | | |
| Failure isolation | <what a bug here takes down> | | |
| What would move it to the other end | <the future fact that would change this decision — write it down so the next RFC can cite it> | | |

## 4. Design

<The components, the control flow, the order of operations. Order is often the safety property —
"kill inside the policy, then withdraw it"; "join the cgroup between fork and exec"; "scrub before
the first yield" — so write the sequence as a numbered list and say which steps may not be
reordered and why.>

1. <step>
2. <step>

**Failure modes.** Every failure fails closed, refuses rather than falls back, and leaves a ledger
row. A row that reads "log a warning and continue" is a design defect.

| Failure | Detected by | Response | Ledger action / refusal text | Names the tier? |
| --- | --- | --- | --- | --- |
| <what can go wrong> | <the check, and where it runs> | <refuse · exit · kill · retry-and-hold> | <`ACTION_NAME`, or the `SPLAT refused …` sentence> | <yes: "a check in SPLAT's process, not a kernel denial"> |

## 5. Memory and concurrency contract

<Bound everything. An unbounded read is how a root process was once made to allocate without
limit by a caller that never sent a newline; a `let _ = fs::write(..)` is how no lease was ever
clamped. Fill the tables for each side the change touches (BPF · daemon · bridge · control plane).>

| Bound | Value | Enforced where | What happens at the bound |
| --- | --- | --- | --- |
| Per-event allocation | <bytes; 0 on the hot path> | | |
| Per-lease / per-mission allocation | <bytes, and the count of maps, handles, buffers> | | |
| Per-connection buffer cap | <e.g. 1 MiB frame, 64 KiB output chunk, 4 MiB transcript> | | <refuse and close · truncate and say so> |
| Map capacity | <`max_entries` per map, and what bounds the product: leases × paths × ports> | kernel | <a failed update refuses and rolls back the lease> |
| Ring buffer | <size; drop policy; how a drop is made visible: sequence gap + counter> | kernel | <the `-EPERM` still happens; the record does not> |
| Backpressure | <what a lagging consumer sees: `Lagged(n)` and carries on, never blocks the producer> | | |

| Ownership and lifetime | Who owns it | Who frees it | How a leak is caught |
| --- | --- | --- | --- |
| <handle / map fd / process handle / cgroup / jail skeleton> | <SafeHandle · `MapHandle` · `Drop`> | <dispose · drop · reaper · next daemon's start> | <finalizer · orphan reap · test> |

| Synchronization | Mechanism | Owner thread / task | Contention or ordering rule |
| --- | --- | --- | --- |
| <the lease table, the drain, the reaper, the stream> | <lock-free · channel (bounded, N slots) · `Mutex` · kernel-serialised map ops · `AsyncLocal`> | <the drain thread · a tokio task per connection · the caller's thread> | <e.g. "the kernel serialises map updates, so no lock"; "the reaper takes expired leases without touching maps"> |

| Cache and layout | Statement |
| --- | --- |
| Hot fields, struct layout, alignment, false sharing | <e.g. "56-byte record, 8-byte aligned, one per denial; the sequence counter is a fetching atomic on one cache line shared by every CPU that denies"> |
| GC avoidance (C#) | <no per-event allocation on the hot path; pooled buffers where measured; `Span<T>` / `stackalloc` only where a measurement shows the copy matters — the continuum map says the JSON hop is not such a place> |
| Async-signal safety (`pre_exec`) | <if the change touches the forked child: no allocation, no lock, no formatting, no `std::fs`; raw syscalls on `CString`s the parent built; a failure returns `errno` and the spawn is refused — see [`jail.rs`](../native/splat-agent/src/jail.rs) for the shape> |

## 6. Kernel and host invariants

| Requirement | Value | Checked by | On failure |
| --- | --- | --- | --- |
| Capabilities | <`CAP_BPF` and `CAP_SYS_ADMIN` to load and attach an LSM program (in practice root); root for cgroup writes and `pivot_root`; Windows: nothing elevated — a restricted launch must start from a non-elevated *and* an elevated console> | `doctor`; the daemon's startup gate | <the daemon exits rather than serves; the launch throws rather than runs unconfined> |
| Kernel configuration | <`CONFIG_BPF_LSM`, `CONFIG_DEBUG_INFO_BTF`, unified cgroup v2, `bpf` in the `lsm=` boot line, kernel ≥ 5.12 for `-mcpu=v3` atomics, ≥ 5.14 for `cgroup.kill`> | `preflight.sh`; `provision` | |
| Quotas | <map `max_entries`; ring-buffer size; cgroup controllers delegated (`memory`, `cpu`, `pids`) and **read back**; job-object limits **read back**> | `cgroup.rs`; `ReadBackLimits` | <a clamp that did not take refuses the lease> |
| Verifier safety constraints | <straight-line code, no unbounded loops; stack ≤ 512 B (today about 40 B); CO-RE reads only (`BPF_CORE_READ`, `bpf_probe_read_kernel`), never a raw dereference; program size and instruction count after the change; every helper GPL-compatible; an earlier LSM's non-zero verdict is returned unchanged> | the load itself; `bpftool prog` | <a program the verifier rejects is a daemon that refuses to start> |
| Windows object rules | <`SetInformationJobObject` **replaces** `LimitFlags` — restate the containment set on every call; every native handle a `SafeHandle`; `[LibraryImport]` entry points spelled exactly (`CreateJobObjectW`); struct sizes asserted, since `STARTUPINFOEX.cb` is what tells the kernel to read the extended form> | `Win32InteropMigrationTests` | |
| Fail-closed checklist | <required containment that cannot be applied refuses the work; no fallback to running uncontained; the refusal names its tier and lands in the ledger> | | |
| Host-wide side effects | <what this change writes outside the workload: a boot line, a systemd unit, a bpffs directory, a `.wslconfig` key — and how `unmount` will undo each> | | |

## 7. Interface and wire specification

Only what a test or a build assertion holds is written as a guarantee; everything else is a
description. Follow the shape of [`SCHEMA.md`](SCHEMA.md), and update it in the same commit.

**Binary layouts** — one table per struct that crosses the kernel ↔ daemon boundary.

| Offset | Size | Field | Byte order | Meaning |
| --- | --- | --- | --- | --- |
| 0 | 8 | `cgroup_id` | native | <…> |
| … | … | `_pad` | — | **Zero, written explicitly on both sides**: hash-map keys are compared byte for byte |

- Total size and alignment: <N bytes, M-byte aligned>, mirrored by a `#[repr(C)]` struct with a
  `const _: () = assert!(size_of::<T>() == N)` that fails the build on drift (the shape in
  [`lease.rs`](../native/splat-agent/src/lease.rs)).
- Fields copied verbatim from a `sockaddr` stay in network byte order and are compared as raw
  bytes; say so per field, because the byte-order mismatch has happened here three times.
- Unspecified bytes (an unzeroed reservation's tail) are named as such and a consumer must not
  read them.

**Serialization contract** — for every frame that crosses the daemon ↔ bridge boundary.

| Property | Value |
| --- | --- |
| Framing | <one JSON object per line, `\n`-terminated, UTF-8 **without** a byte-order mark> |
| Size cap | <bytes; refused *before* parsing; the tail of a refused frame is never re-read as frames of its own> |
| Version field | <`protocolVersion`; anything else refused, never negotiated down> |
| Unknown fields | <refused (`deny_unknown_fields`) — a field parsed and ignored reads back to its caller as granted> |
| Missing fields | <refused, never defaulted: an empty list is a decision, a missing key is the absence of one> |
| Proof coverage | <which bytes the HMAC covers: both nonces, the sequence, the exact request bytes; label string; what the *answer* frames carry, and if nothing, say "nothing"> |
| Ordering | <e.g. every `VIOLATION` for the lease precedes `EXIT`; `STDOUT` and `STDERR` interleave arbitrarily> |
| Test vectors | <token, nonces, request bytes and the expected hex, asserted on both sides so neither can drift while agreeing with itself> |

**C# record mapping** — field by field, with the note for anything that is *not* sent and why
(an inode number read on Windows means nothing in the guest).

**Compatibility.** <What an older daemon does with a newer bridge and the reverse; which fields a
pre-change daemon omits and how the bridge reads their absence (`0`, `Unavailable`, never a
plausible number).>

**What is not promised.** <List it, the way [`SCHEMA.md`](SCHEMA.md#what-is-not-guaranteed) does.>

## 8. Security analysis

| | |
| --- | --- |
| Tier and adversary | <from [`THREAT-MODEL.md`](THREAT-MODEL.md): which tier, who the adversary is, what they can already do> |
| What this holds against | <concrete: "a leased process of any uid, root included"; "a same-user Windows process" is *not* on the list unless the design makes it so> |
| What it does not hold against, stated plainly | <the row that goes into `SUPPORTED_POLICY.md`'s *Not policed* table if it stays open> |
| Enforced by | <kernel object · kernel LSM hook · a check in SPLAT's process · declaration> |
| New surface | <a new port, file, map, unit, capability; who can reach it; how `doctor` reports it> |
| Cost to the work | <measured before it ships: run each affected template both ways, as `NetworkToolsUnderDenialTests` does. A control goes where it changes an outcome, and its cost is measured first> |

## 9. Evidence plan

A control not observed failing was never measured. Every row below names a file.

| Evidence | Where it lives | Owner | Binds which claim |
| --- | --- | --- | --- |
| Unit tests that **fail against the parent commit** and a negative control showing the legitimate path still works | `tests/…`, `native/…/src/*.rs` `#[cfg(test)]` | agent | |
| Probe checks added | `probe-daemon.sh` / `probe-last-hop.ps1` / a new probe, with the JSON field each writes | agent writes, *you* run under root | |
| Evidence files to re-record, and the source hash they bind to | `native/splat-agent/evidence/*.json`, `native/splat-canary/evidence/*.json` | you | `DocumentationDriftTests` withdraws the README's claim until the hash matches |
| Measurements | `src/splat-bench/evidence/*.json` or a new bench; the number, the machine, the iteration count | agent | latency claims in every document |
| Documents updated in the same commit | [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) · [`SCHEMA.md`](SCHEMA.md) · README status row · `CapabilityManifest` · [`ROADMAP.md`](ROADMAP.md) row · the relevant `ARCHITECTURE-*.md` | agent | the drift tests bind the first three |

## 10. Rollout and compatibility

| | |
| --- | --- |
| Protocol or layout version change | <yes / no; what refuses the old one> |
| `provision` and `doctor` changes | <what `provision --apply` now writes, and how the dry run names it; what `doctor` now reports> |
| Migration | <what an existing host has that this changes: pinned maps, a keyed ledger, a policy file> |
| Rollback / unmount | <how the change is undone, and what it cannot restore> |
| Observability | <the log line, the `HEALTH_RESPONSE` field, the ledger action> |

## 11. Alternatives considered

| Alternative | Why not |
| --- | --- |
| <the obvious one> | <the concrete reason, ideally a measurement or a defect it would reintroduce — e.g. "inheriting exec rights for agent-written files lets the workload author its own permission"> |

## 12. Open questions and decisions that are yours

<Each with who decides, what it blocks, and the default the RFC takes if no decision arrives.>

## 13. Acceptance checklist

An RFC moves to `Accepted` only when every box is checked or struck through with a reason.

- [ ] §3 states the layer's placement and the property that decides it; the continuum map row is updated if it moved.
- [ ] §4 lists every failure mode, and none of them falls back to running uncontained.
- [ ] §5 bounds every allocation, buffer and map; a lagging consumer never blocks the kernel; `pre_exec` code is async-signal-safe.
- [ ] §6 names the capabilities, the kernel configuration, the quotas and the verifier constraints, and what `doctor` says when one is absent.
- [ ] §7 has a layout table with explicit padding, a `const` size assertion, a frame cap, a refusal for unknown and missing fields, and test vectors asserted on both sides.
- [ ] §8 names the tier, who enforces the boundary, and what it does not hold against.
- [ ] §9 names the test that fails on the parent commit, the probe field, the evidence file and its source hash, and every document changed in the same commit.
- [ ] No sentence in the RFC promises a latency the benchmark did not record, or a capability the evidence file does not show.
- [ ] Commit subjects follow `type(scope): what changed, and why it matters`; finding ids and template ids are append-only.
