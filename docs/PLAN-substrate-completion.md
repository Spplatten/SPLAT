# SPLAT completion plan — making the remaining claims provable

**What this plan is.** [PLAN-kernel-substrate.md](PLAN-kernel-substrate.md) sequenced the substrate
build; [PLAN-agent-trust-layer.md](PLAN-agent-trust-layer.md) productizes it;
[PLAN-versatility-paths.md](PLAN-versatility-paths.md) covers synthesis and the MCP facade. All three
sequence *features*. This plan closes what is left, and it is ordered by a different axis: **the
distance between what SPLAT claims and what SPLAT can prove.**

That reordering is the point. As of 2026-09-02 the repository machine-checks its own advertised
*test count* ([DocumentationDriftTests.cs](../tests/MissionController.Tests/DocumentationDriftTests.cs))
but does not machine-check the `-EPERM` kernel enforcement that the entire product rests on. The
cheapest claim is enforced by CI; the load-bearing one is a transcript a human pasted into a
markdown file. Every gate below is ordered to correct that inversion first.

---

## Ground truth (verified against the tree 2026-09-02, not from the other plan docs)

Re-verify before building on any line of this — the tree is shared and moves under you.

| Piece | Real state |
| :--- | :--- |
| BPF-LSM program + hooks | Built. `bprm_check_security`, `file_open`, `socket_connect` in [lease_lsm.bpf.c](../native/splat-agent/src/bpf/lease_lsm.bpf.c) |
| Resident daemon | **Does not compile.** `splat-agent` is written — tokio, TCP listener, ephemeral cgroup, child spawn — but `cargo build` fails with 4 × E0106 at [main.rs:50-53](../native/splat-agent/src/main.rs): `libbpf_rs::Map` needs a lifetime parameter in libbpf-rs 0.24. An earlier revision of this table said "Built" on the strength of reading the source; building it is the only way to know |
| Canary harness | **Now asserts** (2026-09-02). Computes a verdict from the ringbuf events, writes `evidence/canary-<kernel>.json`, and exits non-zero on a bad run. Awaiting its first passing run |
| `(dev, ino)` map key | **Fixed** (2026-09-02). Userspace passed `st_dev` where the kernel builds `(major << 20) \| minor`, so every lookup missed — exec failed closed, protected inodes failed **open**. Same bug fixed in the daemon's `lease.rs` |
| OverlayFS CoW | `setup`/`teardown` implemented ([cow.rs](../native/splat-agent/src/cow.rs)); not yet driven per mission from the host |
| Policy compiler | `TemplatePolicyCompiler.CompileTemplatePolicy` exists (template → `LeaseSpec`); the kernel round-trip is unproven |
| Transport | **TCP loopback + newline JSON**, not vsock + gRPC. `splat-agent` has no `tonic`/`prost`; [proto/splat_sandbox.proto](../proto/splat_sandbox.proto) is written and unused. `WslLeasedExecutor` has a `useVsock` flag defaulting to `false` |
| Windows egress for tools | **Absent.** `Win32JobSandbox` has no egress concept. Job objects clamp CPU/memory/PIDs; they do not filter sockets |
| WSL provisioning | Manual (`setup-guest.sh`). No `WslProvisioner` |

**Two documents disagree about the same fact.** README calls the canary run "the next gate";
PLAN-kernel-substrate.md Phase 1 says "✅ MET (2026-08-29)" and quotes real `-EPERM` output. Both
cannot be right, and *nothing in the repository can settle it* — which is itself the finding.
Gate 0 exists to make that question answerable by running something rather than by asking a person.

---

## Gate 0 — Make the substrate proof reproducible and machine-checked

**BLOCKING for every honesty claim in README, the Field Guide, and the pitch.** Nothing else here
matters as much: if this is not done, every downstream capability inherits an unverifiable base.

1. **Make the canary assert.** `run-canary.sh` currently narrates its expectations to a human. It
   should exit non-zero unless it observes exactly: one ALLOWED action, and `-EPERM` from all three
   hooks (exec / open / connect). A proof harness that cannot fail is not a proof harness.
2. **Emit structured evidence.** Write `native/splat-canary/evidence/canary-<kernelrelease>.json`:
   kernel release, LSM list, BTF presence, cgroup version, the four outcomes with pids/inodes, UTC
   timestamp, and the git SHA of the BPF source that produced it. Commit it.
3. **Assert the docs against the evidence.** Extend `DocumentationDriftTests` with a test that reads
   the newest evidence file and fails if README/TUTORIAL describe the substrate as unproven while
   valid evidence exists — or describe it as proven while none does. This is the same mechanism as
   the test-count check, pointed at the claim that actually matters.
4. **Bind evidence to the source it proves.** If `lease_lsm.bpf.c` changes and no newer evidence
   file exists, the test fails. Proof of an older program is not proof of this one.

**DoD:** `bash run-canary.sh` exits 0 only on a genuine four-outcome run and leaves a committed
evidence file; deleting or staling that file turns the suite red; README and the Field Guide agree
with the evidence, and are *made* to agree by a test rather than by memory.

**Human-only:** the run itself needs `sudo` inside WSL for BPF-LSM load, and `sudo` here prompts for
a password an agent cannot supply. Everything else is agent-buildable. Step-by-step in
[RUNBOOK-human-steps.md](RUNBOOK-human-steps.md).

**Starting position is better than the plan docs assume (verified 2026-09-02):** preflight is
**GREEN** on this machine — `bpf` is live in the active LSM list, BTF and cgroup v2 are present, the
full toolchain is installed and `vmlinux.h` is generated for both crates. Nothing is blocked on
setup; the gate is blocked only on the harness being unable to fail.

---

## Gate 1 — Close the Windows egress gap

The Field Guide's Ring 4 ("one phone line — outbound traffic to exactly one approved address") is
**true for the model API calls** — `HardenedHttpClientFactory` pins those — and **false for spawned
tool processes on Windows**, where nothing filters sockets. The guide already admits this in prose.
It became a live concern rather than a theoretical one when the grant-discovery template shipped:
the first specialist whose tool reaches the internet at all.

Ordered by cost, pick one:

- **A. Loopback egress broker (recommended first move).** Deny the tool direct network access and
  give it a per-mission proxy endpoint that enforces the template's `EgressRule`. Fully user-space,
  no driver, testable on any dev box. Weakness: a tool that ignores proxy variables bypasses it — so
  pair with B or accept it as defence-in-depth only, and say so.
- **B. WFP filter bound to the job object's processes.** Real enforcement at the platform layer, and
  the honest analogue of the eBPF story. Cost: a filter driver or WFP user-mode callout, elevation,
  and signing.
- **C. AppContainer / network isolation capabilities.** Strip `internetClient` from the tool's
  container so *no* egress is possible, and permit only templates that declare no destination.
  Cheapest correct option for the majority of templates, which need no network at all.

C first (it fits most of the catalog), then A for templates that do need egress, with B as the
enforcement endgame. **Until one lands, no template whose destination is unenforced may be described
as contained** — encode that as a test over the catalog, not a promise in prose.

**DoD:** a template declaring destination X cannot reach Y from its tool process, demonstrated by a
test; the Field Guide's Windows caveat is removed only when the test proves it obsolete.

---

## Gate 2 — Settle the transport story

`proto/splat_sandbox.proto` describes a gRPC contract nothing implements; the daemon speaks
newline-JSON over TCP loopback. Two honest options, and the wrong move is leaving both in the tree:

- **Implement it** — `tonic` + `prost` in `splat-agent`, `AF_VSOCK` instead of TCP. Vsock is the real
  win, and not for latency: TCP on loopback is reachable by *any* local process, so port 50051 is an
  authentication problem the moment the daemon does anything privileged. Vsock removes that surface.
- **Or delete the proto**, document the JSON line protocol as the contract, and drop the vsock flag.

Either way: **measure and publish p50/p99**, and replace the inherited `<1ms` marketing figure with
the measured number. `WslLeasedExecutor` already carries a `Stopwatch`; wire it to the ledger so the
number is observed in production rather than benchmarked once.

**DoD:** one transport in the tree; a recorded latency distribution; no unimplemented contract left
lying beside a working one; if TCP survives, the daemon authenticates its caller.

---

## Gate 3 — First-run provisioning

`WslProvisioner`: detect WSL, import the distro asset, run `setup-guest.sh`, health-check via
`WslSubstrateHealthChecker`, and report a specific actionable failure rather than a silent fallback
to the Windows path. **The failure mode that matters:** a user believing they have kernel containment
when provisioning quietly failed. Fail loud, name the missing piece, and make the UI state which
substrate is actually active for every mission.

**DoD:** clean machine → app launch → kernel-contained mission, with no manual shell steps; a
deliberately broken provision produces a specific error and a UI that does not claim containment.

**Human-only:** `wsl --install` and reboot.

---

## Gate 4 — Remaining substrate capabilities

Unblocked once Gate 0 makes the base provable. Each is real work, none is load-bearing for honesty.

- **Keyring-gated ephemeral capabilities** (kernel-substrate Phase 4). Lease-scoped credentials in
  the Linux keyring; a tool cannot read another lease's key. Name it *capability binding*, never
  intent verification.
- **Per-mission CoW rollback** (Phase 5). `cow.rs` exists; drive it per mission and prove the host
  tree is untouched after a mission that corrupts its workspace.
- **Contract → kernel round-trip** (Phase 6). `CompileTemplatePolicy` already produces a `LeaseSpec`;
  prove that editing a template's declared egress changes what the kernel permits, and that an
  under-declaring template fails closed.

---

## Cross-cutting — keep the plans honest

The three existing plan docs have drifted from the tree in *both* directions:
PLAN-agent-trust-layer.md states "no resident daemon exists yet" (false since `6dc0d55`), while
PLAN-kernel-substrate.md claims a canary DoD the repository cannot substantiate. A stale plan is
worse than no plan, because it is acted on.

- Fold this file's ground-truth table into those docs, or mark their status blocks superseded.
- Every future DoD lands as **an assertion, not a sentence**: the pattern is now established twice
  (tool documentation, test count) and should be the default for any checkable claim.
- The published Field Guide artifact is the one copy no test can police. Any gate that changes what
  Part 7 says must update it in the same change.

---

## Sequence

```
Gate 0 ──> Gate 2 ──> Gate 3 ──> Gate 4
  │                      ▲
  └──> Gate 1 ───────────┘
```

Gate 0 first and alone — it is what makes every later claim checkable. Gate 1 runs in parallel: it is
Windows-side and shares no code with the substrate, and it is the only gate closing a gap that is
live in shipped software today.
