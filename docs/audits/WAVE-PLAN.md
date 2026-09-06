# SPLAT remediation waves

Working plan derived from the four reports in this directory. The audits say *what* is broken and
*why*; this says **which wave it lands in and what has actually shipped**.

Written while two agents were editing `C:\C_AGENT_BUILDER` concurrently; the second session has
since closed, so the ownership columns below are history rather than a live constraint. The rule
they encode is still worth keeping if a second session is ever opened on this tree: name the file
set before starting, and report a finding in someone else's files instead of editing them.

Finding IDs: `Fnn` from [clinical audit](2026-09-04-clinical-audit.md), `AG-Fnn` from
[antigravity deep audit](2026-09-05-antigravity-deep-audit.md). Sequencing rationale is in the
[roadmap](2026-09-04-roadmap.md); positioning in [competition and scope](2026-09-04-competition-and-scope.md).

---

## Wave 1 — Truthful execution and identity (done)

| Finding | Change | Commit |
| --- | --- | --- |
| — | Workflow engine reports node failure, one execution id, injection refused at the binder | `461001b` |
| F16 (part) | `GovernedHttp` and `OAuthExchange` stop claiming work they never did | `461001b` |
| F02 / AG-F02 | Ledger verifies the payload an auditor reads, not just the commitment | `379f86b` |
| F03 | Unkeyed verification no longer accepted once a key is configured | `379f86b` |
| F01 / AG-F03 | MCP resolves identity at the dispatch gate, before any executor or filesystem call | `379f86b` |

Each fix is proven differentially: the attack test fails against the parent commit and passes after,
with a negative control asserting the legitimate path still works.

## Wave 1b — Windows containment and the loopback surface (done, `616c272` + `87ea3df`)

| Finding | Change | State |
| --- | --- | --- |
| F12 | AppContainer denial skips templates whose sensors need WMI / Event Log / Defender RPC | done |
| — | Containment differential tests restored to a PowerShell host; all nine pass | done |
| AG-F01 / F18 | Loopback gate fails closed: minted token, fixed-time compare, Host check, `/webhook` gated, 1 MiB body cap | done |
| AG-F05 | OAuth `state` recorded, compared in fixed time, expired at 10 min, consumed on success | done |

The gate as first written returned `true` when no token was configured — the default — so a host
that had never set `SPLAT_API_KEY` was as open as before it existed, while the test asserting a 401
for a wrong token still passed. That shape is the one to watch for elsewhere: a check whose negative
case is tested and whose unconfigured case is not.

---

## Wave 2 — Failure is not evidence (done, `0f78cf0` + `616c272`)

A failed run must not become accepted evidence, indexed memory, or a successful tool result.

| Finding | Change | State |
| --- | --- | --- |
| F16 | `AgentReasoning` with no model fails instead of emitting `Status: VERIFIED` over a char count | done |
| F16 | Simulated execution is opt-in (`allowSimulatedExecution`), off by default | done |
| F13 | `QualityIslandEngine`'s offline path reports its own evaluation instead of hardcoding success | done |
| F13 | `SandboxedRemediationEngine` fails on timeout; the ledger action name carries the verdict | done |
| F13 | `MissionExecutionEngine` stops on nonzero exit and timeout instead of logging and continuing | done |
| F14 | Raw stdout/stderr is sanitized before it leaves the engine, not only before the model call | done |
| F20 | A remediation verdict comes from a postcondition, not only from an exit code | **open — design, not a patch** |

Also done: the quality gate's verdict now decides the ledger action, whether the analysis is
indexed, and whether the run reaches a Completed chunk.

Remaining in this theme is F20 — a remediation verdict that comes from a measured postcondition
rather than an exit code. The timeout fix narrows it; closing it needs each action to declare what
restored means, which is a design, not a patch.

## Wave 3 — Linux fail-closed and lease isolation (done)

| Finding | Change | State |
| --- | --- | --- |
| F04 | Daemon exits rather than serving without live BPF maps; `--mock-bpf` is the only way to ask for a non-enforcing one | done, `f2e77f9` |
| F04 | Health reports observed state and an `enforcing` field, instead of three hardcoded `true` and a fixed kernel string | done, `f2e77f9` |
| F04 | A failed map write refuses the lease and rolls back, instead of warning and registering it | done, `f2e77f9` |
| F09 | Clamps resolved before the cgroup exists, written with errors propagated, read back, and refused if looser than requested | done, `f2e77f9` |
| F05 | Expiry kills inside the installed policy and only then withdraws it; a lost client kills too; `Drop` drains before `rmdir` | done, `f2e77f9` |
| F06 | Every policy key carries the cgroup id, so concurrent leases stop receiving the union of each other's permissions | done |
| F07 | Every EXECUTE_TOOL presents a root-owned 0600 token, compared in constant time; the workload drops to an unprivileged uid before exec, or the spawn fails | done |
| F08 | `SUPPORTED_POLICY.md` states what each hook enforces, what the daemon enforces, what it refuses and what it does not police; `readOnlyFs` and `overlayFs.enableCow` are refused rather than ignored; the connect hook now keys on address AND port and denies IPv6 | done |

Evidence: `native/splat-agent/evidence/fail-closed-probe.json` records the same invocation at both
commits — the committed daemon started unprivileged with no BPF and answered `bpfLsmActive: true`;
the current one exits 1.

F07's remaining half is provenance, not authentication: the daemon still appends the caller's
requested command to that lease's own exec allow-list, and the bridge still drops the
`ProtectedInodes` / `AllowedExecInodes` the controller computed because Windows inode identities
mean nothing in the guest. Resolving that is F11's wire contract - one versioned envelope carrying
paths the daemon resolves where they are enforceable - not a patch to this code.

**PROVEN.** `native/splat-agent/evidence/daemon-probe.json`, verdict PASS, 15 checks against a root
daemon on kernel 6.18.33.2. F05's kill-on-expiry, F06's concurrent-lease isolation, F07's
root-to-nobody transition and F08's port and IPv6 checks all held in one run, alongside the three
original hooks. The record carries the SHA-256 of the BPF source it exercised, and
`TheDaemonEnforcementClaim_MatchesItsProbeEvidence` fails the build if the README claims enforcement
while that hash does not match what ships — so the proof cannot outlive the program, which is
exactly how the previous one had been standing over a rewritten kernel program.

Getting there took two failed runs, and both were worth more than the green one.

**The first refused every lease at `memory.max`.** `/sys/fs/cgroup/splat_leases` had never written
its controllers to `cgroup.subtree_control`, so `mission_X/memory.max` did not exist and the
resource clamps had **never applied — not once, for the life of the substrate**. It was invisible
because the clamp write was `let _ = fs::write(..)` and the ENOENT went in the bin. F09's read-back
is the only reason it surfaced, and it surfaced on the first real lease a real daemon tried to
provision. No amount of userspace testing was going to find this: the whole failure lived in the gap
between what a mock daemon does and what a root one does.

**The second mis-scored two checks, and both were the probe's fault.** The protected-file test read
`/etc/shadow` and expected a kernel violation — but F07 now drops the workload to `nobody`, and mode
640 denies that read in the DAC check *before* `security_file_open` is reached. F07's own success had
quietly turned that test into a measurement of nothing, and the probe blamed the daemon for it. It
now runs a differential on `/etc/hostname` (644, so `nobody` genuinely can read it): a control run
reads the file, the leased run is denied, and the control feeds the verdict so a denial is only
scored when the same read succeeds without the protection. Separately, the expiry clock was timing
the probe's own socket settle rather than the kill — `call()` now stops at the EXIT frame.

The lesson worth keeping: **a passing check whose control was never verified is not a measurement.**
Two of the three problems this exercise found were tests that could not fail.

## Wave 4 — Boundaries and the wire contract

| Finding | Change |
| --- | --- |
| F10 | MCP filesystem confinement is handle-based: the object is opened, its final path checked against the root via GetFinalPathNameByHandle, and that same handle used for the read or write | **done** |
| F11 | One versioned wire contract: explicit `argv`, and the compiled policy carried as paths the guest resolves | **done** — `protocolVersion: 2`; a v1 request is refused rather than guessed at |
| AG-F06 | DLP gains bare-token rules (AWS, GitHub, OpenAI, Stripe, JWT) — today only `key=value` shapes redact |
| AG-F07 | Recalled memory is wrapped in untrusted delimiters before it reaches a prompt |
| F15 / F17 | A workflow step is a governed mission; the engine is registered against the real substrate | **done** — `87918b2` |

### F15 / F17 — the subtraction

A `SandboxedScript` node spawned `powershell.exe` directly: application-directory working directory,
a job object, and none of the ACL jail, restricted token, AppContainer denial, egress pin, argument
binder, DLP pass or ledger row a mission gets — inside a graph the operator was told was governed.
The workflow layer existed to protect exactly the thing it bypassed. A step is now a
`GovernedMission` naming a catalogue template; the workflow contributes ordering and nothing else.
`SandboxedScript` stays in the enum so a stored graph deserialises and says why it stopped.

Three findings surfaced doing it, and the first is the one worth keeping:

**The engine was registered nowhere.** `IWorkflowExecutionEngine` had no entry in the container. It
was constructed only by its own tests, so every guarantee it grew was a guarantee no shipped code
path could reach — and the suite stayed green throughout, because a test composes the engine itself.
This is the same shape as Wave 1b's unconfigured gate and Wave 3's `let _ = fs::write`: **the case
nobody tested was the case that shipped.** `CompositionRootTests` now binds the registration as
source text, which is the strongest assertion available from a project that cannot reference WinUI.

**A trigger payload had no addressable fields.** `{trigger}` yields the whole multi-line `key=value`
blob, which the governed binder refuses for the line break alone — correctly. Every webhook-driven
workflow would therefore either fail outright or go back to splicing blobs into a command line.
Fields are now `{trigger-node-id.field}`, namespaced under the node so an unauthenticated caller
cannot choose a key that shadows a measured output.

**The synthesiser emitted fabricated evidence.** One node wrote out `Active Campaigns: 4 | Total
Spend: $1,250 | CTR: 2.84%` and a "Financial Parser Agent" analysed a $3,450.00 invoice the node
above it had invented. Synthesised workflows now compose catalogue templates, and a test binds every
synthesised id to the shipped catalogue so a typo fails at build time rather than at first run.

What is **not** done: there is no workflow view, no persistence (`InMemoryWorkflowRegistry` is the
only registry, so a restart loses everything), and neither `WorkflowScheduler` nor
`EmbeddedWebhookListener` is constructed outside tests. See [the orchestration
plan](2026-09-05-orchestration-plan.md).

## Wave 5 — Release reality

| Finding | Change |
| --- | --- |
| F21 | Replace the affected `SQLitePCLRaw` native bundle; plan the Windows App SDK 1.6 exit |
| F22 | Packaging fails on missing assets, missing signing tools and nonzero native exit codes |
| F19 | Revocation survives restart and is consulted by every entrypoint |
| F23 | Retention inspects checkpoint results and states what erasure does and does not cover |
| F24 | One capability manifest that UI, MCP descriptions, docs and tests all read from |

Positioning corrections from the competition audit — the ROI arithmetic, the "every mainstream
approach" and "every cloud sandbox" claims, the unsupported 90% — can land in any wave; they are
independent of the code.

---

## The ordering argument

Wave 2 went before Wave 3, and that ordering held up. A kernel boundary that cannot be bypassed is
worth little while the layer above it reports a failed run as a success — the strongest containment
in the world still hands the operator a confident wrong answer. Truthful results were also the
cheapest wave, and they are what makes every later gate measurable: with the engine now refusing a
dead sensor and a rejected analysis, a Wave 3 exit gate can be asserted on the result rather than
inferred from a log line.

**Wave 3 is done and proven.** It was the largest remaining block, it is entirely Rust, and F04/F05/F06 are the
three findings that most directly contradict the product'''s central claim — a daemon that runs work
without the policy it reported installing, a lease whose expiry removes enforcement but not the
workload, and capability maps shared across missions.

Wave 4's `F15/F17` was the decision the competition audit kept circling, and it is taken: SPLAT does
not beat n8n on breadth, so the workflow layer became a DAG scheduler *over* `IMissionExecutionEngine`
where each node is a complete 1:1:1 mission. That subtraction shipped in `87918b2`.

**Next is the runtime floor, and it is a deadline rather than a wave.** .NET 9 leaves support on
2026-11-10 — nine weeks — and .NET 8 leaves the same day, so there is no LTS below 10 to fall back
to. Windows App SDK 1.6, which this repo pins, has been out of support since 2025-09-04. Both are
one migration: WinAppSDK 2.x targets .NET 10. Everything in Wave 5 sits behind it, and so does every
line of the orchestration plan. See [the orchestration plan](2026-09-05-orchestration-plan.md),
Phase 0.
