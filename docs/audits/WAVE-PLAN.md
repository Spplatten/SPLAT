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

## Wave 3 — Linux fail-closed and lease isolation (F04/F05/F06/F07 done)

| Finding | Change | State |
| --- | --- | --- |
| F04 | Daemon exits rather than serving without live BPF maps; `--mock-bpf` is the only way to ask for a non-enforcing one | done, `f2e77f9` |
| F04 | Health reports observed state and an `enforcing` field, instead of three hardcoded `true` and a fixed kernel string | done, `f2e77f9` |
| F04 | A failed map write refuses the lease and rolls back, instead of warning and registering it | done, `f2e77f9` |
| F09 | Clamps resolved before the cgroup exists, written with errors propagated, read back, and refused if looser than requested | done, `f2e77f9` |
| F05 | Expiry kills inside the installed policy and only then withdraws it; a lost client kills too; `Drop` drains before `rmdir` | done, `f2e77f9` |
| F06 | Every policy key carries the cgroup id, so concurrent leases stop receiving the union of each other's permissions | done |
| F07 | Every EXECUTE_TOOL presents a root-owned 0600 token, compared in constant time; the workload drops to an unprivileged uid before exec, or the spawn fails | done |
| F08 | Publish the actual supported syscall/protocol matrix and refuse policy outside it | **open** |

Evidence: `native/splat-agent/evidence/fail-closed-probe.json` records the same invocation at both
commits — the committed daemon started unprivileged with no BPF and answered `bpfLsmActive: true`;
the current one exits 1.

F07's remaining half is provenance, not authentication: the daemon still appends the caller's
requested command to that lease's own exec allow-list, and the bridge still drops the
`ProtectedInodes` / `AllowedExecInodes` the controller computed because Windows inode identities
mean nothing in the guest. Resolving that is F11's wire contract - one versioned envelope carrying
paths the daemon resolves where they are enforceable - not a patch to this code.

**The F06 in-kernel proof is outstanding.** The change is verified at the key layer — byte-level
tests over the same `lease_map_keys` the live driver calls, plus size and alignment assertions
against the BPF structs — but the audit's exit gate is concurrent A/B leases proving in the kernel
that A cannot use B's permission, and that needs a root daemon. Re-running
`native/splat-agent/probe-daemon.sh` under root closes this and restores the README's enforcement
claim, which is withdrawn until then. The same run is what proves F07's privilege drop actually
transitions - on an unprivileged dev daemon `drop_privileges` takes its already-unprivileged path,
so `setgroups`/`setresgid`/`setresuid` have never executed: the recorded probe passed against a program that has since
been re-keyed, and `TheDaemonEnforcementClaim_MatchesItsProbeEvidence` now binds that claim to the
agent BPF source the way the canary guard always bound the canary's.

## Wave 4 — Boundaries and the wire contract

| Finding | Change |
| --- | --- |
| F10 | MCP filesystem confinement is handle-based and race-resistant, not a path-prefix string compare |
| F11 | One versioned wire contract: explicit `argv`, and the compiled policy carried as paths the guest resolves | **done** — `protocolVersion: 2`; a v1 request is refused rather than guessed at |
| AG-F06 | DLP gains bare-token rules (AWS, GitHub, OpenAI, Stripe, JWT) — today only `key=value` shapes redact |
| AG-F07 | Recalled memory is wrapped in untrusted delimiters before it reaches a prompt |
| F15 / F17 | The workflow builder either registers and runs the graph it draws, or stops advertising that it does |

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

**Next is Wave 3.** It is the largest remaining block, it is entirely Rust, and F04/F05/F06 are the
three findings that most directly contradict the product'''s central claim — a daemon that runs work
without the policy it reported installing, a lease whose expiry removes enforcement but not the
workload, and capability maps shared across missions.

Wave 4's `F15/F17` is the decision the competition audit keeps circling: SPLAT will not beat n8n on
breadth, and the workflow layer as built bypasses the mission engine it exists to protect. The
smaller, more defensible shape is a DAG scheduler *over* `IMissionExecutionEngine`, where each node
is a complete 1:1:1 mission that keeps its jail, egress pin, DLP pass and ledger row. That is a
subtraction, and it should be decided before more nodes are added.
