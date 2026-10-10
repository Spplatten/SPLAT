<!-- Index for docs/. If you add a document here, add its row. An unlisted document is one nobody
     will find, and an unmaintained row is worse than no row - the whole point of this file is that
     a reader can tell, without opening anything, which documents are still true. -->

# docs/ — what is in here, and which of it is still true

A filename beginning `...` is a document whose work is finished: a template that is only ever
copied, a brief whose audience was superseded, a record of decisions already taken. It is kept,
not deleted, because something still cites it — the row below says what — and the prefix sorts it
out of the way of the documents that are still moving. The prefix changes nothing else:
`DocumentationDriftTests` enumerates `*.*` and filters on extension, so a renamed file is still
scanned for unmeasured claims and broken links exactly as before. It cannot be applied to
`README.md`, `ROADMAP.md`, `RUNBOOK-human-steps.md`, `TUTORIAL.md`, `SPLAT-Field-Guide.html` or
`SPLAT-Field-Guide.published`, which the tests read by literal name.

Finished is not the same as removed. Five build plans were deleted outright on 2026-09-09 and are
recorded at the bottom of this file; those had nothing left citing them.

Last reconciled **2026-10-01**, when three internal commercial documents moved out of this directory to the untracked `private/` — the row at the bottom of this file says which, and why. Before that, **2026-09-26**: model-proposed parameter targeting landed in the ReAct loop ([ARCHITECTURE-control-plane.md](ARCHITECTURE-control-plane.md)) and the README's last-hop claim was restored against the kernel program that ships; the two governance templates and the status-gate record date from 2026-09-23, and the architecture, context and module reference from 2026-09-10.
Read [the OEM subtraction plan](audits/2026-09-09-oem-subtraction-plan.md) first; everything else
is either an input to it, an artifact it produces, or a record of how the project got here. To
change the code rather than the plan, start with [CONTEXT.md](CONTEXT.md).

---

## The live plan

| Document | What it is |
| --- | --- |
| [END-GOAL.md](END-GOAL.md) | **The destination.** SPLAT as a kit you mount from a drive or a download, and unmount cleanly: what it takes, what exists, and what is yours to decide. A design, never a claim. |
| [SCOPE-acting-agents.md](SCOPE-acting-agents.md) | **What SPLAT is for.** Agents that act, not only read: where each part runs, why every action goes through the Linux lease, how a secret lives for one step, and the order of work. Roadmap P5 tracks it. |
| [DAEMON-PRODUCT-PLAN.md](DAEMON-PRODUCT-PLAN.md) | The 2026-10-10 daemon priorities and acceptance gates: step secrets, concurrent platforms, hostname enforcement, local inference and a licensed Linux service. Planned capabilities, with the current proof boundary retained. |
| [audits/2026-10-10-desktop-substrate.md](audits/2026-10-10-desktop-substrate.md) | Local 5.0 verification, the remaining live proof and the exact external-data scope awaiting approval. |
| [ROADMAP.md](ROADMAP.md) | **The status record.** Every open item, who can do it, what "done" means, and the evidence for its current state — checked against the tree, not carried forward from older plans. |
| [audits/2026-09-09-oem-subtraction-plan.md](audits/2026-09-09-oem-subtraction-plan.md) | **The current plan.** Phases P0–P3, the monetization argument, the term-sheet defects. Supersedes every plan document below it. |
| [RUNBOOK-human-steps.md](RUNBOOK-human-steps.md) | What only a human can do — the `sudo` steps, the SDK installs, the reboots. Nothing in it is open right now — Part 0, the .NET 10 SDK, closed 2026-09-09. |
| [GUIDE-operator.md](GUIDE-operator.md) | For the operator, after the 2026-09-20 substrate audit: what changed and why, a reading order for the Linux side, and the root steps that are theirs, with commands and expected output. |
| [audits/2026-09-23-status-gate-and-gap-analysis.md](audits/2026-09-23-status-gate-and-gap-analysis.md) | The five-layer status gate read out of the tree at `40caaa0` — sandbox, telemetry, state machine, auth broker, audit trail — with the top three critical-path fixes, the pragmatism-versus-decoupling verdict, and the minimal demonstration set for an external evaluator. |
| [audits/2026-09-20-substrate-hardening.md](audits/2026-09-20-substrate-hardening.md) | The five weaknesses of the Linux lease after the audit — deny-list not jail, UDP unpoliced, nothing survives the daemon, the shared secret, the unproven record change — with a recommendation, an order and a proof for each. Feeds P2 of the plan. |
| [audits/2026-09-05-orchestration-plan.md](audits/2026-09-05-orchestration-plan.md) | Re-sequenced, not retired. Its Phase 1 was subtracted and its Phase 2 rescoped, but its ordering argument still holds. |

## How the code is put together

Reference, not plan: these describe the tree as it is, and are corrected when the code moves.

| Document | What it is |
| --- | --- |
| [CONTEXT.md](CONTEXT.md) | **Start here to change the code.** What SPLAT is for, where it stands, the rules this repository holds itself to, its vocabulary, and the traps. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | The map: which layer enforces each boundary, how the two hosts differ, the life of a mission, and what is built but not wired. |
| [ARCHITECTURE-control-plane.md](ARCHITECTURE-control-plane.md) | Core, Network and Data: the 1:1:1 template, the mission pipeline, the model leg, the engines that compose missions, the ledger and memory. |
| [ARCHITECTURE-windows-substrate.md](ARCHITECTURE-windows-substrate.md) | What a Windows sensor process experiences — jail, job object, restricted token, AppContainer — and which apply when. |
| [ARCHITECTURE-linux-substrate.md](ARCHITECTURE-linux-substrate.md) | The BPF-LSM lease, the `splat-agent` daemon, the bridge on Windows, who authors a lease, and the evidence behind it. |
| [ARCHITECTURE-agent-surface.md](ARCHITECTURE-agent-surface.md) | How an external agent gets in: `splat-mcp`, the LangGraph adapter, the Copilot / Semantic Kernel adapter. |
| [SCHEMA.md](SCHEMA.md) | The lease's three contracts: BPF map keys and the ring-buffer record byte for byte, the protocol 3 frames and proofs, and the C# records they map to — with what the protocol does not promise. Added 2026-09-20. |
| [RUNBOOK.md](RUNBOOK.md) | What a kernel and a guest need for the daemon to enforce, copy-paste setup for WSL2, the installed unit, and where a developer's shortcuts diverge from a hardened deployment. Added 2026-09-20. |
| [MODULE_INFO.md](MODULE_INFO.md) | Every buildable unit: target, references, packages, what it owns, its tests, and whether it ships. |

## Governance templates

Reusable shapes for the two kinds of document this project writes, added 2026-09-23. Both are
scanned by `DocumentationDriftTests` like every other file here.

| Document | Audience | What it is |
| --- | --- | --- |
| [...RFC_TEMPLATE.md](...RFC_TEMPLATE.md) | Systems engineers, kernel programmers, core contributors | The technical design specification: continuum placement with a trade-off matrix, a memory and concurrency contract, kernel and host invariants, a byte-level interface and wire specification, and an evidence plan. Copy to `docs/rfcs/RFC-NNNN-<slug>.md`. |
| [...EXECUTIVE_STATUS_TEMPLATE.md](...EXECUTIVE_STATUS_TEMPLATE.md) | Enterprise buyers, CISOs, compliance officers, executive sponsors | The readiness and governance report: an attested executive summary, the auditability and non-repudiation scorecard, reliability and SLA tracking, and the milestone and risk heatmap. Every cell carries an attestation level. Copy to `docs/status/<date>-executive-status.md`. |

## Coursework

| Document | What it is |
| --- | --- |
| [course/README.md](course/README.md) | Ten-week bottom-up systems and cybersecurity course, with eight- and twelve-week options, executable interface labs, source traces and current repair assignments. |

## Prospect-facing

Machine-checked: `DocumentationDriftTests` reads every non-`PLAN-` file in this directory and fails
the build if one promises latency the benchmark did not measure, or links to a path that does not
exist. Write accordingly.

| Document | Audience | Status |
| --- | --- | --- |
| [BRIEF-technical-one-pager.md](BRIEF-technical-one-pager.md) | An engineer who will decide in thirty minutes | **Current.** The one to send. Its "what is NOT proven" section is the reason it works. |
| [SPLAT-Field-Guide.html](SPLAT-Field-Guide.html) | Someone learning what SPLAT does, from zero | **Current, and the source of truth** for [TUTORIAL.md](TUTORIAL.md) and the published artifact. Change this one first, then re-sync the other two. |
| [TUTORIAL.md](TUTORIAL.md) | Same reader, in the repo | Derived from the Field Guide. Do not edit independently. |
| [...SPLAT-Enterprise-Executive-Brief.md](...SPLAT-Enterprise-Executive-Brief.md) | A direct enterprise buyer | **Audience superseded.** Kept as long-form positioning and as source material for an OEM licensee's own materials. |

## The record — audits, and why they stay

These are dated findings, not plans. Every `Fnn` and `AG-Fnn` cited anywhere in this repository
resolves to one of the first two, so deleting them would orphan the identifiers that the code
comments, commit messages and the live plan all use.

| Document | What it holds |
| --- | --- |
| [audits/2026-09-04-clinical-audit.md](audits/2026-09-04-clinical-audit.md) | Findings `F01`–`F24`. The origin of the numbering. |
| [audits/2026-09-05-antigravity-deep-audit.md](audits/2026-09-05-antigravity-deep-audit.md) | Findings `AG-F01`–`AG-F08`, from a second agent auditing the same tree. |
| [audits/2026-09-04-competition-and-scope.md](audits/2026-09-04-competition-and-scope.md) | The positioning corrections, and the contradiction table that forced the F15/F17 decision. |
| [audits/2026-09-04-roadmap.md](audits/2026-09-04-roadmap.md) | **Superseded as a plan.** Retained for the work-package → F-number map and the six-group evidence contract that P3's run record fills in. |
| [audits/WAVE-PLAN.md](audits/WAVE-PLAN.md) | What each remediation wave contained and which commit closed it. Waves 1–4 done; Wave 5 open behind the runtime floor. |

## Moved out of the repository 2026-10-01

Four documents, to the untracked `private/` at the repository root. Not finished and not superseded
— the distinction this directory draws elsewhere does not apply. They are internal commercial
material whose cost of being read by the wrong person is higher than its value to anyone reading
this tree: a prospect who finds the price ladder learns the floor before the first call, and a
competitor who finds the segment ordering learns the plan. Everything in this directory is written
for a reader who is not us; these three were not.

The engineering reasoning that cited them stays here. Where a link pointed at one, the citing
document now says what the claim was and where the file went, so nothing silently dangles.

| Moved | Why it is not in a public tree |
| --- | --- |
| `TARGETS-cold-outreach.md` | A working prospect list with the segments ordered by speed-to-cash, where to source each, and the honest caveats to carry into a call — including which claim not to make to a regulated buyer. Headed `INTERNAL` from the day it was written. |
| `PLATTEN-INDUSTRIES-MASTER-PROPOSAL.md` | The full price ladder — per seat, per endpoint, MSP wholesale, sovereign bands, add-on packs, hourly rate — and the ROI model that, worked honestly, does not close at list price. Both are load-bearing internally and neither survives contact with a buyer. |
| `PITCH-Microsoft-CorpDev-Copilot-Safety.md` | A brief addressed to one named company's corporate development group, built around that company's own revenue lines. Marked a byproduct rather than a path since 2026-09-09; publishing it tells every other reader the author is shopping. |
| `IDEAS.md` | The idea ledger, and the reason moving the master proposal alone would have been theatre: it carries the same price ladder, the same ROI figure the competition audit refutes, and a valuation comp. Its §5 feature backlog went with it — a list of what is not built yet is its own kind of signal. |

## Removed 2026-09-09

Five build plans for work that has since shipped. Git has them —
`git log --diff-filter=D --name-only -- docs/` finds the commit.

| Removed | Why |
| --- | --- |
| `PLAN-kernel-substrate.md` | Opened with "there is no Rust, no eBPF, no vsock, no WSL code." All four now exist and are proven under root. |
| `PLAN-agent-trust-layer.md` | Eight phases productizing the substrate. Phases 0, 1, 2 and 6 shipped; 3, 4 and 7 are now P2, P3 and §7 of the live plan. Its successor already recorded that it stated falsehoods about the tree. |
| `PLAN-substrate-completion.md` | Two of four gates closed — the transport ambiguity settled by deleting `proto/`, kernel evidence machine-checked. Windows egress is not closed: 33 of 49 catalog templates run network-denied and 16 keep a network stack — see [the roadmap](ROADMAP.md). This row said "closed", then "half closed, four templates", until 2026-09-11. First-run provisioning moved to P1. |
| `PLAN-versatility-paths.md` | Both paths built: `WorkflowSynthesizerEngine` for Path A, `splat-mcp` for Path B. |
| `AGENT-BUILD-BRIEF.md` | A seed prompt for a session that would build the kernel substrate. That substrate is built, and its "ground truth already established" block had gone stale in the dangerous direction. |

---

## Documents that are not in this directory

| Where | What |
| --- | --- |
| [`../native/splat-agent/SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) | What a lease actually enforces, what the daemon refuses, and what is reachable and not claimed. The most load-bearing document in the repository, and the one to attach to any commercial conversation. |
| [`../README.md`](../README.md) | The repository's own front page. Test-bound: claims about kernel enforcement are checked against the hash of the BPF source that ships. |
| [`../scope.md`](../scope.md) | Early scope capture. Historical; the contradiction table in the competition audit is where it was reconciled against the tree. Its companion idea ledger moved to the untracked `private/` on 2026-10-01 — see the row below. |
