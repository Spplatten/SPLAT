<!-- Index for docs/. If you add a document here, add its row. An unlisted document is one nobody
     will find, and an unmaintained row is worse than no row - the whole point of this file is that
     a reader can tell, without opening anything, which documents are still true. -->

# docs/ — what is in here, and which of it is still true

Last reconciled **2026-09-09**, when five superseded plan documents were removed. Read
[the OEM subtraction plan](audits/2026-09-09-oem-subtraction-plan.md) first; everything else is
either an input to it, an artifact it produces, or a record of how the project got here.

---

## The live plan

| Document | What it is |
| --- | --- |
| [audits/2026-09-09-oem-subtraction-plan.md](audits/2026-09-09-oem-subtraction-plan.md) | **The current plan.** Phases P0–P3, the monetization argument, the term-sheet defects. Supersedes every plan document below it. |
| [RUNBOOK-human-steps.md](RUNBOOK-human-steps.md) | What only a human can do — the `sudo` steps, the SDK installs, the reboots. Nothing in it is open right now — Part 0, the .NET 10 SDK, closed 2026-09-09. |
| [audits/2026-09-05-orchestration-plan.md](audits/2026-09-05-orchestration-plan.md) | Re-sequenced, not retired. Its Phase 1 was subtracted and its Phase 2 rescoped, but its ordering argument still holds. |

## Prospect-facing

Machine-checked: `DocumentationDriftTests` reads every non-`PLAN-` file in this directory and fails
the build if one promises latency the benchmark did not measure. Write accordingly.

| Document | Audience | Status |
| --- | --- | --- |
| [BRIEF-technical-one-pager.md](BRIEF-technical-one-pager.md) | An engineer who will decide in thirty minutes | **Current.** The one to send. Its "what is NOT proven" section is the reason it works. |
| [SPLAT-Field-Guide.html](SPLAT-Field-Guide.html) | Someone learning what SPLAT does, from zero | **Current, and the source of truth** for [TUTORIAL.md](TUTORIAL.md) and the published artifact. Change this one first, then re-sync the other two. |
| [TUTORIAL.md](TUTORIAL.md) | Same reader, in the repo | Derived from the Field Guide. Do not edit independently. |
| [SPLAT-Enterprise-Executive-Brief.md](SPLAT-Enterprise-Executive-Brief.md) | A direct enterprise buyer | **Audience superseded.** Kept as long-form positioning and as source material for an OEM licensee's own materials. |
| [PITCH-Microsoft-CorpDev-Copilot-Safety.md](PITCH-Microsoft-CorpDev-Copilot-Safety.md) | Microsoft CorpDev | **Byproduct, not a path.** Becomes possible with a traction record; do not sequence work around it. |

## Commercial

| Document | What it is |
| --- | --- |
| [TARGETS-cold-outreach.md](TARGETS-cold-outreach.md) | Who to contact, in what order, and what to sell them on the first call. Updated 2026-09-09 for the assessment motion. |
| [PLATTEN-INDUSTRIES-MASTER-PROPOSAL.md](PLATTEN-INDUSTRIES-MASTER-PROPOSAL.md) | **Partly superseded.** Its four direct-sales tracks were set aside for OEM licensing; the buyer-pain analysis and unit economics survive. |

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

## Removed 2026-09-09

Five build plans for work that has since shipped. Git has them —
`git log --diff-filter=D --name-only -- docs/` finds the commit.

| Removed | Why |
| --- | --- |
| `PLAN-kernel-substrate.md` | Opened with "there is no Rust, no eBPF, no vsock, no WSL code." All four now exist and are proven under root. |
| `PLAN-agent-trust-layer.md` | Eight phases productizing the substrate. Phases 0, 1, 2 and 6 shipped; 3, 4 and 7 are now P2, P3 and §7 of the live plan. Its successor already recorded that it stated falsehoods about the tree. |
| `PLAN-substrate-completion.md` | Two of four gates closed — the transport ambiguity settled by deleting `proto/`, kernel evidence machine-checked. Windows egress is only half closed: enforced for tools that need no network, a governance claim for the four `EgressScope.ToolProcess` templates (recorded here as closed until 2026-09-10). First-run provisioning moved to P1. |
| `PLAN-versatility-paths.md` | Both paths built: `WorkflowSynthesizerEngine` for Path A, `splat-mcp` for Path B. |
| `AGENT-BUILD-BRIEF.md` | A seed prompt for a session that would build the kernel substrate. That substrate is built, and its "ground truth already established" block had gone stale in the dangerous direction. |

---

## Documents that are not in this directory

| Where | What |
| --- | --- |
| [`../native/splat-agent/SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) | What a lease actually enforces, what the daemon refuses, and what is reachable and not claimed. The most load-bearing document in the repository, and the one to attach to any commercial conversation. |
| [`../README.md`](../README.md) | The repository's own front page. Test-bound: claims about kernel enforcement are checked against the hash of the BPF source that ships. |
| [`../scope.md`](../scope.md), [`../IDEAS.md`](../IDEAS.md) | Early scope and idea capture. Historical; the contradiction table in the competition audit is where they were reconciled against the tree. |
