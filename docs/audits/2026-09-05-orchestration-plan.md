# Orchestration: from a good engine to a product

Written 2026-09-05, immediately after `87918b2` made a workflow step a governed mission.

The note this answers:

> a good engine, no wiring, no persistence, no connectors, and an architecture that discards the one
> thing that makes SPLAT worth anything.

The last clause is now false — that was the DAG rewrite. The other three are still true, and one of
them has a nine-week fuse attached that has nothing to do with orchestration.

---

## Where the honest line is, today

| | State | Evidence |
| --- | --- | --- |
| Mission execution, Windows | Real. Job object, restricted token, ACL jail, AppContainer denial, argument binder, DLP, ledger row | `HardeningSubsystemTests`, containment differentials read back out of the live kernel object |
| Mission execution, Linux | Real and proven under root | `evidence/daemon-probe.json`, PASS on 15 checks, hash-bound to the BPF source |
| Workflow **execution** | Real, as of `87918b2`. Every step is a mission | `WorkflowGovernanceTests`, 459 tests green |
| Workflow **wiring** | Registered in the container, and that is all | `CompositionRootTests` |
| Workflow **surface** | **None.** Nine views, none of them orchestration | `src/MissionController.UI/Views/` |
| Workflow **persistence** | **None.** `InMemoryWorkflowRegistry` is the only implementation | a restart loses every workflow |
| Workflow **triggers** | `WorkflowScheduler` and `EmbeddedWebhookListener` exist and are constructed nowhere outside tests | `grep -rn "new WorkflowScheduler("` returns nothing in `src/` |
| **Connectors** | Zero, and honestly so. `GovernedHttp` answers `NOT_IMPLEMENTED`, `OAuthExchange` refuses | `WorkflowGovernanceTests` asserts both refusals |

So: the engine can run a governed DAG, and nothing can ask it to. That is the whole gap, and it is
smaller than it sounds — three of the four missing pieces have a working sibling already in the tree
to copy.

---

## Phase 0 — the runtime floor (deadline: 2026-11-10, not negotiable)

This is not part of the orchestration work and it outranks all of it.

| Component | Pinned here | Supported until | Status today |
| --- | --- | --- | --- |
| .NET 9 | every project | **2026-11-10** | 9 weeks |
| .NET 8 | — | **2026-11-10** | same day; not a fallback |
| .NET 10 (LTS) | — | 2028-11-14 | the only destination |
| Windows App SDK 1.6.250108002 | `MissionController.UI` | **2025-09-04** | **out of support for a year** |
| Windows App SDK 1.7 | — | 2026-03-18 | out of support |
| Windows App SDK 1.8 | — | 2026-09-09 | four days |
| Windows App SDK 2.x (`2.4.0`) | — | 2027-04-29 | current; targets .NET 10 |

Two observations that change the shape of this.

**There is no LTS below .NET 10.** The usual hedge — "fall back to the last LTS" — does not exist
here, because .NET 8 and .NET 9 expire on the same date. The only supported runtime after
2026-11-10 is .NET 10.

**The WinAppSDK problem is older and worse than the .NET one, and it is the same migration.** The
repo pins 1.6.250108002 — not even the last 1.6 patch (1.6.250602001), and 1.6 left support twelve
months ago. WinAppSDK 2.x targets .NET 10. So this is one move, not two, and the WinAppSDK half is
the one that carries breaking API risk. F21's "plan the Windows App SDK 1.6 exit" was written when
that exit was optional.

Order of work:

1. Install the .NET 10 SDK. Only 9.0.317 is present on this machine.
2. Retarget the five non-UI projects (`net9.0` → `net10.0`, `net9.0-windows` → `net10.0-windows`)
   and run the suite. These have no WinAppSDK dependency, so this should be close to free and it
   isolates any .NET-10-only breakage from the UI work.
3. Retarget `MissionController.UI` and jump WinAppSDK 1.6 → 2.x in the same commit — they cannot be
   separated. Budget real time for XAML and packaging breakage across four major versions.
4. Re-run the packaging path end to end. F22 (packaging fails on missing assets, missing signing
   tools, nonzero native exit codes) should land here rather than after, because a migration is
   exactly when a silently-passing package script does the most damage.
5. Revisit F21's `SQLitePCLRaw` native bundle while the dependency graph is already open.

**Nothing below this line is worth starting before Phase 0 is done.** Building a workflow view on
WinUI 1.6 means porting it across the 2.x break a few weeks later.

---

## Phase 1 — wiring and persistence

Small, and mostly transcription. Each piece has a sibling in the tree that already works.

**A SQLite workflow registry.** `IWorkflowRegistry` has one in-memory implementation. Four registries
already persist to SQLite the same way — `SqliteTemplateRegistry`, `SqliteProjectTemplateRegistry`,
`SqliteChainedAuditLedger`, `SqliteSemanticMemoryIndex`. Copy the pattern. A workflow that does not
survive a restart is a demo.

**Host the triggers.** `EmbeddedWebhookListener` and `WorkflowScheduler` are written, tested and
never constructed. They need a hosted-service lifetime tied to app startup, the listener's loopback
gate on (that gate was Wave 1b's `AG-F01` and it fails closed correctly), and the scheduler ticking
against persisted graphs.

**One view.** Not a canvas editor. A list of saved workflows, a run button, a live chunk stream
reusing `LiveMissionMonitorView`'s plumbing, and a run history. The graph itself can be authored by
the synthesiser or by JSON for now — a node-drag canvas is weeks of WinUI and it is not what makes
this defensible.

Exit condition for the phase: **a workflow survives a restart, fires on a schedule, and streams its
missions into the UI.** That is the first moment this can be shown to anyone.

---

## Phase 2 — the thing that is actually impressive

Everything above gets SPLAT to parity with a much simpler tool. This is the part that does not have
a competitor.

**Every workflow run emits a verifiable run record.** Not a log — a signed, Merkle-anchored bundle
stating, per step:

- which catalogue template ran, at which version, and the SHA-256 of the policy compiled for it;
- the clamps actually applied, read back from the kernel object rather than from the request;
- the egress rule in force and whether the substrate enforced it or merely declared it (the
  `EgressScope` distinction the templates already carry);
- what the tool read and wrote, and on Linux the BPF verdict on each;
- how many items DLP redacted on the way out;
- the exit contract, and the quality gate's verdict on the analysis;
- the ledger rows, with a Merkle proof binding them to a root.

Almost none of this is new code. `IMerkleProofEngine` builds a tree over `AuditLogEntry` and proves
membership; `IComplianceArchiveExporter` already exports a framework-scoped package;
`SqliteChainedAuditLedger` already chains and verifies. A workflow run writes `AuditLogEntry` rows
today. **This phase is assembly plus a schema, not invention.**

Why this is the wedge, stated plainly: n8n has four hundred connectors and cannot tell you what any
of them was permitted to touch. SPLAT can hand an auditor a file that answers that question for
every step of every run, and prove the file has not been edited. That is not a better automation
tool — it is a different product category, and it is the only category where "our engine spawns
fewer things" is a feature rather than a limitation.

It also converts SPLAT's biggest weakness into the reason to buy. Few connectors, each provably
contained, beats many connectors nobody can account for — *in the one market that pays for
accountability*. Anywhere else, n8n wins and should.

Exit condition: **an auditor who did not run the workflow can verify from the bundle alone what each
step was allowed to do and what it did.**

---

## Phase 3 — connectors, the governed kind

The reframe matters more than the count.

**A connector is a catalogue template, not a node type.** That is already true of every governed
mission, and it means a new connector inherits the jail, the clamps, the egress pin, the argument
binder, the DLP pass and the ledger row *by construction* — there is no way to write one that
skips them, because the mission engine is the only thing that runs. Compare the node-type approach:
each new node is a new place to forget a control, which is precisely how `SandboxedScript` happened.

Concretely:

- Retire the `GovernedHttp` node. Replace it with a governed HTTP **mission template** whose egress
  rule is enforced by `IEgressFirewall` — which exists, is registered, and is tested. Today that
  node honestly reports `NOT_IMPLEMENTED`; the honest replacement is a template, not a node.
- Same for `OAuthExchange`. It refuses today because no token endpoint is wired, and it should keep
  refusing until one is — a vaulted token that was never issued is the fabrication the whole engine
  was cleaned of.
- Then pick **six** connectors, not four hundred, chosen for the buyer in Phase 2's market: a SIEM
  sink (`ISiemForwarder` is already registered), a ticketing system, an EDR query, an identity
  provider read, an object store, and generic pinned HTTP. Six connectors each carrying a
  verifiable containment record is a demo. Four hundred that do not is somebody else's product.

---

## Phase 4 — what remains open, and where it lands

| Finding | What it needs | Phase |
| --- | --- | --- |
| F20 | A remediation verdict from a measured postcondition, not an exit code. Each action declares what *restored* means | 2 — it is an evidence problem |
| AG-F06 | DLP bare-token rules (AWS, GitHub, OpenAI, Stripe, JWT); today only `key=value` shapes redact | 2 — the run record counts redactions, so the counter must be right |
| AG-F07 | Recalled memory wrapped in untrusted delimiters before it reaches a prompt | 1 — cheap, and workflows make memory reachable from a webhook |
| F19 | Revocation survives restart and every entrypoint consults it | 1 — same persistence work |
| F21 / F22 | `SQLitePCLRaw` bundle; packaging fails loudly | 0 |
| F23 | Retention inspects checkpoint results and states what erasure does not cover | 3 |
| F24 | One capability manifest that UI, MCP, docs and tests all read | 3 — the connector count becomes a claim worth binding |

---

## The ordering argument

Phase 0 is a deadline, not a priority, and it eats the calendar between now and mid-November whether
or not anything else happens.

Phase 1 before Phase 2 because an evidence bundle for a run nobody can trigger is not testable.

Phase 2 before Phase 3 because the run record is what makes a small connector set defensible. Build
connectors first and SPLAT is a worse n8n with six integrations; build the record first and it is
the only automation tool that can prove what it did. The connector count stops being an apology and
starts being a consequence of the thing being enforced.

And the discipline that produced the last four waves carries forward unchanged: **a passing check
whose control was never verified is not a measurement**, and **the case nobody tested is the case
that ships** — the workflow engine went its entire life unregistered while its own tests passed.
