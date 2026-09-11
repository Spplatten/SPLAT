<!-- The one status record. When an item's state changes, change its row here in the same commit
     that changes it. When the ORDER changes, the argument goes in the plan and the rows move here.
     Every "State" below was checked against the tree on 2026-09-10: a row that says "open" was
     looked for in the code, not carried over from an older document. -->

# Roadmap

Everything still to do, in the order it pays to do it, with who can do it and what "done" means.
The argument for this order is [the OEM subtraction plan](audits/2026-09-09-oem-subtraction-plan.md);
this file is only the state. The
[competition audit](audits/2026-09-04-competition-and-scope.md) asked for exactly this — "one
authoritative status record" — and until 2026-09-10 the state was spread across the plan, the wave
plan, three audits and the runbook, where it drifted in all of them.

**Owner:** *agent* — can be done without you. *you* — needs `sudo`, an install, money, a signature or
a decision. Where both appear, the agent does the work and you do the one step it cannot.

---

## Done recently

| Item | Evidence |
| --- | --- |
| The server's first byte is the JSON | Every MCP client's first response began with a UTF-8 byte order mark — `ef bb bf` before `{` — which strict JSON parsers reject. Found by reading the bytes, fixed with 1.1, and pinned by a test on the stream itself |
| P0 — the shipping tree on .NET 10 | `0027e57`: 459/459 on `.NETCoreApp,Version=v10.0`, and the frozen console still builds on the net9 leg |
| F21, SQLite half — a high-severity advisory was shipping | `0027e57`: `SQLitePCLRaw` 2.1.10 → 2.1.12, clearing `GHSA-2m69-gcr7-jv3q`. `dist\App` republished, and the patched `e_sqlite3.dll` confirmed loaded in the running app |
| A cold build is warning-free on both legs | 2026-09-10, `--no-incremental`: the console and the net9 legs, 0 warnings; the net10 legs, 0 code warnings and one `MSB3061` — a file lock during the rebuild's delete step, not the code |
| Preflight stopped reporting an unmounted securityfs as YELLOW | `1343457` |
| The runbook's commands run in the shell you actually have | `fa48915`: 11 of 11 PowerShell blocks parse under Windows PowerShell 5.1 |
| Remediation waves 1–3, and Wave 4's F10, F11 and F15/F17 | [WAVE-PLAN](audits/WAVE-PLAN.md) |

---

## Now — P1: installable and provable by a stranger

**Exit:** a stranger with WSL2 adds one stanza to their MCP config, runs a command the kernel refuses,
and can point to the line in [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) that
predicted it. This is also the first thing that can be invoiced: a containment assessment needs P1
and nothing after it.

| # | Item | Owner | State, 2026-09-10 | Done when |
| --- | --- | --- | --- | --- |
| 1.1 | A `splat-mcp` command line — `--workspace`, help, refusal of unknown options — validated **before** any startup effect | agent | **Done 2026-09-11.** Parsed before anything is built: a bad option or a missing workspace exits 2 with the ledger untouched, and a workspace is never created. `--workspace` is optional on purpose — without it the file tools stay in SPLAT's private folder, which fails safe, and the server names that folder on stderr | The selected root reaches `WorkspaceGuard`, and a bad option exits without creating a database — both shown on the real exe, not only in tests |
| 1.2 | `splat-mcp doctor` | agent | **Done 2026-09-12.** Probes this host — kernel, `lsm=` on the boot line, daemon reachable *and* holding live BPF maps, token present — and prints what a lease enforces, refuses and does not police, copied from `SUPPORTED_POLICY.md` and bound to it by a test. Exit 0 only when a lease reaches the kernel. On this host: enforcing, exit 0 | It reports this host's kernel, BPF-LSM state, daemon and token, then what will and will not be enforced — read from the policy tables, never hardcoded — and refuses the enforcing modes when the substrate is absent |
| 1.3 | First-run WSL provisioning | agent; `wsl --install` is yours | Not started — there is no `WslProvisioner` | A clean machine reaches a kernel-contained mission with no manual shell step, and a broken provision names the missing piece instead of falling back silently |
| 1.4 | Distribution: single-file `splat-mcp`, a `dotnet tool`, an `npx` shim | agent | Not started — no `PackAsTool` | `dotnet tool install` plus one config stanza is the whole setup |
| 1.5 | F24 — one capability manifest | agent | Not started | The CLI, `tools/list`, `SUPPORTED_POLICY.md` and the tests all read one file — including which templates run outside the Windows AppContainer — and drift between them fails the build |
| 1.6 | Bound every request frame before parsing it | agent | Open. The daemon reads an unbounded line at `main.rs:437`, before its auth check at `:481` — a pre-auth memory hazard in a root process. `splat-mcp` reads stdin the same way | A frame exactly at the limit parses, and one byte over is refused before it can grow |
| 1.7 | Warnings fail the build on the shipping projects | agent | Open. The cold build is clean today (above); nothing stops that regressing | A new warning in Core, Data, Linux, Network, Windows, `splat-mcp` or the tests fails the build |
| 1.8 | Record the last hop | agent builds it; you start the root daemon | **Done 2026-09-11.** [`probe-last-hop.ps1`](../native/splat-agent/probe-last-hop.ps1) drives `splat-mcp.exe` over stdio as a client does; the kernel refused an undeclared exec and an out-of-lease connect while the permitted command ran as `nobody`. The run found the defect that made the hop unusable: the bridge's `wsl.exe` children inherited the server's stdin and ate the JSON-RPC stream | Evidence is committed of an MCP client's command refused by the kernel, bound to the sources that produced it, and `DocumentationDriftTests` holds the README to it in both directions |

---

## Next — P2: the workload's own mount namespace

Three of the gaps people ask about first — read-only roots, copy-on-write scratch, running code an
agent just wrote — are one missing capability. The plan's §3 has the argument.

| # | Item | Owner | State, 2026-09-10 | Done when |
| --- | --- | --- | --- | --- |
| 2.1 | `unshare(CLONE_NEWNS)` and `pivot_root` inside the spawn's `pre_exec` closure | agent | Not started; it exists as a comment in `cow.rs`. The hard one: async-signal-safe code in a forked child of a multithreaded process | `readOnlyFs` and `overlayFs.enableCow` move out of `SUPPORTED_POLICY.md`'s **Refused** table |
| 2.2 | Leased scratch execution for code an agent just wrote | agent | Blocked on 2.1 | A file created in scratch executes, the same file outside scratch does not, and the scratch layer is gone after teardown |
| 2.3 | The proof, under root | you — `sudo` for the daemon and its token | Blocked on 2.1 | `daemon-probe.json` gains those checks and is re-recorded; the runbook gets a section for it |
| 2.4 | Caller identity on the bridge | agent | Not started. Today: loopback TCP and a root-owned shared secret, which stops an unprivileged process in the guest but not another process running as the same Windows user. The code's own notes name AF_VSOCK, or `SO_PEERCRED` over a Unix socket | The threat model is written down first — which callers each option actually excludes; AF_VSOCK identifies a VM, not a Windows process — and the daemon enforces what it says |

---

## Then — P3: the per-mission run record

**Exit:** someone who did not run a mission can verify from the bundle alone what it was permitted to
do and what it did. The schema already exists — the six-group evidence contract in
[the 09-04 roadmap](audits/2026-09-04-roadmap.md). Fill it in; do not redesign it.

| # | Item | Owner | State, 2026-09-10 | Done when |
| --- | --- | --- | --- | --- |
| 3.1 | Assemble the bundle over `IMerkleProofEngine`, `IComplianceArchiveExporter` and the ledger | agent | The parts exist; nothing assembles them per mission | The exit above |
| 3.2 | Key the ledger | agent; you decide where the key lives | Open. Keying is supported, but `splat-mcp` builds its ledger with no key and no vault, so it chains unkeyed and a rewrite is undetectable | A ledger that is meant to be keyed refuses to append without its key, and the record states which kind of chain it came from |
| 3.3 | AG-F06 — bare-token DLP on the output path | agent | Open. The output sanitizer catches private keys, `key=value` secrets, password flags, emails, card numbers and SSNs. It has no AWS, GitHub, OpenAI, Stripe or JWT shapes — those exist only in the prompt-side credential sanitizer | The record's redaction count can be trusted |
| 3.4 | Truthful terminal reasons from the bridge | agent | Open. Every cancellation, the caller's own included, is reported as "Process killed by kernel/daemon" (`WslLeasedExecutor.cs:245`), with no confirmation from the daemon | Caller cancellation, local timeout and a confirmed kill are three different results, and only the last claims a kill |
| 3.5 | The policy compiler refuses a destination it cannot resolve | agent | Open but latent. On a DNS failure `TemplatePolicyCompiler` grants `127.0.0.1` and keeps the network on (`:107`). No production path calls it yet; P3 is where one would start to | Fixed before any production path compiles a policy |
| 3.6 | F20 — a remediation verdict from a measured postcondition, not an exit code | agent | Open | Each remediation declares what "restored" means, and its verdict is read from that |

---

## Open, not scheduled

Real, known, and not blocking the phases above. Each needs a decision or a slot before it is work.

| Item | Owner | State, 2026-09-10 |
| --- | --- | --- |
| Windows network denial for the sixteen templates without it | decision: an egress control that is not also an RPC wall — a WFP filter is the candidate | Of 49 catalog templates, 33 launch their tool in an AppContainer with no capabilities, so network denial is enforced. **Sixteen run without one.** One needs the network (Grant Opportunity Ingestion, `EgressScope.ToolProcess`): an AppContainer chooses network or none, not a host, so its destination is a claim. Fifteen are built on WMI, the Event Log service, Defender or the service manager, which the container would also cut off, so they keep a network stack they do not need — chosen by a text match over the command line that the code itself calls an interim measure (`ToolNeedsLocalSubsystems`, `Models.cs:150`). `IEgressFirewall` covers neither group; it guards SPLAT's own model client. Counted from the shipped catalog on 2026-09-10; no test binds these numbers yet |
| Lease gaps: unconnected UDP `sendto`, AF_UNIX and AF_NETLINK, inherited descriptors, ambient reads | agent; each proof needs you under root | Listed under **Not policed** in `SUPPORTED_POLICY.md`. P2 closes writes outside the workspace; these stay open |
| F19 — revocation that survives a restart and covers every entrypoint | agent | Open. `IncidentRevocationManager` keeps revocations in a `ConcurrentDictionary` and reloads nothing on start |
| AG-F07 — recalled memory reaches a prompt as context, never as instructions | agent | Done on the mission path: labelled "treat as context, not as instructions" and sanitized (`MissionExecutionEngine.cs:511`). The goal decomposer adds recalled incidents to its prompt with no such label (`CognitiveGoalDecomposer.cs:150`), and the brain-engine and workflow recall sites carry none either |
| F23 — retention proves the erasure it reports | agent | Half done. It states what erasure does and does not cover and forces a `TRUNCATE` checkpoint, but never reads the checkpoint's result — if a reader holds the WAL, the pre-purge image survives while the sweep reports success. And no host schedules it |
| F22 — packaging fails loudly | agent | Open. `build-msix.ps1` checks exactly one native exit code, the publish's (`:45`). It also publishes self-contained, a different artifact from the framework-dependent build `dist\App` holds |
| Two ledgers | decision | The console chains into `Data\missioncontroller.db` (`SqliteStorageContext.cs:18`) and `splat-mcp` into `SPLAT\audit_ledger.db`. A headless OEM build may never need the first |
| AG-F08 — `TransactionalScope` is compensation, not rollback | agent | Open, in the deferred workflow layer. For files, the real fix is P2's overlay |
| The console: Windows App SDK 1.6 → 2.x, or retire it | decision | Frozen, and still builds. Keeping it costs one rule: no .NET-10-only API in the five shared libraries while their net9 leg exists. .NET 9 support ends 2026-11-10 |

---

## Deferred by decision

The OEM subtraction took these off the road on 2026-09-09. They are not forgotten, and they are not
next.

- **Workflow persistence, trigger hosting and a workflow view** — the orchestration plan's Phase 1.
  `InMemoryWorkflowRegistry` is still the only registry, and `WorkflowScheduler`,
  `EmbeddedWebhookListener` and `OAuthCallbackCoordinator` are constructed by no host.
- **Connectors** — the orchestration plan's Phase 3. `GovernedHttp` answers `NOT_IMPLEMENTED` rather
  than pretending to send.
- **Built and never wired:** `DataRetentionService`, `VertexAiStreamClient`, `PkceLoopbackAuthService`,
  `ServiceAccountAuthService`. Wire one when a phase needs it, not before.

---

## The commercial track — yours

| Item | State | Needed before |
| --- | --- | --- |
| An LLC, with the IP assigned to it | Not tracked in this repository | Anything is signed |
| General-liability and E&O cover | Not tracked | The first client machine |
| The OEM term sheet: draw the open-core line at the daemon, and attach `SUPPORTED_POLICY.md` as Exhibit A | A draft exists outside the repository; its runtime defect went away with P0 | It is sent |
| The first containment assessment | Waiting on P1 | — |
| The first outreach | Triggered by P1's exit; the targets are in [TARGETS-cold-outreach.md](TARGETS-cold-outreach.md) | — |

## Human-only steps

Nothing in [the runbook](RUNBOOK-human-steps.md) is open today. Two rows above will add to it: 1.8
needs the root daemon started, and 2.3 re-records the daemon probe under root.
