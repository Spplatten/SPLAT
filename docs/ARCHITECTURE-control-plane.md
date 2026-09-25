<!-- Companion to ARCHITECTURE.md. Covers MissionController.Core, .Infrastructure.Network and
     .Infrastructure.Data - the assemblies that DECIDE. Apart from the in-process egress firewall,
     nothing here enforces a boundary at the operating-system level; the substrates do that. Read
     out of the tree at 0027e57 on 2026-09-10. -->

# Control plane — how a mission is decided, run and recorded

## The seam map

`MissionController.Core` has no project references and no package references. Every platform
effect sits behind one of its interfaces — most of them in
[`Interfaces.cs`](../src/MissionController.Core/Interfaces.cs), the rest beside the code that
consumes them — and the infrastructure assemblies implement them.

| Seam | Implemented by | In |
| --- | --- | --- |
| `IJailManager`, `IJobSandbox`, `IProcessLauncher`, `IRestrictedTokenProvider` | `NtAclJailManager`, `Win32JobSandbox`, `SuspendedProcessLauncher`, `RestrictedTokenProvider` | Infrastructure.Windows |
| `ICredentialVault`, `IRemediationEngine`, `ICopilotSafetySubstrate` | `DpapiCredentialVault`, `SandboxedRemediationEngine`, `CopilotSafetySubstrate` | Infrastructure.Windows |
| `ILeasedExecutor`, `ITemplatePolicyCompiler` | `WslLeasedExecutor`, `TemplatePolicyCompiler` | Infrastructure.Linux |
| `IModelStreamClient` | `ModelClientRouter` over `ClaudeStreamClient` and `GeminiStreamClient` | Infrastructure.Network |
| `IEgressFirewall`, `IDataLossPreventionSanitizer`, `ICredentialSanitizer` | `EgressFirewallHandler`, `RegexDataLossPreventionSanitizer`, `PromptCredentialSanitizer` | Infrastructure.Network |
| `ITokenValidator`, `IApiKeyValidator`, `ITokenLifecycleManager`, `IIncidentRevocationManager` | `JwtTokenValidator`, `ApiKeyValidator`, `TokenLifecycleManager`, `IncidentRevocationManager` | Infrastructure.Network |
| `ISiemForwarder`, `IEdrIngestionBridge` | `SiemForwarder`, `EdrIngestionBridge` | Infrastructure.Network |
| `IAuditLedger`, `IMerkleProofEngine`, `IComplianceArchiveExporter`, `ISemanticMemoryIndex` | `SqliteChainedAuditLedger`, `MerkleTreeEngine`, `ComplianceArchiveExporter`, `SqliteSemanticMemoryIndex` | Infrastructure.Data |
| `ITemplateRegistry`, `IProjectTemplateRegistry`, `IGovernedCrewRegistry` | `SqliteTemplateRegistry`, `SqliteProjectTemplateRegistry`, `SqliteGovernedCrewRegistry` | Infrastructure.Data |
| `IOperatorIdentityProvider` ([`OperatorIdentity.cs`](../src/MissionController.Core/OperatorIdentity.cs)) | `WindowsOperatorIdentityProvider`; `McpOperatorIdentityProvider` in `splat-mcp` | Infrastructure.Windows, splat-mcp |

Core, Data, Linux and Network target `net10.0`, and Infrastructure.Windows targets
`net10.0-windows`. The `net9.0` leg they carried for the console went when the console moved to
.NET 10 on 2026-09-18.

## The governed template

[`SingleToolTemplate`](../src/MissionController.Core/Models.cs) is the unit of policy. "1:1:1" is
what `ValidateStrictRules()` checks, and it is a check of *shape*: exactly one target model, one
tool with an executable path and one egress FQDN; at least one allowed exit code; a timeout from 1
to 3600 seconds; memory and CPU limits inside the governed range; unique parameter keys. It never
looks at a parameter's value — that is the binder's job.

Two derived properties decide containment, and are worth knowing before you add a template:

- **`EgressRule.Scope`** ([`Enums.cs`](../src/MissionController.Core/Enums.cs)) names *which
  process* reaches the declared FQDN. `ModelGateway`, the default, means SPLAT's own provider
  client does, so the sensor needs no network at all. `ToolProcess` means the sensor opens it
  itself. Windows uses the scope to decide whether the tool gets a network stack; the Linux
  compiler uses it to decide whether a lease opens the network. A template that says nothing gets
  the contained behaviour.
- **`ToolNeedsLocalSubsystems`** scans the tool's command line for cmdlets that reach WMI/CIM, the
  Event Log service, Defender or the SCM — RPC that an AppContainer walls off — and exempts a
  matching template from network denial rather than letting it break. See
  [who gets the AppContainer](ARCHITECTURE-windows-substrate.md#who-gets-the-appcontainer).

The shipped catalog is
[`GovernedTemplateCatalog`](../src/MissionController.Infrastructure.Data/Catalog/GovernedTemplateCatalog.cs),
split into partial files by operational domain. `TemplateId` is the identity written into every
ledger row, so ids are append-only; names and descriptions are display metadata. The model ids and
the AI-gateway FQDN are constants at the top of that file rather than per-template strings. Both
hosts seed the catalog into SQLite at startup.

Parameters reach a command line only through
[`GovernedArgumentBinder`](../src/MissionController.Core/GovernedArgumentBinder.cs): one regex pass
over the original `ArgumentsTemplate`, so a value containing `{OtherKey}` stays inert, and an
allow-list chosen by where each placeholder sits and what type its field declares — a bare token,
for instance, must open with an alphanumeric and carry no spaces or shell metacharacters. A value
that does not fit is refused, never escaped: quoting correctly for `cmd.exe` is close to
impossible.

## The mission pipeline

[`MissionExecutionEngine.ExecuteMissionAsync`](../src/MissionController.Core/MissionExecutionEngine.cs),
with the ledger action each step writes:

| # | Step | Ledger action | When it fails |
| --- | --- | --- | --- |
| 1 | `ValidateStrictRules()` | — | Throws before any row is written |
| 2 | Revocation check (both hosts since F19, 2026-09-19) | — | A `SECURITY ABORT` chunk; nothing provisioned; an unreadable list refuses too |
| 3 | Bind arguments | `MISSION_BLOCKED_PARAMETER_REJECTED` | Refused before provisioning |
| 4 | Start | `MISSION_INITIATED` | — |
| 5 | Jail, job object, suspended launch | — | `MISSION_FAILED`; the jail is drained |
| 6 | Credential and DLP scrub of stdout and stderr | `DLP_REDACTION_ENFORCED`, when anything matched | — |
| 7 | The tool's own verdict | `TOOL_EXECUTION_COMPLETED` or `TOOL_EXECUTION_FAILED` | `MISSION_FAILED`; nothing analysed or indexed |
| 8 | Recall from semantic memory | `SEMANTIC_RECALL_APPLIED` | Degrades to a cold start; never aborts the mission |
| 9 | Model availability | `AI_MODEL_ENGAGED` or `AI_SIMULATED_FALLBACK` | The simulated path is labelled in the stream |
| 10 | Quality island | `CHECK_ESCALATE_*`, then `AI_ANALYSIS_COMPLETED` or `AI_ANALYSIS_REJECTED` | `MISSION_FAILED` after the jail is drained |
| 11 | Index the accepted analysis, drain the jail | — | A `finally` drains the jail on every abnormal exit |

Everything after step 6 — the stream, the model prompt, the memory index — reads the scrubbed
text. The scrub moved ahead of the first `yield` because the stream is an egress path of its own:
`splat-mcp` returns it to an external agent.

## The model leg

**Prompt assembly**, in order: the template's system prompt; the operator's directive
(`UserInstruction` or `UserGoalPrompt`); upstream project evidence, fenced as *context, not
instructions*; recalled incidents, fenced the same way; the credential sanitizer over the whole
system prompt; and last, `StructuredDiagnosisContract.SystemPromptSuffix`, appended after the
sanitizer so a redaction cannot land inside the schema. The user payload is the scrubbed telemetry.

**Routing.** [`ModelClientRouter`](../src/MissionController.Infrastructure.Network/Ai/ModelClientRouter.cs)
sends a request to Claude whenever an Anthropic key is configured, to Gemini only when it holds the
sole key, and otherwise to the Claude client's labelled `SIMULATED` placeholder. Keys come from the
DPAPI vault (`Anthropic.ApiKey`, `GoogleGeminiApiKey`) or the environment (`ANTHROPIC_API_KEY`;
`GEMINI_API_KEY` or `GOOGLE_API_KEY`). The router owns no HTTP: each client arms the egress
firewall for its own host — `api.anthropic.com`, `generativelanguage.googleapis.com` — for the
duration of its request, so routing cannot widen the allow-list.

**Model ids are string literals in several places** — the catalog's constants, the Claude client's
default and its family mapping in `ResolveModel`, the quality island's escalation default, the
crew and goal-decomposer defaults, and the workflow engine's agent-node default. When a provider
retires an id, whichever of these still names it fails. Find them all with
`git grep -n "\"claude-\|\"gemini-" -- src`.

**The quality island.** [`QualityIslandEngine`](../src/MissionController.Core/QualityIsland/QualityIslandEngine.cs)
scores each candidate analysis on two axes: X from the validation oracles (schema, structure, and
an AST check for code) and Y from the semantic evaluators (telemetry grounding, diagnostic
completeness, anti-hedging). Only Quadrant I — `X >= 1.0` and `Y` at or above the threshold — is
accepted. In the default mode, `LeanFailSafe`, the first candidate uses the template's model; a
miss escalates once, with a targeted prompt, to `QualityIslandOptions.FrontierEscalationModel`; if
that misses too, the better-scoring candidate is returned **with `IsSuccess` false**, and the
mission records a rejection. The Bradley–Terry arbiter ranks a cohort only in the
`SpeculativeBestOfN` mode. With no live model, the island evaluates the offline analysis with the
same checks and reports their verdict — so an offline analysis that passes them is accepted and
indexed like any other, with `AI_SIMULATED_FALLBACK` in the ledger to say what it was.

**Findings and grounding.** [`JsonFindingsExtractor`](../src/MissionController.Core/JsonFindingsExtractor.cs)
parses the one JSON shape the contract asks for.
[`TelemetryGrounder`](../src/MissionController.Core/TelemetryGrounder.cs) then checks each
finding's specifics — addresses, counts, paths, binaries, percentages — against the sensor output
and marks the ones that do not appear `[UNSUPPORTED]`. It never drops a finding and never lowers a
severity; a critical verdict resting on unsupported claims is flagged in its headline instead.

## Engines that compose missions

Each of these is a policy over `IMissionExecutionEngine`. The limits below are enforced in code,
not left to the model — a model asked to police its own budget eventually decides it needs one more
look.

- **[`GovernedInvestigationLoop`](../src/MissionController.Core/GovernedInvestigationLoop.cs)** —
  after each mission, asks a model whether another governed step is warranted and which template it
  uses. A hard ceiling (`AbsoluteMaxSteps`) caps whatever the caller requests, a template never
  repeats, selection is restricted to the catalog inside `ReActDecisionContract.Parse`, and a
  healthy verdict ends the chain.
- **[`ProjectExecutionEngine`](../src/MissionController.Core/ProjectExecutionEngine.cs)** — one to
  six ordered stages, each a mission; the evidence handed forward is capped
  (`MaxContextCharacters`) and fenced as context. A stage can be marked `ContinueOnFailure`.
- **[`GovernedCrewEngine`](../src/MissionController.Core/Crew/GovernedCrewEngine.cs)** —
  `Sequential` crews run tasks in order; `Hierarchical` crews have a manager agent route them. A
  task bound to a template runs as a mission; a task without one is a model call with the agent's
  own prompt. Upstream context is DLP-scrubbed and capped on every hand-off.
  [`GovernedCrewParser`](../src/MissionController.Core/Crew/GovernedCrewParser.cs) rejects a task
  graph with a cycle, and the engine halts a delegation cycle at run time.
- **[`AgentBrainEngine`](../src/MissionController.Core/Brain/AgentBrainEngine.cs)** —
  [`CognitiveGoalDecomposer`](../src/MissionController.Core/Brain/CognitiveGoalDecomposer.cs) turns
  a natural-language goal into candidate templates and sub-goals, and re-plans as grounded
  telemetry comes back; each step is a mission.
- **[`WorkflowExecutionEngine`](../src/MissionController.Core/Workflow/WorkflowExecutionEngine.cs)**
  — a node graph with single-pass `{node-id.field}` substitution. `GovernedMission` nodes run
  through the mission engine. `TransactionalScope` still launches through `IProcessLauncher` under
  its own job object. `SandboxedScript` is refused. Simulated execution happens only when a caller
  asks for it by name. [`WorkflowSynthesizerEngine`](../src/MissionController.Core/Workflow/WorkflowSynthesizerEngine.cs)
  composes catalog templates rather than inventing script.
- **Synthesis** compiles the operator's sentence with a model, grounded in the catalog and validated
  against it. Until 2026-09-25 it did neither: it held an `IModelStreamClient` it never called and
  matched keywords over five hardcoded graphs, so a request matching none of them - nearly every real
  sentence - produced an Active Directory health check labelled *Successfully synthesized*. The model
  now returns either a prebuilt recipe by id or a stage list naming exact template ids, with a
  per-stage `continueOnFailure`; a template id the catalog does not have throws in the compiler
  rather than reaching the execution engine, and with no model connected synthesis refuses instead of
  emitting a default plan. The stage's directive and its continue-on-failure flag travel in the
  node's configuration as reserved keys that are never bound as mission parameters.

## Identity and attribution

Every ledger row names a principal that the operating system or a validator established, never a
string the caller supplied. The console attributes to the Windows logon session;
[`splat-mcp`](ARCHITECTURE-agent-surface.md#splat-mcp) adds an optional validated credential. When
an `IIncidentRevocationManager` is wired — both hosts, since F19 on 2026-09-19 — the mission engine refuses a revoked
operator before binding anything.

## Evidence and memory

One SQLite file per host, opened by
[`SqliteStorageContext`](../src/MissionController.Infrastructure.Data/SqliteStorageContext.cs) with
per-connection pragmas: WAL, `synchronous = NORMAL`, foreign keys on, and `secure_delete` on — the
last is a retention prerequisite, since without it deleted bytes survive in free pages.

**The ledger** — [`SqliteChainedAuditLedger`](../src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs).
Each append runs in a transaction: read the previous entry hash, draw a 256-bit salt, commit to a
salted digest of the details rather than the details themselves (hash version 2), and chain the
entry hash over the previous hash, timestamp, mission, template, action, that commitment and the
operator. The salted commitment is what lets retention erase a payload later without forging a
tamper signal. The key, when there is one, is the raw bytes of a file the operator keeps
([`LedgerKeyFile`](../src/MissionController.Infrastructure.Data/LedgerKeyFile.cs)): `--ledger-key` on
`splat-mcp`, `SPLAT_LEDGER_KEY_FILE` for either host, never the vault. Each row's hash version
names its chain: 2 is unkeyed SHA-256, and 3 is HMAC-SHA256 under the key. The first keyed append
writes a `LEDGER_KEYED` entry that commits to the unkeyed history before it. A keyed ledger refuses
to be extended without its key or with another, and a host holding a key verifies only a chain that
has been keyed. **Unkeyed, editing a row in place is detected; recomputing from genesis is not.
Keyed, neither goes unnoticed by anyone without the key file. Deleting the newest entries is caught
only by a saved audit anchor, and whoever can read the key file can do anything the key can.**

**Proofs and packages.** [`MerkleTreeEngine`](../src/MissionController.Infrastructure.Data/Compliance/MerkleTreeEngine.cs)
builds a tree over ledger rows and produces and verifies inclusion proofs — an inclusion proof shows
a row is present, and says nothing about rows that are missing.
[`ComplianceArchiveExporter`](../src/MissionController.Infrastructure.Data/Compliance/ComplianceArchiveExporter.cs)
writes a framework-tagged package (SOC 2, HIPAA, CMMC, ISO 27001), by default under
`<data root>\ComplianceExports`. Both are reached from the console's Security
Audit screen.

**Retention.** [`DataRetentionService`](../src/MissionController.Infrastructure.Data/Retention/DataRetentionService.cs)
overwrites expired payload columns and keeps the metadata skeleton, deletes semantic rows whole, and
cryptographically erases ledger details — payload and salt destroyed, commitment kept, so
verification still passes — then checkpoints the WAL and vacuums. No host schedules it.

**Semantic memory.** [`SqliteSemanticMemoryIndex`](../src/MissionController.Infrastructure.Data/Vector/SqliteSemanticMemoryIndex.cs)
keeps in-process 128-dimension vectors in SQLite and searches them by cosine similarity; nothing is
sent to an embedding service. The mission engine recalls a few matches above a strict floor
(`RecallTopK`, `RecallMinScore`) and indexes an analysis only when the island accepted it, verdict
first, so a recall reads as "what was wrong last time".

**Registries.** `SqliteTemplateRegistry` and `SqliteProjectTemplateRegistry` are seeded from the
template and project catalogs. `SqliteGovernedCrewRegistry` exists but neither host constructs it;
`splat-mcp` reads [`GovernedCrewCatalog`](../src/MissionController.Infrastructure.Data/Catalog/GovernedCrewCatalog.cs)
directly.

## The network edge

- [`HardenedHttpClientFactory`](../src/MissionController.Infrastructure.Network/HardenedHttpClientFactory.cs)
  builds the one `HttpClient` each host uses: the egress firewall over a `SocketsHttpHandler` with
  automatic redirects **off** (a redirect has to come back as a response and be re-requested
  through the firewall), TLS 1.2 or 1.3, online revocation checks, and the system proxy.
- [`EgressFirewallHandler`](../src/MissionController.Infrastructure.Network/EgressFirewallHandler.cs)
  holds the permitted host in an `AsyncLocal`. A request with no active scope is **blocked**, and
  the host must match exactly. `BeginScope` restores the previous policy on dispose, so a policy
  cannot leak across awaits into unrelated work. The scopes armed today: the Claude and Gemini
  clients, the SIEM forwarder's Sentinel host, and the two Google OAuth services, which no host
  constructs.
- [`RegexDataLossPreventionSanitizer`](../src/MissionController.Infrastructure.Network/Dlp/RegexDataLossPreventionSanitizer.cs)
  — ordered rules for private-key blocks, NTLM hash pairs, credential assignments, command-line
  password arguments, email addresses, card numbers and SSNs, each with a match timeout because the
  input is attacker-influenceable; a rule that times out records a `:ScanTimeout` category instead
  of wedging the mission. Bare-token rules for AWS, GitHub, OpenAI, Stripe and JWT are AG-F06,
  planned with P3.
  [`PromptCredentialSanitizer`](../src/MissionController.Infrastructure.Network/Identity/PromptCredentialSanitizer.cs)
  runs first, and over the system prompt as well.
- [`SiemForwarder`](../src/MissionController.Infrastructure.Network/Siem/SiemForwarder.cs)
  (Sentinel with HMAC, CEF, RFC 5424 syslog) and
  [`EdrIngestionBridge`](../src/MissionController.Infrastructure.Network/Edr/EdrIngestionBridge.cs)
  (Defender and CrowdStrike posture) serve the console's Security Audit screen.
- `Triggers/` — a loopback webhook listener with a minted token, fixed-time comparison, Host check
  and body cap; an OAuth callback coordinator; a scheduler. No host starts them.

## What this layer does not do

- Contain a process. The job object, token, AppContainer and lease live in the substrates.
- Detect a ledger rewrite while the ledger is unkeyed, or one by anyone who can read the key file.
- Catch secrets its patterns do not describe.
- Give the two hosts one record: each keeps its own ledger and memory.
