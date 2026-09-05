# SPLAT clinical audit: technical safety and release readiness

Audit started: 2026-09-04; completed: 2026-09-05, America/New_York. Repository: `C:\C_AGENT_BUILDER`. Base commit: `461001b`; findings apply to the inspected working tree, including its six pre-existing modified files. Filenames retain the audit start date.

**Verdict: do not release the current build as a general-purpose containment boundary for untrusted agents.** There is substantial working Windows diagnostic infrastructure, but authorization, isolation, lease lifecycle, evidence integrity and result-status defects invalidate the broad safety guarantees. A passing build and test suite do not close those defects.

“Clinical” here means a rigorous technical and product audit. The repository implements computer-system diagnosis and agent execution, not a patient-care application. This is not a clinical efficacy study or a regulatory certification.

Companion reports: [competition and scope](2026-09-04-competition-and-scope.md) and [prioritized delivery plan](2026-09-04-roadmap.md).

## Evidence and boundaries

| Check performed | Result | What this establishes |
| --- | --- | --- |
| `dotnet test tests/MissionController.Tests/MissionController.Tests.csproj --nologo --logger 'trx;LogFileName=clinical-audit.trx' --results-directory "$env:TEMP\SplatAudit20260905" --verbosity minimal` | **389 passed, 0 failed, 0 reported skipped**, 26-second test duration | Existing .NET regression suite passes on this Windows host. Includes native Windows process tests and the existing local diagnostic verification runner. |
| `dotnet build MissionController.sln --nologo --no-restore --verbosity minimal` | **0 errors, 0 warnings**, 23.08 seconds | Entire solution, including WinUI, builds in the inspected Debug configuration. |
| `dotnet list MissionController.sln package --vulnerable --include-transitive --format json` | **High-severity advisory found** for `SQLitePCLRaw.lib.e_sqlite3` 2.1.10 | Current resolved NuGet graph contains an affected native SQLite dependency. This command exits zero even when it reports vulnerabilities. |
| In-memory MCP authentication probe against the actual handler, existing mock executor and rejecting identity provider | Authentication error `-32001`; **executor invoked**; **0 audit rows** | A rejected caller can reach execution before credential validation. No actual command/process was launched by this probe. |
| In-memory workflow with `AgentReasoning`, no model and no other services | **Success=true**, output includes `Status: VERIFIED`, with zero evidence characters | Missing model configuration produces a successful, unsupported verification claim. |
| In-memory workflow containing only `GovernedHttp` | **Success=true**, output says `NOT_IMPLEMENTED` and `No request was sent` | Unsupported HTTP execution is recorded as workflow success. No network request was made. |
| Reflection over the actual 49-template catalog and production selection predicate | **33 select AppContainer; 16 retain network access** | Exact current selection coverage, not a per-template live functionality or isolation proof. |
| Python command argument probe using the MCP wrapper and daemon-equivalent whitespace splitting | `print(123)` becomes a quoted string expression; **exit 0, empty stdout** | A simple supported-looking `run_code` invocation can succeed without running its intended Python statement. This was a local Python argument reproduction, not an MCP-to-daemon kernel run. |
| Repository source/entrypoint review | Windows/Linux enforcement, MCP, workflow, brain, quality, persistence, identity, packaging and planning reviewed | Findings below identify code paths and distinguish active wiring from unconnected components. |

TRX evidence: `C:\Users\s_pla\AppData\Local\Temp\SplatAudit20260905\clinical-audit.trx`. Host: Windows `10.0.26200`, .NET SDK `9.0.317`, runtime `9.0.19`.

No new Linux privileged probe, Rust/BPF build, clean-machine installation, UI interaction test, load test, external security assessment or dedicated live-provider evaluation was performed. Existing committed canary/daemon evidence was reviewed; it is historical proof for its recorded scenarios, not a fresh end-to-end test. The existing diagnostic verification test uses its normal application storage and Windows APIs; this audit does not claim the test suite is free of runtime state writes. Production source and the pre-existing edits were preserved.

An isolated temporary-database tampering reproduction was rejected by automatic approval review with the generic reason “blocked by policy.” It did not run. F02/F03 are supported by direct verification-code inspection and test-gap analysis, not a newly executed database modification.

The reported zero skips is not proof every network assertion ran: `SensorNetworkContainmentTests.cs:138-146` returns normally when its independent internet prerequisite fails. No code-coverage percentage was measured.

## Threat model used

The control plane, its administrator-owned policy and the OS/kernel are trusted. Agent requests, generated code, tool output and documents are untrusted. Other local processes must not receive privileged execution merely by reaching a loopback port. A mission must not inherit another mission's capabilities. Local files outside an approved workspace, credentials, audit payloads, other processes and remote destinations are protected assets.

The required order is **authenticate → authorize an immutable policy → provision and verify enforcement → execute → terminate descendants → record the actual outcome → release enforcement**. A failed prerequisite must stop the affected action. A failed diagnosis must not become successful evidence or trusted memory.

P1 means a blocker for releasing the affected capability under its stated contract. P2 means a material reliability, privacy, product-truth or operational issue to close before the relevant pilot/enterprise claim. These are audit priorities, not externally assigned CVSS scores. “Source-confirmed” does not imply a live exploit was attempted.

## Ranked findings

### F01 — P1: MCP validates credentials after execution or file mutation

**Evidence:** `src/splat-mcp/McpServerHandler.cs:574-608` calls `ExecuteLeasedAsync` before `ResolveActorAsync`; `:792-808` creates directories and writes the file before resolving the actor. Dispatch does not establish a common identity gate. The diagnosis path at `:928` resolves identity earlier, so the defect is path-dependent.

**Impact:** with a configured credential that cannot validate, `run_command` can execute and then return an authentication failure. `fs_write` can change disk before reporting failure. The rejected-credential in-memory probe confirmed executor invocation and no audit record. Existing attribution tests asserting only an error response and empty ledger miss the side effect.

**Required change/gate:** resolve and authorize the actor once before dispatching any protected tool; bind policy and audit intent to that actor. Invalid/expired/revoked identities must produce zero executor invocations, zero filesystem changes and an appropriate rejection record without exposing credential material.

### F02 — P1: the audit verifier does not authenticate the displayed payload

**Evidence:** `src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs:157-190` reads `Details` and `DetailsCommitment`, but not `DetailsSalt`. Version-2 verification recomputes the row hash using the stored commitment without checking that unredacted `Details` actually produces it. `tests/MissionController.Tests/HmacAuditLedgerAndAstValidatorTests.cs:61-65` describes payload tampering but changes the commitment column instead.

**Impact:** changing only a version-2 row's displayed details leaves every value consumed by the verifier unchanged. An integrity-green ledger can therefore display forged narrative evidence. This is a simpler defect than rewriting an entire unkeyed chain.

**Required change/gate:** verify the salted payload commitment for unredacted rows. Give authorized redaction an authenticated, explicit representation and history. Test payload-only edits, salt edits, forged redaction markers and legitimate erasure independently. Merkle verification of unchanged row hashes cannot repair this missing payload check.

### F03 — P1: HMAC verification permits an unkeyed downgrade

**Evidence:** `SqliteChainedAuditLedger.cs:185-190` retries with a null key after keyed verification fails. `:31-50` also treats vault failures as no key. `src/splat-mcp/Program.cs:38-40` constructs the ledger without a vault/key.

**Impact:** a writer able to rewrite the database can replace a keyed chain with unkeyed hashes that verification accepts. Current MCP composition does not enable the optional keyed path in the first place. Tail truncation/full-history replacement also needs a trusted external checkpoint to be distinguishable from a shorter legitimate history.

**Required change/gate:** use a versioned and authenticated algorithm/key identifier, an explicit migration boundary, mandatory key availability for keyed mode, and independently retained signed/checkpointed roots. Test downgrade, wrong/missing key, truncation, full replacement, rotation and clean-machine verification. Do not describe the current archive as immutable or notarized.

### F04 — P1: Linux execution remains available when enforcement fails; health reports success anyway

**Evidence:** `native/splat-agent/src/main.rs:129-198` logs BPF open/load/attach/map-handle failures and continues. `:268-275` hardcodes BPF/cgroup/OverlayFS health to true and a fixed kernel string. `:295-320` allows a fabricated cgroup fallback when the manager is not enforcing. `native/splat-agent/src/lease.rs:152-169` logs map-synchronization failure and still returns a registered lease.

**Impact:** a reachable daemon can look healthy and run work without the claimed policy. Partial map writes can leave an inconsistent enforcement state. The Windows health reader consumes these booleans; it does not independently establish their truth.

**Required change/gate:** production execution must require observed kernel attachment, usable maps and complete atomic policy installation. Separate development mock mode from production endpoints. Inject every setup/map failure and assert no process starts; health must identify the failed component and effective enforcement state.

### F05 — P1: lease expiry removes enforcement without terminating the workload

**Evidence:** `main.rs:200-209` only logs expired leases; `lease.rs:191-211` removes their BPF state. `main.rs:104-115` deletes cgroup membership from the policing map. Each BPF hook returns allow for unlisted cgroups. `main.rs:608-629` awaits the child and revokes only on the normal completion path. `cgroup.rs:73-78` attempts directory removal but does not kill occupants.

**Impact:** a process outliving its lease can become unpoliced. Descendants, client disconnects, failed response writes and cancellation do not have a demonstrated kill-and-reap protocol. A host-side socket timeout does not kill guest processes.

**Required change/gate:** enforce expiry while keeping the workload denied; kill and reap the entire cgroup before removing policy. Use structured cleanup on every exit/disconnect path and recovery after daemon restart. Test a child and grandchild that outlive the parent, lost clients, TTL expiry and forced daemon death with observable zero-survivor evidence.

### F06 — P1: Linux capability maps are shared across missions

**Evidence:** `native/splat-agent/src/bpf/lease_lsm.bpf.c:59-81` keys executable/file entries only by `(dev, ino)` and network entries only by IPv4. The cgroup ID is checked separately at `:88-90`, not included in policy keys. `main.rs:77-115` adds/removes those global entries per lease without per-mission keys or ownership accounting.

**Impact:** overlapping missions can receive the union of allowed executables/destinations. Revoking one lease can remove entries another still needs, including a file protection. This contradicts the defining per-mission capability boundary.

**Required change/gate:** key policy by mission/cgroup plus resource identity; update and revoke atomically. Concurrent A/B tests must prove A cannot use B's permission and revoking A changes none of B's permissions or protections.

### F07 — P1: the privileged guest daemon accepts unauthenticated caller-selected commands

**Evidence:** `main.rs:213-238` accepts TCP clients; `:265-285` dispatches execution from request fields without principal authentication. `:323-365` uses caller policy values and adds the requested executable to its allowlist, plus shell/ping/curl defaults. Process creation has cgroup placement but no visible UID/capability drop or namespace isolation.

**Impact:** loopback reachability is being treated as authority. A local process reaching a root-run daemon can request execution as that daemon's user. Checking three hooks does not make root safe: root-accessible cgroup controls, host mounts and unprotected files remain relevant escape routes. These broader escape scenarios were not live-tested.

**Required change/gate:** authenticate the bridge/peer, authorize a controller-issued policy independently of caller wishes, constrain executable identity and drop workload privilege. Protect cgroup/control-plane resources from the workload. Demonstrate a second local user and a hostile in-guest process cannot issue or widen a lease.

### F08 — P1: declared Linux file/network permissions exceed the implemented hooks

**Evidence:** `lease_lsm.bpf.c:146-187` denies selected protected file inodes and IPv4 `connect()` destinations; it explicitly permits non-IPv4 families and has no destination-port test. There is no send-message hook for unconnected UDP. `main.rs:339` parses read-only mode but does not enforce it; `OverlayWorkspace` is imported without a setup call. The bridge sends overlay settings at `WslLeasedExecutor.cs:92-97`, but the daemon does not consume them into an execution workspace.

**Impact:** `allowNetwork=false` is not total network denial; approved IPs do not enforce approved ports. Read-only/workspace restrictions and transactional filesystem execution are not provided by the current daemon. A two-file denylist is not a filesystem jail, and a permitted interpreter can access unlisted resources without an additional exec.

**Required change/gate:** publish the actual supported syscall/protocol/resource matrix; refuse unsupported policy rather than accepting it. Test IPv4/IPv6, TCP/UDP, ports, inherited descriptors, local sockets, writes outside the workspace and read-only mutation. Implement a real mount/identity boundary before promising arbitrary-code containment.

### F09 — P1: requested Linux resource limits are not the limits provisioned

**Evidence:** `main.rs:295` provisions a cgroup with fixed 256 MiB/50%/100-PID values before it parses the request's limits at `:372-384`. `lease.rs` does not apply those parsed limits. `native/splat-agent/src/cgroup.rs:32-48` ignores errors writing `memory.max`, `cpu.max` and `pids.max`.

**Impact:** a caller requesting stricter limits does not receive them; failed controller writes can leave an unclamped workload while the request is accepted.

**Required change/gate:** validate limits first, provision exactly the accepted ceiling, read back effective controller values and fail closed on failure. Test lower-than-default requests, unavailable controllers and process/memory exhaustion inside a disposable supported environment.

### F10 — P1: MCP filesystem containment is lexical and follows filesystem redirection

**Evidence:** `src/splat-mcp/McpServerHandler.cs:97-124` uses `Path.GetFullPath` and a prefix comparison; reads/writes subsequently use ordinary path APIs. There is no junction/reparse-point rejection, handle-based final-path validation or race-resistant relative open.

**Impact:** a pre-existing junction or link inside the permitted workspace can redirect a superficially in-workspace request outside it. A path normalization check does not establish the final filesystem object. Exploitability requires an existing redirect or the ability to create/swap one; no junction was created during this audit.

**Required change/gate:** perform race-resistant final-object confinement, including parent traversal and new-file creation. Test symlinks, junctions, nested reparse points, alternate roots and a concurrent link swap using disposable directories.

### F11 — P1: MCP policy and command semantics do not survive the Linux bridge

**Evidence:** `McpServerHandler.cs:555-563` constructs placeholder protected inode values and an empty exec-inode list; `_policyCompiler` has no production invocation. `WslLeasedExecutor.cs:73-98` omits both inode policy lists. `McpServerHandler.cs:675-686` shell-quotes `run_code`; `main.rs:393` splits the argument string on whitespace instead of parsing a quoted command or receiving an argument vector.

**Impact:** compiled template policy is not the actual authorization source for this path. The argument probe showed `print(123)` producing empty output with exit zero; whitespace-containing scripts can fail differently. Isolated daemon canaries do not establish this bridge's correctness.

**Required change/gate:** define one versioned wire contract with an explicit `argv` array, policy identity/hash, effective permissions and terminal outcome. Validate inode identities in the enforcing environment. Run actual Python/Bash/Node examples with spaces, quotes, newlines and Unicode through the external MCP client and verify exact output plus negative policy cases.

### F12 — P1: Windows ACL jails do not provide the promised per-mission filesystem boundary

**Evidence:** `RestrictedTokenProvider.cs:42-57` strips privileges/admin grants and lowers integrity to Medium while retaining the user identity; it does not create a workspace-only identity. `NtAclJailManager.cs:40-60` changes the jail's ACL, not the permissions on outside files. `SensorAppContainer.cs:37` uses one global profile name; `NtAclJailManager.cs:71-78` grants that same container SID Modify rights on every jail.

**Impact:** non-AppContainer sensors retain access to resources their user can access outside the jail. AppContainer missions share authority over other mission jails when reachable. Current selection is 33/49 templates; 16 retain their network stack because of destination or local-subsystem requirements. The HTTP gateway's FQDN handler does not control those child sockets.

**Required change/gate:** specify separate supported tiers and refuse a tier mismatch. For strict isolation, use a per-mission identity/profile and an actual outside-filesystem boundary. Test cross-jail reads/writes, user-profile access and raw socket egress across all supported sensor families. Preserve the real WMI/Event Log compatibility constraints rather than silently dropping required diagnostics.

### F13 — P1: failure outcomes become completed missions and accepted evidence

**Evidence:** `MissionExecutionEngine.cs:274-314` logs a process exit without stopping on nonzero exit/timeout. At `:511-538` it publishes and indexes the quality-island output without checking `islandResult.IsSuccess`, then emits success at `:551-555`. `QualityIslandEngine.cs:381-403` can return the best failing candidate with `IsSuccess=false`; its offline path at `:461-477` returns true independently of the evaluation. `McpServerHandler.cs:928-952` returns `IsError=false` after collecting a diagnostic stream, even when a launch failure ended the mission early. Remediation reports success from exit code alone at `SandboxedRemediationEngine.cs:110`.

**Impact:** external clients and future recall can treat failed execution, rejected analysis or incomplete observations as successful evidence. Human-readable messages do not provide a reliable machine-consumable result contract.

**Required change/gate:** carry typed execution, timeout, analysis-validation and terminal states through every adapter, using each template's explicit exit-code contract. Preserve useful partial output without calling the mission successful. Gate trusted memory and remediation suggestions on accepted evidence. Force tool failure, timeout, malformed/ungrounded model output and analysis exhaustion; assert unsuccessful terminal results and no accepted-memory insertion.

### F14 — P1: DLP covers direct model input but raw telemetry is returned through MCP

**Evidence:** `MissionExecutionEngine.cs:282-316` yields raw stdout/stderr before the sanitization at `:318-341`. `McpServerHandler.cs:928-943` appends those raw chunks to the tool result. `run_command` also returns raw process output at `:581-589` and records arguments at `:607`.

**Impact:** an external agent client can receive credentials or identifying telemetry that would have been redacted before SPLAT's own model call. Agent-driven or remote orchestration makes the MCP response an independent egress boundary. Local UI inspection and remote tool output need different explicit permissions.

**Required change/gate:** sanitize every outward channel, including failed-node outputs, tool results, errors and audit arguments; retain privileged raw-view access only under a defined local policy. Seed known secret markers in stdout, stderr and errors and assert they never reach unauthorized model/MCP/log sinks.

### F15 — P1: the visible workflow builder does not execute the graph it presents

**Evidence:** `src/MissionController.UI/ProjectStudioViewModel.cs:155-199` calls a keyword synthesizer, displays a webhook URL and converts each non-trigger node into a diagnostic stage using the first matching model template. It does not preserve graph edge/condition semantics in an executable workflow registration. `App.xaml.cs:176-196` does not compose/start the workflow engine, registry, scheduler or listener. Repository-wide call search found their definitions but no production activation.

**Impact:** the UI can advertise AI synthesis, OAuth/webhooks and conditional automation while saving/running a different ordered diagnostic project. Unit-testing an isolated workflow engine does not establish the user journey.

**Required change/gate:** either remove the unsupported flow claims from this journey or persist and execute the actual graph through composed services. A UI-created conditional workflow must survive restart, run only its chosen branch, receive a real authenticated trigger and return the same execution ID across UI/API/ledger.

### F16 — P1: production workflow classes still manufacture successful outcomes

**Evidence:** `WorkflowExecutionEngine.cs:437-438` returns a simulated successful script when services are absent; `:711-717` emits `Status: VERIFIED` without a model; `:743-750` returns successful placeholder HTTP output. The ReAct loop at `:481-527` selects the next list item and echoes a placeholder, then claims the boundary held. `WorkflowSynthesizerEngine.cs` contains fixed TikTok campaign totals, email invoice content and a speculative mutation/rollback made of printed strings.

**Impact:** a caller can receive `Success=true` without executing a requested action, sending an HTTP request or collecting evidence. Two in-memory reproductions confirmed this. The OAuth execution node correctly refuses an unimplemented exchange, but equivalent failure semantics are not consistently used elsewhere.

**Required change/gate:** unsupported or missing services must produce a typed unavailable/failure result. Put intentional demos behind an explicit nonproduction mode with provenance carried downstream. Replace synthetic business facts with actual connector results before advertising those workflows.

### F17 — P1 when enabled: workflow scripts bypass the mission containment contract

**Evidence:** `WorkflowExecutionEngine.cs:399-431` uses an application-directory working directory and a Job Object without provisioning a jail, applying the node's egress FQDN or requesting AppContainer network denial. Linux runtime selection invokes `wsl.exe -e bash`, not the lease bridge. The constructor makes DLP/audit/launcher services optional.

**Impact:** wiring this component into production would introduce another execution tier under the same “governed” label. A Job Object attached to `wsl.exe` is not evidence of guest process containment or guest-descendant termination. This path is presently uncomposed; do not characterize it as an already exposed UI/API exploit.

**Required change/gate:** route script nodes through the same authorized execution service as other tools and reject unsupported runtime/policy combinations. Tests must establish actual filesystem/network/identity behavior for each enabled runtime, not just launcher invocation.

### F18 — P1 when enabled: local triggers lack caller security and OAuth completion is false

**Evidence:** `EmbeddedWebhookListener.cs:121-145,233-277` processes unauthenticated requests, reads unbounded bodies and executes as hardcoded `RestApiGateway`; task dispatch at `:87` is unbounded. `OAuthCallbackCoordinator.cs:36-65` ignores returned state, stores the authorization code instead of exchanging it, and disposes its linked timeout source when the non-async method returns. The callback page at `EmbeddedWebhookListener.cs:159-192` ignores `handled` and always announces a vaulted token.

**Impact:** once enabled, another local process can trigger stored actions and read their results. Browser-origin attacks require environment-specific verification; they are not claimed as reproduced. OAuth can wait indefinitely and mislead the operator even when no usable token exists. These classes currently lack production wiring.

**Required change/gate:** authenticated principals, signed/replay-resistant webhooks, method/content/body/concurrency limits and explicit startup failure. Implement provider token exchange with bound one-time state, PKCE where appropriate, timeout/cancellation cleanup and truthful callback status. Reuse the separately implemented authentication primitives only after verifying their integration.

### F19 — P2: emergency revocation does not survive restart or span entrypoints

**Evidence:** `IncidentRevocationManager.cs:13,36,49-71` keeps the deny index only in memory; an audit event is not restored into enforcement state. `src/splat-mcp/Program.cs:66-78` passes null as the mission revocation manager.

**Impact:** restarting the console loses revocations, and the MCP mission composition does not consult this subsystem. “Emergency revoked” does not mean globally blocked across tools/processes.

**Required change/gate:** persist an authoritative revocation epoch/index, share it across entrypoints and define whether it also cancels running missions. Restart both hosts after revocation and prove the same identifier cannot execute again.

### F20 — P2: diagnostic confidence and remediation claims exceed the evidence

**Evidence:** `Brain/AgentBrainEngine.cs:232-245` marks a causal hypothesis confirmed solely on Warning/Critical status and refuted otherwise, including Unknown; `:257-263` collects every template remediation. `QualityIsland/Evaluators/AntiHedgingSemanticEvaluator.cs:18-22` penalizes phrases that can express legitimate lack of evidence. `QuickDiagnosticianViewModel.cs:243-256` describes a zero-exit rollback as verified restoration; `SandboxedRemediationEngine.cs:100-110` executes with retained privilege and checks process exit, not restored state.

**Impact:** a real but unrelated warning can be presented as a confirmed cause; absent evidence can refute a hypothesis. Fluent confidence is not measured correctness, and a successful undo command is not proof the prior state was restored. These are system-diagnosis issues, not patient-health findings.

**Required change/gate:** separate observation, hypothesis, support/refutation and unknown states. Preserve calibrated abstention; assess against a held-out corpus of known system incidents and failures. Bind each remediation to a specific observed condition, risk approval, precondition and postcondition. Define filesystem-only versus external-side-effect rollback explicitly.

### F21 — P1/P2: affected SQLite dependency and unsupported UI framework

The live NuGet scan reports `SQLitePCLRaw.lib.e_sqlite3` **2.1.10** through the Data/UI/tests/MCP graphs. The reviewed advisory covers versions **through 2.1.11**, describes SQLite memory corruption before **3.50.2**, and lists no patched version in that old NuGet package family. Do not “fix” this by moving only to 2.1.11. Select a compatible maintained provider/bundle, verify the loaded native SQLite version, then rerun the advisory scan. An exploitable untrusted-SQL path in SPLAT was not demonstrated. [Advisory GHSA-2m69-gcr7-jv3q / CVE-2025-6965](https://github.com/advisories/GHSA-2m69-gcr7-jv3q).

`src/MissionController.UI/MissionController.UI.csproj:42` pins Windows App SDK **1.6.250108002**; Microsoft ended 1.6 servicing on **2025-09-04**. Plan and validate a supported stable upgrade, including packaged deployment and shaders. [Microsoft Windows App SDK lifecycle](https://learn.microsoft.com/en-us/windows/apps/windows-app-sdk/release-channels).

.NET 9 is still supported at audit time; it reaches end of support **2026-11-10**. The current host runtime is 9.0.19. Migrate deliberately to a supported LTS before that deadline rather than inaccurately calling .NET 9 already unsupported. [.NET support policy](https://dotnet.microsoft.com/en-us/platform/support/policy).

### F22 — P1 for enterprise delivery: packaging can announce success without a verified signed package

**Evidence:** `packaging/build-msix.ps1` checks the publish exit code but not the MakeAppx/signing exit codes, permits missing signing tools, falls back to ZIP, and prints an unconditional successful MSIX-signing conclusion. The manifest references logo assets absent from the tracked source inventory; the script creates an Assets directory without generating those images. `install-enterprise.ps1` imports trust into LocalMachine and its ZIP fallback writes Program Files.

**Impact:** source build success does not establish signed, installable MSIX delivery. The provided install path requires administrative provisioning in important cases and does not establish the scope's standard-user/no-UAC promise. Arm64 selection is also inconsistent with hardcoded x64 publish/layout/manifest settings.

**Required change/gate:** fail on missing assets/tools or nonzero native exit codes, verify the final signature/package, distinguish ZIP and MSIX outcomes, and document administrator provisioning separately from user execution. Test install, launch, upgrade, downgrade policy and uninstall on clean managed standard-user machines. No installer or trust-store change was run in this audit.

### F23 — P2: retention does not prove physical erasure

**Evidence:** `DataRetentionService.cs:85-106,170-174` invokes WAL checkpoint through `ExecuteNonQueryAsync` without inspecting checkpoint busy/completion values, then may vacuum and report the sweep. Semantic content is plaintext SQLite text in `SqliteSemanticMemoryIndex.cs:33,58-62`.

**Impact:** a concurrent reader can affect checkpoint completion; row-level removal is not evidence that all prior copies, WAL pages, backups or exports have been erased. DPAPI protection for credentials does not encrypt the whole database. This is a privacy-proof gap, not a demonstrated disk-forensics recovery.

**Required change/gate:** inspect checkpoint results, define retention guarantees and backup/export ownership, and use an explicit encryption/key-retirement design where required. Verify concurrent-reader behavior and inspect intended local artifacts after deletion. Avoid compliance claims based only on a successful SQL update or vacuum flag.

### F24 — P2: verification infrastructure and product claims are not one release contract

**Evidence:** the existing suite passes but misses F01/F02/F13/F16. The repository has no checked-in `.github` CI workflow, SDK pin or complete cross-language release gate; external CI configuration was not inspected. README mixes nine and twelve MCP tools, while scope and multiple plans describe different products. Historical source-hash-pinned BPF evidence is useful, but does not bind an entire shipped package and policy to a fresh full-client run.

**Impact:** more passing tests or documentation-string checks can increase confidence without testing the actual disputed boundary. Security assertions can remain inconsistent across UI, MCP, daemon, package and sales documents.

**Required change/gate:** one supported-capability manifest and release evidence record; mandatory adversarial seam tests; separate Windows/Linux/Python/package gates; fail the release on reported high advisories and unsupported dependencies. Record source revision, dirty state, build/policy hashes, test prerequisites and unmet gates.

## Strengths worth preserving

- Suspended Windows spawn, real Job Objects, restricted-token handling and AppContainer differential tests provide meaningful native evidence for specific supported paths.
- Governed argument binding, bounded investigation/crew loops, explicit structured diagnosis and direct-provider DLP are useful controls when enforced at every entrypoint.
- SQLite transactions, retention-aware commitments, operator attribution types and incident recall are substantive implementation work. Their documented boundaries need the repairs above.
- Recorded BPF canaries show real denials for the measured hooks; the Windows benchmark honestly records a measured overhead rather than maintaining an unsupported sub-millisecond promise.
- Existing refusal paths for failed launches and unimplemented OAuth exchange show the right behavior is already present in parts of the product and can be made consistent.

## Release decision

Use this build for controlled engineering evaluation of explicitly supported, trusted diagnostics. Do not treat it as a secure arbitrary-code service, a durable n8n replacement, a fully isolated multitenant execution host, or a completed enterprise deployment package. Promotion requires the concrete gates in the delivery plan, especially F01-F14, truthful results and an independently reviewed enforcement boundary. No production fixes, dependency upgrades, commits, publishing or deployment were performed by this audit.
