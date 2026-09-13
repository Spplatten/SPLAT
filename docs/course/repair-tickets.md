# Repair assignments grounded in the current tree

These are coursework specifications, not a claim that production was repaired during course creation. The source observations below were checked at revision 0027e577b75a118f8ec1ad29ddc5d567782ce9a7. Their proposed tests have not yet been implemented unless explicitly listed in verification.md.

“Source-confirmed” means the implementation contains the stated behavior. It does not mean a live exploit was demonstrated. Reproduce each defect before changing it, because a later checkout may already fix it.

## R1 — refuse unresolved destination policy

**Level:** intermediate; weeks 6 and 10. **Status:** source-confirmed compiler behavior; production reachability is narrower than the compiler's availability suggests.

**Source:** [TemplatePolicyCompiler.CompileTemplatePolicy](../../src/MissionController.Infrastructure.Linux/TemplatePolicyCompiler.cs), DNS exception handler.

**Trigger and current result:** a tool-scoped, non-loopback FQDN cannot resolve. The catch adds 127.0.0.1 to the approved IPs while keeping network enabled and retaining the requested port. This substitutes a local service for the declared destination.

**Reachability finding:** current searches find CompileTemplatePolicy invocations in tests, not a production execution call site. MCP holds the compiler dependency but builds the run_command lease directly. Repair the compiler contract without claiming a demonstrated MCP exploit or silently wiring the compiler into a new route.

**Build steps:**

1. Introduce an injectable, narrowly scoped hostname resolver; preserve the normal system resolver at composition.
2. Characterize a declared non-loopback host with a throwing resolver.
3. Return an explicit compilation failure for unresolved or unsupported address sets. Keep intentionally declared loopback separately expressible.
4. Normalize and deduplicate successful IPv4 answers. Validate ports before narrowing numeric types.
5. Trace all actual callers and adapt failure handling without translating rejection into permission.

**Acceptance:** throwing resolver grants no address; IPv6-only resolution is not a fabricated IPv4 success; explicit loopback still works; successful resolution preserves the intended port; model-gateway-only templates remain network-disabled for the tool. Keep [LinuxSubstrateAndCompilerTests](../../tests/MissionController.Tests/LinuxSubstrateAndCompilerTests.cs) relevant.

**Limit:** pinned destination IPs do not by themselves establish server identity, TLS hostname validation or complete network-hook coverage.

## R2 — distinguish cancellation from timeout and confirmed termination

**Level:** intermediate; weeks 7 and 10. **Status:** source-confirmed bridge result/reporting defect.

**Source:** [WslLeasedExecutor.ExecuteLeasedAsync](../../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs), linked token and OperationCanceledException catch.

**Trigger and current result:** the caller cancels during connect/read, or the bridge's local deadline expires. Both reach a catch that sets TimedOut and reports that the kernel/daemon killed the process. The catch has no termination acknowledgement.

**Build steps:**

1. Extend the existing loopback fake-daemon pattern; block at a controlled read point with a barrier.
2. Cancel the caller token and assert the chosen cancellation contract independently of lease duration.
3. Make local deadline expiry produce a timeout result with language limited to what the bridge observed.
4. If introducing a typed terminal reason, update every result consumer and preserve unavailable resource metrics.
5. Treat daemon kill/drain confirmation as a separate protocol addition with compatibility tests.

**Acceptance:** caller cancellation is not reported as lease expiry; local timeout makes no unconfirmed kill claim; missing EXIT and abrupt EOF are not success; explicit EXIT preserves its code; callbacks and violations still propagate; no automatic retry occurs.

**Limit:** fake TCP tests prove bridge semantics, not descendant death. The daemon's disconnect and reaper paths need live process-tree evidence for that claim.

## R3 — make required audit-key failure explicit

**Level:** intermediate/advanced; weeks 5 and 10. **Status:** source-confirmed fallback and composition choice; no live ledger tampering performed.

**Sources:** [GetHmacKeyAsync and AppendLogAsync](../../src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs); [MCP Main](../../src/splat-mcp/Program.cs).

**Trigger and current result:** a supplied vault throws or returns no usable key. Retrieval catches exceptions and returns null; append can compute an unkeyed chain entry. Main currently constructs its ledger without a vault or explicit key, so its default is unkeyed. Do not describe that default as HMAC-authenticated.

**Build steps:**

1. Define an explicit mode for required keyed evidence versus intentional unkeyed use.
2. Inject a throwing, empty, cancelled and successful vault into separate temporary-ledger fixtures.
3. In required mode, refuse append and verification when the required key is unavailable. Preserve OperationCanceledException.
4. Establish and load the key at composition before promising keyed evidence.
5. Specify how existing unkeyed records are recognized and anchored; do not silently rewrite their history.

**Acceptance:** required-mode missing key cannot append an unkeyed row; valid-key round trips pass; wrong-key verification fails; cancellation propagates; deliberate unkeyed mode remains accurately labeled; existing payload/redaction tests still pass.

**Limit:** HMAC does not protect against a caller who also controls the key, and a valid ledger can still contain a false original observation.

## R4 — bound the request before parsing it

**Level:** intermediate for a parser, advanced across both transports; weeks 6 and 10. **Status:** source-confirmed unbounded line-read sites; resource-exhaustion impact has not been exercised.

**Sources:** [Rust handle_client](../../native/splat-agent/src/main.rs), BufReader.read_line before JSON parsing/token validation; [MCP Main](../../src/splat-mcp/Program.cs), ReadLineAsync.

**Trigger and current result:** a peer sends a very long frame or never terminates a line. These call sites have no explicit pre-allocation frame-byte budget or per-frame read deadline.

**Build steps:**

1. Specify a finite UTF-8 byte budget, deadline, EOF behavior and error response.
2. Extract a bounded frame reader whose parser never receives an oversized payload.
3. Test segmented reads, multiple frames in one input, multi-byte characters, malformed UTF-8 and partial EOF.
4. Propagate cancellation and release connection/buffer ownership deterministically.
5. Add separate output budgets: bounding requests alone does not bound tool output or accumulated results.

**Acceptance:** exactly-at-limit frame parses; one byte over is rejected before unbounded growth; invalid input cannot dispatch; cancellation releases the read; secrets are not echoed in errors; a permitted small request still works.

**Limit:** a per-connection cap alone does not bound total memory across many connections. Concurrency admission needs its own measured budget.

## R5 — explicit workspace selection before startup effects

**Level:** beginner/intermediate; weeks 9 and 10. **Status:** source-confirmed missing CLI behavior.

**Source:** [MCP Main(string[] args)](../../src/splat-mcp/Program.cs); [WorkspaceGuard](../../src/splat-mcp/WorkspaceGuard.cs).

**Trigger and current result:** a caller supplies --workspace. Main does not parse args and constructs the database and catalog before serving requests. The requested workspace is therefore not bound by that option.

**Build steps:**

1. Add a small typed options parser with help, explicit workspace, and rejection of unknown or incomplete options.
2. Validate options before constructing storage, registries or a daemon-facing service.
3. Pass the selected root to the handler's existing workspace seam; retain handle-based confinement.
4. Make help and option errors terminate without entering the JSON-RPC loop.
5. Keep normal protocol stdout free of startup logging. Direct diagnostics to stderr.

**Acceptance:** selected root reaches WorkspaceGuard; missing/invalid options do not create a database or start work; help exits promptly; traversal and junction regressions remain green; a valid in-root file operation still works.

**Limit:** selecting a Windows MCP workspace does not create a Linux mount namespace for leased commands.

## R6 — close one declared Linux coverage gap

**Level:** advanced, preferably the twelve-week route. **Status:** documented gaps confirmed against the current hook set; no new kernel proof collected.

**Sources:** [SUPPORTED_POLICY](../../native/splat-agent/SUPPORTED_POLICY.md), [BPF hooks](../../native/splat-agent/src/bpf/lease_lsm.bpf.c), [daemon spawn](../../native/splat-agent/src/main.rs).

Choose exactly one: unconnected UDP send policy; inherited-descriptor control; or filesystem confinement through a private mount namespace and restricted root. Local IPC needs its own policy decision. Do not promise all four after closing one.

**Build steps:**

1. Define permitted/denied operations and compatibility requirements.
2. Reproduce the gap with a harmless fixture in an instructor-owned disposable guest.
3. Identify every kernel operation needed for the promised boundary; consult the current kernel's available hooks and verifier constraints.
4. Add policy vocabulary only when the daemon and enforcement consumer support it.
5. Add permitted and denied controls, concurrent-lease isolation, disconnect, expiry and cleanup probes.
6. Regenerate evidence tied to the exact BPF/daemon sources and update only the claims the probes establish.

**Acceptance:** kernel accepts the program; denied operation fails because of the lease rather than ordinary permissions; permitted control works; other leases retain isolation; cleanup leaves no live workload without its policy.

**Limit:** a prototype or a passing fixture is insufficient to enable production flags for unsupported containment.

## Already repaired mechanisms to study as regressions

| Case study | Current source/test evidence | Student task |
| --- | --- | --- |
| Actor resolved after effects | HandleToolsCallAsync now resolves before dispatch; [pre-execution tests](../../tests/MissionController.Tests/AuditPayloadAndPreExecutionAuthTests.cs) passed in the selected run. | Add another rejected-identity variant and assert zero effects. |
| Payload changed while a chain still verifies | Same test file covers edited details and forged redaction. | Explain the commitment/redaction design and add a boundary case. |
| Pre-quoted argv loses meaning across transport | [ArgumentVectorContractTests](../../tests/MissionController.Tests/ArgumentVectorContractTests.cs) and [wire tests](../../tests/MissionController.Tests/WslLeasedExecutorWireTests.cs) passed. | Add an encoding regression; retain protocol version 2. |
| Fabricated resource metrics | Wire tests require unavailable metrics where no counters were measured. | Trace unavailable through one outward consumer. |
| Sensor failure indexed as evidence | [FailureIsNotEvidenceTests](../../tests/MissionController.Tests/FailureIsNotEvidenceTests.cs) passed. | Add a consumer assertion across a stage boundary. |
| Reachable daemon called enforcing | [SubstrateHealthHonestyTests](../../tests/MissionController.Tests/SubstrateHealthHonestyTests.cs) passed against fixtures. | Explain why a real kernel probe is still required. |

Keep historical defects in historical context. For Linux per-lease keys and kill-before-withdraw ordering, this course reviewed code and committed probes; it did not repeat live privileged execution.
