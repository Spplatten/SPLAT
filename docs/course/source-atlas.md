# Source atlas: follow ownership upward

Paths resolve from this course to the actual checkout. Locate the named symbol with rg before editing; source line numbers will move.

~~~powershell
rg -n 'ExecuteLeasedAsync|ExecuteMissionAsync|HandleToolsCallAsync' src
rg -n 'LeaseIpv4Key|splat_socket_connect|kill_tree' native/splat-agent/src
~~~

## The architectural continuum

~~~mermaid
flowchart BT
    H["CPU: instructions, caches, RAM, MMU"] --> OS["Host OS and WSL2 guest OS"]
    OS --> W["Windows jobs, tokens, AppContainer, handles"]
    OS --> L["Linux cgroup v2 and BPF-LSM hooks"]
    W --> WL["SuspendedProcessLauncher"]
    L --> R["Rust splat-agent"]
    R --> B["WslLeasedExecutor: JSON over TCP"]
    WL --> E["MissionExecutionEngine"]
    B --> M["McpServerHandler run_command / run_code"]
    E --> M
    E --> U["WinUI composition and operator views"]
    E --> G["Projects, crews, workflows, model reasoning"]
    G --> M
    D["SQLite audit and registries"] --> E
~~~

Arrows show the upward study order and supporting relationships, not every runtime call. The MCP leased-command route and Windows mission route are distinct. Do not claim that every mission travels through both operating systems.

| Layer | Open this file | Start at | What to trace |
| --- | --- | --- | --- |
| Build graph | [Core project](../../src/MissionController.Core/MissionController.Core.csproj) | TargetFrameworks | Which target the consumer selects |
| Native compilation | [build.rs](../../native/splat-agent/build.rs) | main | BPF C input, clang options, generated Rust skeleton |
| ABI | [lease.rs](../../native/splat-agent/src/lease.rs) | LeaseIpv4Key, kernel_dev_from_st_dev | Sizes, padding, device-number encoding |
| Kernel policy | [lease_lsm.bpf.c](../../native/splat-agent/src/bpf/lease_lsm.bpf.c) | lease_ipv4_key, splat_socket_connect | Lease identity plus endpoint lookup |
| Win32 declarations | [Win32Interop.cs](../../src/MissionController.Infrastructure.Windows/Win32Interop.cs) | LibraryImport declarations (source-generated) | Widths, flags, exact-spelling entry points, error reporting |
| Windows launch | [SuspendedProcessLauncher.cs](../../src/MissionController.Infrastructure.Windows/SuspendedProcessLauncher.cs) | LaunchSuspendedInJobAsync | Suspend, assign, resume, drain, cleanup |
| Resource ownership | [Win32JobSandbox.cs](../../src/MissionController.Infrastructure.Windows/Win32JobSandbox.cs) | ConfigureExtendedLimits | Handles and CPU/memory policy |
| Tokens | [RestrictedTokenProvider.cs](../../src/MissionController.Infrastructure.Windows/RestrictedTokenProvider.cs) | CreateLowPrivilegeToken | Authority reduction |
| Windows network | [SensorAppContainer.cs](../../src/MissionController.Infrastructure.Windows/SensorAppContainer.cs) | SensorAppContainer | Capability SIDs and compatibility costs |
| Linux resources | [cgroup.rs](../../native/splat-agent/src/cgroup.rs) | apply_and_verify, kill_tree | Readback and descendant draining |
| Linux daemon | [main.rs](../../native/splat-agent/src/main.rs) | handle_client, drop_privileges | Authentication, admission, pre_exec, disconnect |
| Daemon authentication | [auth.rs](../../native/splat-agent/src/auth.rs) | PeerAuth | Secret lifecycle and caller validation |
| Windows workspace | [WorkspaceGuard.cs](../../src/splat-mcp/WorkspaceGuard.cs) | OpenForRead, OpenForWrite | Handle-based access and object identity |
| Windows jail | [NtAclJailManager.cs](../../src/MissionController.Infrastructure.Windows/NtAclJailManager.cs) | ProvisionJailAsync | ACL inheritance and cleanup |
| Database | [SqliteStorageContext.cs](../../src/MissionController.Infrastructure.Data/SqliteStorageContext.cs) | InitializeDatabase | Schema and connection pragmas |
| Audit | [SqliteChainedAuditLedger.cs](../../src/MissionController.Infrastructure.Data/SqliteChainedAuditLedger.cs) | AppendLogAsync, VerifyLedgerIntegrityAsync | Transaction, commitment and key selection |
| Retention | [DataRetentionService.cs](../../src/MissionController.Infrastructure.Data/Retention/DataRetentionService.cs) | DataRetentionService | Redaction, checkpoint and purge semantics |
| Cryptographic proof | [MerkleTreeEngine.cs](../../src/MissionController.Infrastructure.Data/Compliance/MerkleTreeEngine.cs) | VerifyProof | Membership versus completeness |
| Lease compiler | [TemplatePolicyCompiler.cs](../../src/MissionController.Infrastructure.Linux/TemplatePolicyCompiler.cs) | CompileTemplatePolicy | Tool mapping, DNS and policy vocabulary |
| Guest bridge | [WslLeasedExecutor.cs](../../src/MissionController.Infrastructure.Linux/WslLeasedExecutor.cs) | ExecuteLeasedAsync | UTF-8 JSON, output frames and terminal results |
| Health | [WslSubstrateHealthChecker.cs](../../src/MissionController.Infrastructure.Linux/WslSubstrateHealthChecker.cs) | WslSubstrateHealthChecker | Reachability versus enforcement |
| Outbound HTTP | [EgressFirewallHandler.cs](../../src/MissionController.Infrastructure.Network/EgressFirewallHandler.cs) | BeginScope, ValidateOutboundTarget | Async-local host authority |
| HTTP transport | [HardenedHttpClientFactory.cs](../../src/MissionController.Infrastructure.Network/HardenedHttpClientFactory.cs) | CreateHardenedClient | Redirect handling and TLS |
| Data filtering | [RegexDataLossPreventionSanitizer.cs](../../src/MissionController.Infrastructure.Network/Dlp/RegexDataLossPreventionSanitizer.cs) | RegexDataLossPreventionSanitizer | Raw input to sanitized output |
| Shared contracts | [Interfaces.cs](../../src/MissionController.Core/Interfaces.cs) | ILeasedExecutor, IProcessLauncher, IAuditLedger | Who owns effects and results |
| Data contracts | [Models.cs](../../src/MissionController.Core/Models.cs) | SingleToolTemplate, JobResourceMetrics | Limits, output contracts, absent measurements |
| Argument binding | [GovernedArgumentBinder.cs](../../src/MissionController.Core/GovernedArgumentBinder.cs) | Bind | Parameters become executable syntax |
| Mission execution | [MissionExecutionEngine.cs](../../src/MissionController.Core/MissionExecutionEngine.cs) | ExecuteMissionAsync | Validation through evidence persistence |
| Finite projects | [ProjectExecutionEngine.cs](../../src/MissionController.Core/ProjectExecutionEngine.cs) | ExecuteProjectAsync | Stage order and bounded hand-off |
| Workflow graph | [WorkflowExecutionEngine.cs](../../src/MissionController.Core/Workflow/WorkflowExecutionEngine.cs) | WorkflowExecutionEngine | Dependencies, node outcomes and unsupported paths |
| Crews | [GovernedCrewEngine.cs](../../src/MissionController.Core/Crew/GovernedCrewEngine.cs) | RunCrewAsync | Delegation budgets and failure propagation |
| Planning | [AgentBrainEngine.cs](../../src/MissionController.Core/Brain/AgentBrainEngine.cs) | ProcessGoalAsync | Goal to approved actions |
| Grounding | [TelemetryGrounder.cs](../../src/MissionController.Core/TelemetryGrounder.cs) | TelemetryGrounder | Claim-to-evidence comparison |
| Semantic memory | [SqliteSemanticMemoryIndex.cs](../../src/MissionController.Infrastructure.Data/Vector/SqliteSemanticMemoryIndex.cs) | SearchSimilarMissionsAsync | Vectorization and similarity ranking |
| Quality gates | [QualityIslandEngine.cs](../../src/MissionController.Core/QualityIsland/QualityIslandEngine.cs) | QualityIslandEngine | Structural and semantic acceptance |
| MCP boundary | [McpServerHandler.cs](../../src/splat-mcp/McpServerHandler.cs) | HandleToolsCallAsync | Actor resolution before dispatch |
| MCP composition | [Program.cs](../../src/splat-mcp/Program.cs) | Main | Dependency construction and standard streams |
| Python adapter | [tools.py](../../src/splat-langgraph-py/splat_langgraph/tools.py) | Public tools | External caller to MCP result |
| UI composition | [App.xaml.cs](../../src/MissionController.UI/App.xaml.cs) | AddSingleton registrations | Interface binding and lifetime |
| UI state | [LiveMissionMonitorViewModel.cs](../../src/MissionController.UI/LiveMissionMonitorViewModel.cs) | LiveMissionMonitorViewModel | Stream consumption, display and cancellation |
| GPU boundary | [SwapChainRenderLoop.cs](../../src/MissionController.UI/Graphics/SwapChainRenderLoop.cs) | RenderAsync | Frame scheduling, disposal and backend contract |
| Shader | [MissionControllerComposite.hlsl](../../src/MissionController.UI/Graphics/Shaders/MissionControllerComposite.hlsl) | Shader entry points | Per-pixel math and compiled resources |
| Distribution | [build-msix.ps1](../../packaging/build-msix.ps1) | Parameters and signing steps | Build artifact versus installed identity |

## Two action traces to reproduce

**Leased command:** MCP standard input → ProcessMessageAsync → HandleToolsCallAsync → ResolveActorAsync → ExecuteRunCommandAsync → LeaseSpec → ILeasedExecutor → WslLeasedExecutor → TCP/JSON → Rust handle_client → token and policy validation → cgroup and BPF maps → workload → frames → MCP result and audit.

**Windows mission:** caller → ExecuteMissionAsync → template validation/revocation/argument binding → jail → Job Object → suspended process → stdout/stderr and exit → sanitization → optional model/quality gates → accepted evidence and audit → caller's stream.

Inspect each effect's failure path, including failures while collecting or publishing evidence. A successful tool exit does not by itself establish a successful mission.
