using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Crew;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Host;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Dlp;
using MissionController.Infrastructure.Network.Identity;

namespace SplatMcp;

public partial class McpServerHandler
{
    private readonly ILeasedExecutor _leasedExecutor;
    private readonly ITemplatePolicyCompiler _policyCompiler;
    private readonly IAuditLedger _auditLedger;
    private readonly ICredentialSanitizer _credentialSanitizer;
    private readonly IDataLossPreventionSanitizer _dlpSanitizer;
    private readonly WslSubstrateHealthChecker _healthChecker;
    private readonly IMissionExecutionEngine? _missionEngine;
    private readonly IMissionRunRecordAssembler? _runRecords;
    private readonly RunRecordLedgerVerifier? _recordVerifier;
    private readonly IGovernedInvestigationLoop? _investigationLoop;
    private readonly ITemplateRegistry? _templateRegistry;
    private readonly ISemanticMemoryIndex? _semanticMemory;
    private readonly IModelStreamClient? _modelClient;
    private readonly IAgentBrain? _agentBrain;
    private readonly IGovernedCrewEngine? _crewEngine;
    private readonly IGovernedCrewRegistry? _crewRegistry;
    private readonly IOperatorIdentityProvider _identityProvider;
    private readonly IIncidentRevocationManager? _revocationManager;

    /// <summary>
    /// The ledger actor for the call in flight, resolved through <see cref="_identityProvider"/>.
    ///
    /// This replaced a <c>string _operatorIdentity</c> field defaulting to the literal
    /// <c>"mcp-client"</c>, which named the transport in the column reserved for who acted and made
    /// every non-repudiation claim over this server's rows unfounded.
    /// </summary>
    private async Task<string> ResolveActorAsync(CancellationToken ct)
    {
        // Resolved once per tool call and reused. Every handler still asks for the actor where it
        // needs one, but the provider is consulted at the gate in HandleToolsCallAsync, so the
        // identity that authorized the call is the identity that lands in the ledger row - not a
        // second resolution that could answer differently.
        if (CurrentActor.Value is { } cached)
        {
            return cached;
        }

        string actor = (await _identityProvider.ResolveAsync(ct)).ToLedgerIdentity();
        CurrentActor.Value = actor;
        return actor;
    }

    /// <summary>
    /// The actor for the tool call in flight. AsyncLocal rather than a field so the value is scoped
    /// to one logical request even if the transport is ever driven concurrently, and so it reaches
    /// every handler the dispatch switch calls without threading a parameter through twelve
    /// signatures.
    /// </summary>
    private static readonly AsyncLocal<string?> CurrentActor = new();

    /// <summary>
    /// The only directory subtree <c>fs_read</c> and <c>fs_write</c> may touch.
    ///
    /// Both tools previously called File.ReadAllTextAsync / File.WriteAllTextAsync on whatever
    /// absolute path the caller supplied, at this process's own privilege, guarded only by substring
    /// checks against LINUX paths (/etc/shadow, /etc/, /sys/, /proc/) that match nothing on the
    /// Windows host this code runs on. Any MCP client could read %USERPROFILE%\.aws\credentials or
    /// write into C:\Windows. Confining them to one governed root is what makes the tool
    /// descriptions true; <see cref="ResolveWithinWorkspace"/> is what enforces it.
    /// </summary>
    /// <summary>
    /// Where fs_read and fs_write are confined when the host names no workspace. Defined once, so the
    /// help text and the startup note on stderr cannot describe a different folder from the one the
    /// guard actually uses.
    /// </summary>
    public static string DefaultWorkspaceRoot { get; } = SplatDataRoot.Layout.McpWorkspace;

    private readonly string _workspaceRoot;

    /// <summary>
    /// Decides containment from a HANDLE rather than from a string. The path-prefix test this
    /// replaced was a statement about a name, and a junction inside the workspace normalises to a
    /// name under the root while resolving somewhere else entirely.
    /// </summary>
    private readonly WorkspaceGuard _workspace;

    /// <summary>The endpoints a run_command lease may name. See <see cref="McpEgressPolicy"/>.</summary>
    private readonly McpEgressPolicy _egressPolicy;
    private readonly AgentManifestApproval? _agent;
    internal bool IsAgentBound => _agent is not null;

    public McpServerHandler(
        ILeasedExecutor leasedExecutor,
        ITemplatePolicyCompiler policyCompiler,
        IAuditLedger auditLedger,
        WslSubstrateHealthChecker? healthChecker = null,
        IMissionExecutionEngine? missionEngine = null,
        IGovernedInvestigationLoop? investigationLoop = null,
        ITemplateRegistry? templateRegistry = null,
        ISemanticMemoryIndex? semanticMemory = null,
        IModelStreamClient? modelClient = null,
        IAgentBrain? agentBrain = null,
        IGovernedCrewEngine? crewEngine = null,
        IGovernedCrewRegistry? crewRegistry = null,
        IOperatorIdentityProvider? identityProvider = null,
        string? workspaceRoot = null,
        McpEgressPolicy? egressPolicy = null,
        IMissionRunRecordAssembler? runRecords = null,
        IIncidentRevocationManager? revocationManager = null,
        RunRecordLedgerVerifier? recordVerifier = null,
        ICredentialSanitizer? credentialSanitizer = null,
        IDataLossPreventionSanitizer? dlpSanitizer = null,
        AgentManifestApproval? agent = null)
    {
        _runRecords = runRecords;
        _recordVerifier = recordVerifier;
        _leasedExecutor = leasedExecutor ?? throw new ArgumentNullException(nameof(leasedExecutor));
        _policyCompiler = policyCompiler ?? throw new ArgumentNullException(nameof(policyCompiler));
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _credentialSanitizer = credentialSanitizer ?? new PromptCredentialSanitizer();
        _dlpSanitizer = dlpSanitizer ?? new RegexDataLossPreventionSanitizer();
        _healthChecker = healthChecker ?? new WslSubstrateHealthChecker();
        _missionEngine = missionEngine;
        _investigationLoop = investigationLoop;
        _templateRegistry = templateRegistry;
        _semanticMemory = semanticMemory;
        _modelClient = modelClient;
        _agentBrain = agentBrain;
        _crewEngine = crewEngine;
        _crewRegistry = crewRegistry;
        _identityProvider = identityProvider ?? new McpOperatorIdentityProvider(
            new StaticOperatorIdentityProvider(OperatorIdentity.Unknown("mcp-stdio")));
        _workspace = new WorkspaceGuard(workspaceRoot ?? DefaultWorkspaceRoot);
        _workspaceRoot = _workspace.Root;
        // No policy means no network for run_command, not the caller's choice of network.
        _egressPolicy = egressPolicy ?? McpEgressPolicy.None;
        _revocationManager = revocationManager;
        if (agent is not null)
        {
            AgentManifestApproval.ValidateSelection(agent.AgentId, agent.Sha256);
            if (AgentManifestApproval.AgentIdOf(agent.Manifest) != agent.AgentId
                || AgentManifestApproval.Hash(agent.Manifest) != agent.Sha256)
                throw new InvalidOperationException("Agent contract does not match its approved version.");
            // Copy at the authority boundary; caller-owned collections cannot mutate a live session.
            _agent = agent with { Manifest = JsonSerializer.Deserialize<CompiledAgentManifest>(
                JsonSerializer.Serialize(agent.Manifest))! };
        }
    }

    /// <summary>
    /// The refusal returned when a path leaves the workspace. It says what actually happened - a
    /// user-space policy check in this process - because the string it replaced claimed
    /// "[KERNEL -EPERM BLOCK]" for a string.Contains() test, telling both the calling agent and the
    /// compliance ledger that a kernel had denied something no kernel was ever asked about.
    /// </summary>
    private McpToolCallResult OutOfWorkspace(string tool, string path) => new()
    {
        IsError = true,
        Content = new List<McpContentItem>
        {
            new()
            {
                Type = "text",
                Text = $"[SPLAT POLICY] {tool} is confined to the governed workspace at " +
                       $"'{_workspaceRoot}'. The path '{path}' resolves outside it and was refused. " +
                       "This is a user-space policy check in the MCP host, not a kernel denial."
            }
        }
    };

    public async Task<McpJsonRpcMessage> ProcessMessageAsync(McpJsonRpcMessage request, CancellationToken ct = default)
    {
        if (request == null)
        {
            return CreateErrorResponse(null, -32600, "Invalid Request");
        }

        if (string.IsNullOrEmpty(request.Method))
        {
            return CreateErrorResponse(request.Id, -32600, "Missing method");
        }

        try
        {
            switch (request.Method)
            {
                case "initialize":
                    return HandleInitialize(request);

                case "notifications/initialized":
                case "ping":
                    return new McpJsonRpcMessage { JsonRpc = "2.0", Id = request.Id, Result = JsonSerializer.SerializeToElement(new { }) };

                case "tools/list":
                    return await HandleToolsListAsync(request, ct);

                case "tools/call":
                    return await HandleToolsCallAsync(request, ct);

                default:
                    return CreateErrorResponse(request.Id, -32601, $"Method '{request.Method}' not found");
            }
        }
        catch (McpAuthenticationException authFailure)
        {
            // FAIL CLOSED. A credential was presented and did not validate, so there is no actor to
            // attribute this call to. Refusing is the only outcome that keeps the ledger honest -
            // falling back to an anonymous row here would let a caller downgrade their own
            // attribution simply by sending a bad token.
            return CreateErrorResponse(
                request.Id, -32001, $"Authentication failed [{authFailure.ErrorCode}]: {authFailure.Message}");
        }
        catch (Exception ex)
        {
            return CreateErrorResponse(request.Id, -32603, Scrub($"Internal server error: {ex.Message}"));
        }
    }

    private McpJsonRpcMessage HandleInitialize(McpJsonRpcMessage request)
    {
        var result = new McpInitializeResult();
        if (_agent is not null)
            result.Instructions = $"This endpoint is bound to agent {_agent.AgentId}, contract {_agent.Sha256}. "
                + "Use tools/list for the only available tools. Execution authority comes from the saved contract.";
        return new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = request.Id,
            Result = JsonSerializer.SerializeToElement(result)
        };
    }

    private Task<McpJsonRpcMessage> HandleToolsListAsync(McpJsonRpcMessage request, CancellationToken ct)
    {
        if (_agent is not null)
            return Task.FromResult(ListAgentTools(request));
        var tools = new List<McpToolDefinition>
        {
            new()
            {
                Name = "run_command",
                Description = "Execute a command in the WSL2 guest under an in-kernel BPF-LSM capability lease: exec limited to exactly this command, memory/CPU/PID clamps, and network only to endpoints this host's operator approved.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""command"": { ""type"": ""string"", ""description"": ""The executable to run (e.g. /bin/bash, /usr/bin/python3, /bin/ls)"" },
                        ""args"": { ""type"": ""array"", ""items"": { ""type"": ""string"" }, ""description"": ""Arguments as a vector, already separated. Preferred: nothing re-splits it, so spaces and quotes inside an argument survive intact."" },
                        ""arguments"": { ""type"": ""string"", ""description"": ""Legacy shell-style argument string. Split POSIX-style on this side before it reaches the guest; an unterminated quote is refused rather than guessed. Prefer 'args'."" },
                        ""workingDirectory"": { ""type"": ""string"", ""description"": ""Working directory inside sandbox"", ""default"": ""/tmp"" },
                        ""allowNetwork"": { ""type"": ""boolean"", ""description"": ""Request network egress. Granted only inside this host's operator egress policy (splat-mcp --egress a.b.c.d:port,...), and refused when the host has none. The ports come from that policy, not from the caller."", ""default"": false },
                        ""allowedEgressIps"": { ""type"": ""array"", ""items"": { ""type"": ""string"" }, ""description"": ""IPv4 addresses to request, each of which must be in the operator's egress policy; omit to request every address it approves. Refused if sent without allowNetwork."" },
                        ""timeoutSeconds"": { ""type"": ""integer"", ""description"": ""Lease lifespan in seconds (5-300)"", ""default"": 30 },
                        ""readOnlyFs"": { ""type"": ""boolean"", ""description"": ""NOT ENFORCED - the guest daemon establishes no mount namespace for the workload, so it REFUSES this request rather than accepting a boundary it cannot impose. Leave false."", ""default"": false },
                        ""traceId"": { ""type"": ""string"", ""description"": ""Optional external orchestrator trace id (LangSmith/OpenTelemetry run id). Correlated into the chained audit ledger and echoed in the auditAnchor result item."" },
                        ""clientName"": { ""type"": ""string"", ""description"": ""Optional calling framework name (e.g. langgraph, copilot-studio), recorded with the trace correlation."" }
                    },
                    ""required"": [""command""]
                }")
            },
            new()
            {
                Name = "run_code",
                Description = "Execute code (bash script, python, etc.) under an ephemeral kernel sandbox with full audit chaining.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""language"": { ""type"": ""string"", ""description"": ""Script language (bash, sh, python3)"", ""default"": ""bash"" },
                        ""code"": { ""type"": ""string"", ""description"": ""The source code script content to execute"" },
                        ""workingDirectory"": { ""type"": ""string"", ""description"": ""Working directory"", ""default"": ""/tmp"" },
                        ""allowNetwork"": { ""type"": ""boolean"", ""description"": ""Request network egress, under the same operator egress policy as run_command."", ""default"": false },
                        ""timeoutSeconds"": { ""type"": ""integer"", ""description"": ""Timeout in seconds"", ""default"": 30 },
                        ""traceId"": { ""type"": ""string"", ""description"": ""Optional external orchestrator trace id (LangSmith/OpenTelemetry run id). Correlated into the chained audit ledger and echoed in the auditAnchor result item."" },
                        ""clientName"": { ""type"": ""string"", ""description"": ""Optional calling framework name (e.g. langgraph, copilot-studio), recorded with the trace correlation."" }
                    },
                    ""required"": [""code""]
                }")
            },
            new()
            {
                Name = "fs_read",
                Description = "Read a file from SPLAT's governed MCP workspace. Paths are resolved inside the workspace root and anything outside it is refused by host policy. This is a user-space boundary, not a kernel one.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""path"": { ""type"": ""string"", ""description"": ""Path to read, relative to the workspace root. Absolute paths outside the workspace are refused."" }
                    },
                    ""required"": [""path""]
                }")
            },
            new()
            {
                Name = "fs_write",
                Description = "Write a file into SPLAT's governed MCP workspace, with a chained audit-ledger record. Paths are resolved inside the workspace root and anything outside it is refused by host policy. This is a user-space boundary, not a kernel one.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""path"": { ""type"": ""string"", ""description"": ""Path to write, relative to the workspace root. Absolute paths outside the workspace are refused."" },
                        ""content"": { ""type"": ""string"", ""description"": ""Content to write"" }
                    },
                    ""required"": [""path"", ""content""]
                }")
            },
            new()
            {
                Name = "get_substrate_health",
                Description = "Check health and capability status of the underlying WSL2 kernel substrate, BPF-LSM, and cgroups v2.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {}
                }")
            },
            new()
            {
                Name = "list_diagnostic_templates",
                Description = "List all pre-approved, governed 1:1:1 diagnostic sensor templates available in SPLAT's catalog.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""category"": { ""type"": ""string"", ""description"": ""Optional category filter (e.g. Networking, Identity & Access, Endpoint Security, SysOps & Fleet Health)"" }
                    }
                }")
            },
            new()
            {
                Name = "diagnose_system",
                Description = "Execute a governed diagnostic mission using SPLAT's 1:1:1 sandbox + DLP filter + live AI reasoning stream + Merkle audit.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""templateId"": { ""type"": ""string"", ""description"": ""The template ID (e.g. net-dns-diagnostics, sys-disk-health, endpoint-defender-status)"" },
                        ""userInstruction"": { ""type"": ""string"", ""description"": ""Optional specific directive or goal to guide the diagnostic analysis"" },
                        ""parameters"": { ""type"": ""object"", ""description"": ""Key-value parameters for template arguments"" },
                        ""traceId"": { ""type"": ""string"", ""description"": ""Optional external orchestrator trace id (LangSmith/OpenTelemetry run id). Correlated into the chained audit ledger and echoed in the auditAnchor result item."" },
                        ""clientName"": { ""type"": ""string"", ""description"": ""Optional calling framework name (e.g. langgraph, copilot-studio), recorded with the trace correlation."" }
                    },
                    ""required"": [""templateId""]
                }")
            },
            new()
            {
                Name = "investigate_system",
                Description = "Run SPLAT's autonomous Reason-Act-Observe cognitive investigation loop: multi-step hypothesis testing across sandboxed tools with AI decision making.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""startingTemplateId"": { ""type"": ""string"", ""description"": ""The initial template ID to start the investigation from"" },
                        ""investigationGoal"": { ""type"": ""string"", ""description"": ""High-level goal or symptom description (e.g. 'Investigate slow outbound network latency' or 'Check for unauthorized persistence')"" },
                        ""maxSteps"": { ""type"": ""integer"", ""description"": ""Maximum investigation steps to chain (1-5)"", ""default"": 3 },
                        ""traceId"": { ""type"": ""string"", ""description"": ""Optional external orchestrator trace id (LangSmith/OpenTelemetry run id). Correlated into the chained audit ledger and echoed in the auditAnchor result item."" },
                        ""clientName"": { ""type"": ""string"", ""description"": ""Optional calling framework name (e.g. langgraph, copilot-studio), recorded with the trace correlation."" }
                    },
                    ""required"": [""startingTemplateId""]
                }")
            },
            new()
            {
                Name = "search_incident_memory",
                Description = "Search historical fleet incident memory for past diagnoses, findings, and remediation actions using semantic indexing.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""query"": { ""type"": ""string"", ""description"": ""Search query or symptom description"" },
                        ""topK"": { ""type"": ""integer"", ""description"": ""Maximum results to return"", ""default"": 5 }
                    },
                    ""required"": [""query""]
                }")
            },
            new()
            {
                Name = "export_run_record",
                Description = "Export one mission's run record: a bundle holding what the mission was permitted to do and what it did, the mission's audit ledger entries with a Merkle proof for each, and scripts that verify them. Signed when the host was started with a run record key. The mission must have ended.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""missionId"": { ""type"": ""string"", ""description"": ""The mission's id, as returned by the tool that ran it."" },
                        ""outputDirectory"": { ""type"": ""string"", ""description"": ""Where to write the bundle. Defaults to %LOCALAPPDATA%\\MissionController\\MissionRunRecords."" }
                    },
                    ""required"": [""missionId""]
                }")
            },
            new()
            {
                Name = "verify_run_record",
                Description = "Check a run record bundle against this host's ledger. Everything inside a bundle agrees with itself however many of the mission's rows were left out of it; this reports, row by row, whether the live ledger still holds exactly those entries at those positions and nothing more for that mission, whether the bundle's signature covers every file unchanged, and whether the host's own chain recomputes.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""bundlePath"": { ""type"": ""string"", ""description"": ""Path to the RUN-RECORD-*.zip to check, as returned by export_run_record."" }
                    },
                    ""required"": [""bundlePath""]
                }")
            },
            new()
            {
                Name = "run_agent_brain",
                Description = "Execute SPLAT's Layer 2 Cognitive Planning & Autonomous Reasoning Engine ('The Brain'): Decomposes high-level natural language goals, performs multi-hypothesis testing, verifies grounded telemetry, synthesizes cross-subsystem root cause, and formulates self-healing remediations with Merkle ledger commitment.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""userGoal"": { ""type"": ""string"", ""description"": ""High-level directive or symptom description to autonomously investigate (e.g. 'Investigate packet loss and slow outbound DNS queries')"" },
                        ""maxReasoningSteps"": { ""type"": ""integer"", ""description"": ""Maximum reasoning steps to execute (1-5)"", ""default"": 3 },
                        ""traceId"": { ""type"": ""string"", ""description"": ""Optional external orchestrator trace id (LangSmith/OpenTelemetry run id). Correlated into the chained audit ledger and echoed in the auditAnchor result item."" },
                        ""clientName"": { ""type"": ""string"", ""description"": ""Optional calling framework name (e.g. langgraph, copilot-studio), recorded with the trace correlation."" }
                    },
                    ""required"": [""userGoal""]
                }")
            },
            new()
            {
                Name = "list_governed_crews",
                Description = "List all pre-configured enterprise multi-agent crews available in SPLAT's catalog.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {}
                }")
            },
            new()
            {
                Name = "run_governed_crew",
                Description = "Execute a governed multi-agent crew (e.g. 'secops-incident-response-crew', 'campus-infrastructure-audit-crew') with kernel containment, DLP sanitization, anti-deadlock cycle protection, and SHA-256 chained audit ledgers.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""crewId"": { ""type"": ""string"", ""description"": ""The crew ID to execute (e.g. 'secops-incident-response-crew', 'campus-infrastructure-audit-crew')"" },
                        ""parameters"": { ""type"": ""object"", ""description"": ""Optional key-value parameters passed to the crew's tasks"" },
                        ""traceId"": { ""type"": ""string"", ""description"": ""Optional external orchestrator trace id (LangSmith/OpenTelemetry run id). Correlated into the chained audit ledger and echoed in the auditAnchor result item."" },
                        ""clientName"": { ""type"": ""string"", ""description"": ""Optional calling framework name (e.g. langgraph, copilot-studio), recorded with the trace correlation."" }
                    },
                    ""required"": [""crewId""]
                }")
            }
        };

        // One statement of what holds each tool, taken from the manifest that doctor and the
        // tests read too. A description that says "governed" without saying by what is where F24
        // began, and a tool the manifest does not name fails a test rather than shipping silent.
        foreach (var tool in tools)
        {
            var capability = CapabilityManifest.Tools.FirstOrDefault(c => c.Tool == tool.Name);
            if (capability is not null)
            {
                tool.Description += $" Enforced by {capability.Detail}.";
            }
        }

        var responseData = new { tools };
        return Task.FromResult(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = request.Id,
            Result = JsonSerializer.SerializeToElement(responseData)
        });
    }

    private async Task<McpJsonRpcMessage> HandleToolsCallAsync(McpJsonRpcMessage request, CancellationToken ct)
    {
        if (!request.Params.HasValue)
        {
            return CreateErrorResponse(request.Id, -32602, "Missing tool call parameters");
        }

        var paramDoc = request.Params.Value;
        string toolName = paramDoc.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? "" : "";
        JsonElement args = paramDoc.TryGetProperty("arguments", out var argsProp) ? argsProp : default;

        // IDENTITY BEFORE EFFECTS. Each handler used to resolve the actor on its way to the ledger,
        // which put resolution AFTER the side effect: run_command executed and fs_write hit disk,
        // and only then did a rejected credential throw - so the call left an execution or a file
        // behind, and because the throw skipped the append that followed it, no ledger row either.
        // Resolving here means an unauthenticated caller reaches no executor and no filesystem.
        CurrentActor.Value = null;
        string actor = await ResolveActorAsync(ct);

        // CIRCUIT BREAKER BEFORE EFFECTS: If this principal/actor is revoked, fail closed immediately.
        if (_revocationManager != null)
        {
            RevocationStatus revStatus;
            try
            {
                revStatus = await _revocationManager.CheckRevocationAsync(actor, ct);
            }
            catch (RevocationUnavailableException ex)
            {
                // No answer is not the same as "not revoked". The call is refused, and the refusal
                // is recorded, so a revocation database that quietly went missing shows up as
                // refused calls rather than as calls that were never checked.
                await AppendScrubbedLogAsync(
                    Guid.NewGuid(),
                    $"mcp-tool-{toolName}",
                    "CALL_REFUSED_REVOCATION_UNREADABLE",
                    $"Whether principal '{actor}' is revoked could not be established: {ex.Message}",
                    actor,
                    ct);

                return CreateErrorResponse(
                    request.Id,
                    -32003,
                    $"Execution refused. Whether principal '{actor}' has been revoked could not be established: {ex.Message}");
            }

            if (revStatus.IsRevoked)
            {
                await AppendScrubbedLogAsync(
                    Guid.NewGuid(),
                    $"mcp-tool-{toolName}",
                    "CALL_REFUSED_REVOKED_PRINCIPAL",
                    $"Principal '{actor}' is revoked: {revStatus.Entry?.Reason}",
                    actor,
                    ct);

                return CreateErrorResponse(
                    request.Id,
                    -32003,
                    $"Execution refused. Principal '{actor}' has been revoked: {revStatus.Entry?.Reason}");
            }
        }

        McpToolCallResult toolResult;

        // This gate precedes every generic tool, including nested orchestration and host file I/O.
        // The caller cannot supply or switch an agent ID; the operator pinned it at host startup.
        if (_agent is not null)
        {
            toolResult = await ExecuteAgentToolAsync(toolName, args, actor, ct);
            toolResult = await AttachAuditAnchorAsync(toolName, args, toolResult, ct);
            return new McpJsonRpcMessage { JsonRpc = "2.0", Id = request.Id,
                Result = JsonSerializer.SerializeToElement(toolResult) };
        }

        switch (toolName)
        {
            case "run_command":
                toolResult = await ExecuteRunCommandAsync(args, ct);
                break;

            case "run_code":
                toolResult = await ExecuteRunCodeAsync(args, ct);
                break;

            case "fs_read":
                toolResult = await ExecuteFsReadAsync(args, ct);
                break;

            case "fs_write":
                toolResult = await ExecuteFsWriteAsync(args, ct);
                break;

            case "get_substrate_health":
                toolResult = await ExecuteGetSubstrateHealthAsync(ct);
                break;

            case "list_diagnostic_templates":
                toolResult = await ExecuteListTemplatesAsync(args, ct);
                break;

            case "diagnose_system":
                toolResult = await ExecuteDiagnoseSystemAsync(args, ct);
                break;

            case "investigate_system":
                toolResult = await ExecuteInvestigateSystemAsync(args, ct);
                break;

            case "search_incident_memory":
                toolResult = await ExecuteSearchIncidentMemoryAsync(args, ct);
                break;

            case "run_agent_brain":
                toolResult = await ExecuteRunAgentBrainAsync(args, ct);
                break;

            case "export_run_record":
                toolResult = await ExecuteExportRunRecordAsync(args, ct);
                break;

            case "verify_run_record":
                toolResult = await ExecuteVerifyRunRecordAsync(args, ct);
                break;

            case "list_governed_crews":
                toolResult = await ExecuteListGovernedCrewsAsync(ct);
                break;

            case "run_governed_crew":
                toolResult = await ExecuteRunGovernedCrewAsync(args, ct);
                break;

            default:
                return CreateErrorResponse(request.Id, -32601, $"Tool '{toolName}' is not recognized");
        }

        toolResult = await AttachAuditAnchorAsync(toolName, args, toolResult, ct);

        return new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = request.Id,
            Result = JsonSerializer.SerializeToElement(toolResult)
        };
    }

    private static int GetSafeInt(JsonElement args, string propertyName, int defaultValue, int min, int max)
    {
        if (!args.TryGetProperty(propertyName, out var prop))
            return defaultValue;

        if (prop.ValueKind == JsonValueKind.Number && prop.TryGetInt32(out int numVal))
            return Math.Clamp(numVal, min, max);

        if (prop.ValueKind == JsonValueKind.String && int.TryParse(prop.GetString(), out int strVal))
            return Math.Clamp(strVal, min, max);

        return defaultValue;
    }

    private static bool GetSafeBool(JsonElement args, string propertyName, bool defaultValue)
    {
        if (!args.TryGetProperty(propertyName, out var prop))
            return defaultValue;

        if (prop.ValueKind is JsonValueKind.True or JsonValueKind.False)
            return prop.GetBoolean();

        if (prop.ValueKind == JsonValueKind.String && bool.TryParse(prop.GetString(), out bool strVal))
            return strVal;

        return defaultValue;
    }

    /// <param name="toolName">
    /// The tool the caller named. run_code wraps its script and delegates here, and its rows used to
    /// land under run_command's name - a record that described a call nobody made.
    /// </param>
    private async Task<McpToolCallResult> ExecuteRunCommandAsync(JsonElement args, CancellationToken ct,
        string toolName = "run_command", LeaseSpec? approvedLease = null)
    {
        string ledgerTool = $"mcp-tool-{toolName}";
        var startedAtUtc = DateTimeOffset.UtcNow;
        string command = args.TryGetProperty("command", out var cmdProp) ? cmdProp.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(command))
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem>
                {
                    new() { Type = "text", Text = "Error: 'command' parameter is required and cannot be empty." }
                }
            };
        }

        // `args` (an array) is the contract; `arguments` (a string) is the legacy shape, split
        // here rather than in the guest. The daemon used to split on whitespace, which cannot
        // recover quoting and produced silently wrong argument vectors.
        IReadOnlyList<string> argv;
        string argumentsForLog;
        if (args.TryGetProperty("args", out var argvProp) && argvProp.ValueKind == JsonValueKind.Array)
        {
            var list = new List<string>();
            foreach (var el in argvProp.EnumerateArray())
            {
                if (el.GetString() is string a)
                {
                    list.Add(a);
                }
            }
            argv = list;
            argumentsForLog = string.Join(" ", list);
        }
        else
        {
            string arguments = args.TryGetProperty("arguments", out var argProp) ? argProp.GetString() ?? "" : "";
            try
            {
                argv = PosixArgumentSplitter.Split(arguments);
            }
            catch (FormatException ex)
            {
                return new McpToolCallResult
                {
                    IsError = true,
                    Content = new List<McpContentItem>
                    {
                        new() { Type = "text", Text = $"Error: could not parse 'arguments': {ex.Message} Pass an 'args' array instead." }
                    }
                };
            }
            argumentsForLog = arguments;
        }
        string workDir = args.TryGetProperty("workingDirectory", out var wdProp) ? wdProp.GetString() ?? "/tmp" : "/tmp";
        bool allowNetwork = GetSafeBool(args, "allowNetwork", false);
        uint timeoutSec = (uint)GetSafeInt(args, "timeoutSeconds", 30, 5, 300);
        bool readOnlyFs = GetSafeBool(args, "readOnlyFs", false);

        var egressIps = new List<string>();
        if (args.TryGetProperty("allowedEgressIps", out var ipsProp) && ipsProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in ipsProp.EnumerateArray())
            {
                if (el.GetString() is string ip && !string.IsNullOrWhiteSpace(ip))
                {
                    egressIps.Add(ip);
                }
            }
        }
        var missionId = approvedLease?.MissionId ?? Guid.NewGuid();

        // The network half of the lease is the operator's. allowNetwork and allowedEgressIps used to
        // go into it as sent, loopback filled in and 80 and 443 added for every address, so an agent
        // could author its own egress to any address it named - the same request-as-its-own-
        // authorization the exec allow-list below was pinned to close. A caller may now ask only for
        // part of the operator's policy, and anything else is refused before a lease is requested.
        IReadOnlyList<string> leaseAddresses = Array.Empty<string>();
        IReadOnlyList<uint> leasePorts = Array.Empty<uint>();
        string? egressRefusal = null;
        if (approvedLease is not null)
        {
            leaseAddresses = approvedLease.AllowedEgressIps;
            leasePorts = approvedLease.AllowedEgressPorts;
        }
        else if (allowNetwork)
        {
            var egress = _egressPolicy.Authorize(egressIps);
            egressRefusal = egress.Refusal;
            leaseAddresses = egress.Addresses;
            leasePorts = egress.Ports;
        }
        else if (egressIps.Count > 0)
        {
            // The daemon installs endpoints only when allowNetwork is set, so these used to ride in the
            // lease and be ignored - a request that read back to its caller as accepted.
            egressRefusal = "allowedEgressIps names addresses, but allowNetwork is false. Set allowNetwork to request them.";
        }

        if (egressRefusal is not null)
        {
            string refusedActor = await ResolveActorAsync(ct);
            await AppendScrubbedLogAsync(
                missionId,
                ledgerTool,
                "EGRESS_REQUEST_REFUSED",
                $"Command='{command}' RequestedEgress='{string.Join(",", egressIps)}' | {egressRefusal}",
                refusedActor,
                ct);

            // A refusal is a run with a record, exactly as it is for a mission the engine refuses.
            // The bundle for it says nothing ran and why, which is the answer an auditor asking
            // "what did this agent do at 14:02" needs to be able to get.
            var refusedFacts = NewLeaseFacts(missionId, ledgerTool, refusedActor, startedAtUtc, command, argumentsForLog, workDir, timeoutSec);
            refusedFacts.TemplateSha256 = "none: the call was refused before a lease was authored";
            // The caller named a working directory; nothing was provisioned at it, and the bundle's
            // cleanup group has to say that rather than report on a boundary that never existed.
            refusedFacts.WorkspacePath = null;
            refusedFacts.DeclaredEgress = $"requested {string.Join(",", egressIps)}, refused by the operator's egress policy";
            refusedFacts.Admission = $"Refused: {egressRefusal}";
            refusedFacts.ExecutionState = "Refused";
            refusedFacts.TerminalReason = egressRefusal;
            await SealLeaseFactsAsync(refusedFacts);

            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem>
                {
                    new()
                    {
                        Type = "text",
                        Text = $"[SPLAT POLICY] {toolName} was refused before any lease was requested: {Scrub(egressRefusal)} " +
                               "This is a check in the MCP host, not a kernel denial.\n" +
                               $"[SPLAT RUN RECORD] mission {missionId:D} — export it with the export_run_record tool."
                    }
                }
            };
        }

        var lease = approvedLease ?? new LeaseSpec(
            MissionId: missionId,
            WorkingDirectory: workDir,
            AllowNetwork: allowNetwork,
            AllowedEgressIps: leaseAddresses,
            AllowedEgressPorts: leasePorts,
            ReadOnlyFs: readOnlyFs,
            // Inode NUMBERS are not knowable here - this process runs on Windows and the files
            // live in the guest - so the zeros say so rather than the 1 and 2 that used to sit
            // there looking like identities. The daemon resolves SourcePath in the environment
            // where an inode means something, which is the only place the resolution is valid.
            ProtectedInodes: new List<InodeIdentifierModel>
            {
                new(0, 0, "/etc/shadow"),
                new(0, 0, "/etc/sudoers")
            },
            // The command is the policy for this tool: run_command executes exactly what it was
            // asked to, so that is what the lease permits and nothing else. An empty list here
            // meant the daemon assembled its own, which made the request its own authorization.
            AllowedExecInodes: new List<InodeIdentifierModel> { new(0, 0, command) },
            LeaseDurationSeconds: timeoutSec,
            // The record's own defaults, restated here as literals until 2026-09-23: two copies of
            // one policy on this side of the wire, beside the daemon's ceilings in main.rs and the
            // operator's in policy.json, each of which may only lower what this asks for.
            Limits: new LeaseResourceLimits());

        var violations = new List<LeaseViolationEvent>();
        var violationProgress = new SynchronousProgress<LeaseViolationEvent>(v =>
        {
            lock (violations)
            {
                violations.Add(v);
            }
        });

        var execResult = await _leasedExecutor.ExecuteLeasedAsync(
            lease,
            command,
            argv,
            violations: violationProgress,
            ct: ct);

        string actor = await ResolveActorAsync(ct);
        var facts = NewLeaseFacts(missionId, ledgerTool, actor, startedAtUtc, command, argumentsForLog, workDir, timeoutSec);

        // What the leased process printed is the least trustworthy text this server produces, and it
        // leaves here for another agent's context window. Two things follow from the boundary, and
        // the second is not about the model at all: SPLAT's own lines below it can no longer be
        // FORGED from inside the sandbox. A program that printed "[KERNEL VIOLATION CONTAINMENT
        // REPORT]" on stdout used to land in this same flat block, indistinguishable from the
        // report the daemon's violation events actually produced.
        string commandBoundary = RecalledContext.NewBoundary();
        var sandboxOutput = new StringBuilder();
        if (!string.IsNullOrEmpty(execResult.StandardOutput))
        {
            sandboxOutput.AppendLine(execResult.StandardOutput);
        }
        if (!string.IsNullOrEmpty(execResult.StandardError))
        {
            sandboxOutput.AppendLine(execResult.StandardError);
        }

        var outputSb = new StringBuilder();
        outputSb.AppendLine(RecalledContext.Delimit(
            $"SANDBOXED PROCESS OUTPUT - '{Scrub(command, facts)}'", commandBoundary, Scrub(sandboxOutput.ToString(), facts)));

        if (violations.Count > 0)
        {
            outputSb.AppendLine("\n[KERNEL VIOLATION CONTAINMENT REPORT]");
            foreach (var v in violations)
            {
                outputSb.AppendLine(Scrub($"  -EPERM: Hook={v.Hook} Comm={v.ProcessComm} Detail={v.DetailText} (PID={v.ProcessId})", facts));
            }
        }

        outputSb.AppendLine($"[Process Exited with code {execResult.ExitCode}]");
        if (approvedLease is not null)
            outputSb.AppendLine(JsonSerializer.Serialize(new { agentLease = execResult.Lease }));

        // Record flight recorder log in audit ledger
        await AppendScrubbedLogAsync(
            missionId,
            ledgerTool,
            "EXECUTED_LEASABLE_COMMAND",
            $"Command='{command}' Args='{argumentsForLog}' ExitCode={execResult.ExitCode} Violations={violations.Count}",
            actor,
            ct);

        facts.TemplateSha256 = MissionRunFacts.HashLease(lease);
        facts.DeclaredEgress = allowNetwork
            ? $"{string.Join(",", leaseAddresses)}:{string.Join(",", leasePorts)} (the operator's egress policy, as far as the caller asked for it)"
            : "none: the caller asked for no network";
        facts.NetworkDenialRequested = !allowNetwork;
        facts.RequestedMemoryBytes = (long)Math.Min(lease.Limits.MaxMemoryBytes, (ulong)long.MaxValue);
        facts.RequestedCpuPercent = (int)Math.Min(lease.Limits.MaxCpuPercent, (uint)int.MaxValue);
        facts.ExitCode = execResult.ExitCode;
        facts.TimedOut = execResult.TimedOut;
        facts.TerminalReason = execResult.TerminalReason
            ?? (execResult.TimedOut ? $"killed at the lease's {timeoutSec}s budget" : "the command exited");

        // The contract this tool told its caller it was holding to. isError below is exit 0 and no
        // timeout, so that is what the record has to say the contract was - a record that disagrees
        // with the answer the agent already acted on is worse than no record.
        facts.AllowedExitCodes.Add(0);
        facts.ExitContractMet = execResult.ExitCode == 0 && !execResult.TimedOut;
        facts.ExecutionState = execResult.TimedOut ? "ToolFailed" : (execResult.ExitCode == 0 ? "Completed" : "ToolFailed");

        // Read back from the guest, never repeated from the request, and in the one vocabulary the
        // assembler matches on. A lease the daemon never reported leaves these unset: the bundle
        // then says the controls were not recorded rather than naming controls nobody observed.
        if (LeaseControls.Describe(execResult.Lease, execResult.AppliedControls) is { } applied)
        {
            facts.AppliedControls.AddRange(applied);
        }

        facts.LimitsReadBack = execResult.LimitsReadBack;

        if (execResult.Lease is { } leaseOutcome)
        {
            facts.KernelRefusals = leaseOutcome.ViolationsCounted;
            facts.KernelRefusalsReported = leaseOutcome.ViolationsReported;
            facts.KernelRefusalEvidenceComplete = leaseOutcome.ViolationsComplete;
            facts.GuestSignedOutcome = leaseOutcome.SignedOutcome;
            facts.GuestOutcomeSignature = leaseOutcome.OutcomeSignature;
            facts.GuestOutcomeKeyId = leaseOutcome.OutcomeKeyId;
            facts.GuestOutcomePublicKey = leaseOutcome.OutcomePublicKey;

            // The daemon's word on its own teardown. It creates the workspace only for a lease that
            // asked for an ephemeral one, so a caller's own directory is left alone and the record
            // says nothing was provisioned rather than that nothing was cleaned up.
            facts.WorkspacePath = leaseOutcome.Workspace ?? workDir;
            // Only a directory the daemon made is a directory the daemon can say it removed. For one
            // the caller owns this stays null, and the bundle says the disposition is not recorded
            // rather than reporting on a cleanup nobody performed.
            facts.JailRemoved = leaseOutcome.WorkspaceCreated ? leaseOutcome.WorkspaceRemoved : null;
            facts.JobName = leaseOutcome.CgroupPath ?? (leaseOutcome.Installed ? leaseOutcome.CgroupId.ToString() : null);
            // The daemon's EXIT frame count, not a measurement from here: nothing on this side can
            // see into the guest's cgroup. Null when the lease ended without one.
            facts.ProcessesLeftAtTeardown = execResult.FinalMetrics.ActiveProcessCount;
        }

        await SealLeaseFactsAsync(facts);

        // Outside the delimited block, so it is SPLAT's line and not the sandbox's. An agent that
        // gets this can ask for the bundle; without it the evidence exists and nothing points at it.
        outputSb.AppendLine($"[SPLAT RUN RECORD] mission {missionId:D} — export it with the export_run_record tool.");

        return new McpToolCallResult
        {
            IsError = execResult.ExitCode != 0 || execResult.TimedOut,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = outputSb.ToString() }
            }
        };
    }

    /// <summary>
    /// The fields every lease-tool call has before anything runs. The rest is filled in where the
    /// handler observes it, never reconstructed afterwards - the same discipline the mission engine
    /// keeps, because the same assembler reads both.
    /// </summary>
    private static MissionRunFacts NewLeaseFacts(
        Guid missionId,
        string ledgerTool,
        string actor,
        DateTimeOffset startedAtUtc,
        string command,
        string argumentsForLog,
        string workDir,
        uint timeoutSec) => new()
        {
            MissionId = missionId,
            TemplateId = ledgerTool,
            Principal = actor,
            StartedAtUtc = startedAtUtc,
            ExecutablePath = command,
            CommandLine = argumentsForLog,
            WorkspacePath = workDir,
            TimeoutSeconds = (int)timeoutSec,
            // The guest's kernel, not this process's: the host is Windows and the tool is not on it.
            // The lease's own frames name the cgroup and the controls; the release string is not
            // among them, so nothing here claims to know it.
            Substrate = LinuxLeaseSubstrate.SubstrateName,
            OsDescription = "not recorded: the tool ran in the WSL2 guest, whose release the lease frames do not carry",
            // Nothing in a lease tool's request asks for a privilege drop. The daemon runs the
            // workload as a non-root uid regardless, and that lands in AppliedControls as the
            // workload:uid= line the daemon actually reported.
            PrivilegeDropRequested = false,
        };

    /// <summary>
    /// Seals what a lease tool did as the call's MISSION_RUN_FACTS row - the same row, the same
    /// schema and the same reader as a mission the engine ran.
    ///
    /// Until this existed run_command left two lines of prose in the ledger and no record could be
    /// assembled for it at all: the one tool an external agent actually calls was the one path with
    /// no evidence, while the product's claim is that the evidence is the point. Written with
    /// CancellationToken.None for the reason the engine does it: a call cancelled mid-flight is
    /// exactly the one whose record matters.
    /// </summary>
    private async Task SealLeaseFactsAsync(MissionRunFacts facts)
    {
        facts.EndedAtUtc ??= DateTimeOffset.UtcNow;
        ScrubLeaseFacts(facts);
        try
        {
            await _auditLedger.AppendLogAsync(
                facts.MissionId,
                facts.TemplateId,
                MissionRunFacts.LedgerAction,
                JsonSerializer.Serialize(facts),
                facts.Principal,
                CancellationToken.None);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A ledger that refuses this row refused the call's other rows too, so there is no
            // record this could still complete - and failing the tool call here would turn a
            // storage fault into a sandbox escape report.
        }
    }

    private string Scrub(string text, MissionRunFacts? facts = null)
    {
        try
        {
            // The opaque map contains the original credentials and must never reach evidence.
            var credentials = _credentialSanitizer.Sanitize(text);
            var dlp = _dlpSanitizer.Sanitize(credentials.SanitizedText);
            if (facts is not null)
            {
                facts.RedactionCount += credentials.RedactedCount + dlp.RedactedCount;
                if (credentials.RedactedCount > 0 && !facts.RedactedCategories.Contains("Credential"))
                    facts.RedactedCategories.Add("Credential");
                foreach (string category in dlp.RedactedCategories)
                {
                    if (!facts.RedactedCategories.Contains(category)) facts.RedactedCategories.Add(category);
                }
            }
            return dlp.SanitizedContent;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // A failed scanner must withhold the text, including any exception that echoes it.
            if (facts is not null)
            {
                facts.RedactionCount++;
                if (!facts.RedactedCategories.Contains("SanitizationFailure"))
                    facts.RedactedCategories.Add("SanitizationFailure");
            }
            return "[REDACTED_SANITIZATION_FAILURE]";
        }
    }

    private Task AppendScrubbedLogAsync(
        Guid missionId, string templateId, string action, string details, string actor, CancellationToken ct) =>
        _auditLedger.AppendLogAsync(missionId, Scrub(templateId), action, Scrub(details), actor, ct);

    private void ScrubLeaseFacts(MissionRunFacts facts)
    {
        // Scrub values before JSON escaping and before the ledger hashes them. Filtering serialized
        // JSON can miss escaped credentials or break the schema; filtering exports breaks proofs.
        // The resolved principal is attribution, not caller text: masking email-shaped identities
        // would collapse distinct authenticated operators into the same ledger actor.
        facts.ExecutablePath = Scrub(facts.ExecutablePath, facts);
        if (facts.CommandLine is not null) facts.CommandLine = Scrub(facts.CommandLine, facts);
        if (facts.WorkspacePath is not null) facts.WorkspacePath = Scrub(facts.WorkspacePath, facts);
        facts.DeclaredEgress = Scrub(facts.DeclaredEgress, facts);
        facts.Admission = Scrub(facts.Admission, facts);
        if (facts.TerminalReason is not null) facts.TerminalReason = Scrub(facts.TerminalReason, facts);
        if (facts.JobName is not null) facts.JobName = Scrub(facts.JobName, facts);
        for (int i = 0; i < facts.AppliedControls.Count; i++)
            facts.AppliedControls[i] = Scrub(facts.AppliedControls[i], facts);

        // The guest receipt can repeat a workspace path. A sensitive receipt is withheld in full:
        // changing its signed bytes would manufacture a signature failure in an otherwise valid run.
        bool withholdReceipt = false;
        foreach (string? signedField in new[] { facts.GuestSignedOutcome, facts.GuestOutcomeSignature, facts.GuestOutcomeKeyId, facts.GuestOutcomePublicKey })
        {
            if (signedField is not null && Scrub(signedField, facts) != signedField) withholdReceipt = true;
        }
        if (withholdReceipt)
        {
            facts.GuestSignedOutcome = null;
            facts.GuestOutcomeSignature = null;
            facts.GuestOutcomeKeyId = null;
            facts.GuestOutcomePublicKey = null;
            facts.RedactedCategories.Add("GuestOutcomeWithheld");
        }
    }

    private async Task<McpToolCallResult> ExecuteRunCodeAsync(JsonElement args, CancellationToken ct)
    {
        string language = args.TryGetProperty("language", out var langProp) ? langProp.GetString() ?? "bash" : "bash";
        string code = args.TryGetProperty("code", out var codeProp) ? codeProp.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(code))
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem>
                {
                    new() { Type = "text", Text = "Error: 'code' parameter is required and cannot be empty." }
                }
            };
        }

        // Pre-Flight AST & Static Analysis Security Check
        var astResult = DynamicCodeAstValidator.Validate(code, language);
        if (!astResult.IsSafe)
        {
            var blockedMission = Guid.NewGuid();
            string blockedActor = await ResolveActorAsync(ct);
            string rejection = astResult.RejectionReason ?? "Forbidden script primitive detected";
            await AppendScrubbedLogAsync(
                blockedMission,
                "mcp-tool-run_code",
                "DYNAMIC_CODE_AST_BLOCKED",
                rejection,
                blockedActor,
                ct);

            // Sealed like any other refusal: the record is what proves the block happened, and a
            // block with no record is indistinguishable afterwards from a call nobody made.
            var blockedFacts = NewLeaseFacts(
                blockedMission, "mcp-tool-run_code", blockedActor, DateTimeOffset.UtcNow,
                $"{language} (script)", string.Empty, "none: nothing was provisioned", 0);
            blockedFacts.WorkspacePath = null;
            blockedFacts.TemplateSha256 = "none: the script was refused before a lease was authored";
            blockedFacts.DeclaredEgress = "none: nothing ran";
            blockedFacts.Admission = $"Refused: {rejection}";
            blockedFacts.ExecutionState = "Refused";
            blockedFacts.TerminalReason = rejection;
            await SealLeaseFactsAsync(blockedFacts);

            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem>
                {
                    new() { Type = "text", Text = $"[PRE-FLIGHT AST SECURITY REJECTION] {Scrub(rejection)}" }
                }
            };
        }

        string workDir = args.TryGetProperty("workingDirectory", out var wdProp) ? wdProp.GetString() ?? "/tmp" : "/tmp";
        bool allowNetwork = GetSafeBool(args, "allowNetwork", false);
        uint timeoutSec = (uint)GetSafeInt(args, "timeoutSeconds", 30, 5, 300);

        string runner;

        // No quoting. The code is ONE argument, and it travels as one element of an argv array -
        // so there is no string for anything downstream to re-split, and no escaping to get wrong.
        // The previous version single-quoted it and the guest then split the result on whitespace,
        // which handed python `'print(123)'`: a string literal that evaluates, prints nothing and
        // exits 0. `print(1, 2)` arrived as `'print(1,` and died on an unterminated string.
        switch (language.ToLowerInvariant())
        {
            case "python":
            case "python3":
            case "py":
                runner = "/usr/bin/python3";
                break;

            case "sh":
                runner = "/bin/sh";
                break;

            case "bash":
            default:
                runner = "/bin/bash";
                break;
        }

        var wrappedArgs = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new
        {
            command = runner,
            args = new[] { "-c", code },
            workingDirectory = workDir,
            allowNetwork = allowNetwork,
            timeoutSeconds = timeoutSec
        }));

        return await ExecuteRunCommandAsync(wrappedArgs, ct, "run_code");
    }

    private async Task<McpToolCallResult> ExecuteFsReadAsync(JsonElement args, CancellationToken ct)
    {
        string path = args.TryGetProperty("path", out var pProp) ? pProp.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(path))
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Error: Path cannot be empty." } }
            };
        }

        // The handle IS the authorisation. Reading by path afterwards would ask the filesystem a
        // second, different question - which is the window a link swap lives in.
        using var handle = _workspace.OpenForRead(path, out string? resolvedPath);
        if (handle is null)
        {
            await AppendScrubbedLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_read",
                "REFUSED_FILE_READ_OUT_OF_WORKSPACE",
                $"Refused read on out-of-workspace path '{path}'",
                await ResolveActorAsync(ct),
                ct);

            return OutOfWorkspace("fs_read", path);
        }

        try
        {
            string content;
            await using (var stream = new FileStream(handle, FileAccess.Read))
            using (var reader = new StreamReader(stream))
            {
                content = await reader.ReadToEndAsync(ct);
            }

            await AppendScrubbedLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_read",
                "AUDITED_FILE_READ",
                $"Read {content.Length} bytes from '{resolvedPath}'",
                await ResolveActorAsync(ct),
                ct);

            // Deliberately NOT delimited, unlike run_command's output. fs_read's contract is the
            // bytes: an agent round-trips a file through fs_write and fs_read to edit it, and a
            // wrapper turns the file it writes back into the file plus a banner. The planted-text
            // risk is real but it belongs to whoever put the file in the workspace, and paying for
            // it by corrupting every read is the wrong trade at this layer.
            return new McpToolCallResult
            {
                IsError = false,
                Content = new List<McpContentItem> { new() { Type = "text", Text = content } }
            };
        }
        catch (Exception ex)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = $"Error reading file: {ex.Message}" } }
            };
        }
    }

    private async Task<McpToolCallResult> ExecuteFsWriteAsync(JsonElement args, CancellationToken ct)
    {
        string path = args.TryGetProperty("path", out var pProp) ? pProp.GetString() ?? "" : "";
        string content = args.TryGetProperty("content", out var cProp) ? cProp.GetString() ?? "" : "";

        if (string.IsNullOrWhiteSpace(path))
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Error: Path cannot be empty." } }
            };
        }

        // The guard creates the parent, verifies IT really lands inside, refuses an existing leaf
        // that is itself a link, and hands back a handle whose final path it has checked. Creating
        // directories from a merely-lexical path was the previous version's own escape hatch: a
        // junction anywhere along the way and Directory.CreateDirectory happily follows it.
        using var handle = _workspace.OpenForWrite(path, out string? resolvedPath);
        if (handle is null)
        {
            await AppendScrubbedLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_write",
                "REFUSED_FILE_WRITE_OUT_OF_WORKSPACE",
                $"Refused write on out-of-workspace path '{path}'",
                await ResolveActorAsync(ct),
                ct);

            return OutOfWorkspace("fs_write", path);
        }

        try
        {
            await using (var stream = new FileStream(handle, FileAccess.Write))
            using (var writer = new StreamWriter(stream))
            {
                await writer.WriteAsync(content.AsMemory(), ct);
            }
            await AppendScrubbedLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_write",
                "AUDITED_FILE_WRITE",
                $"Wrote {content.Length} bytes to '{resolvedPath}'",
                await ResolveActorAsync(ct),
                ct);

            return new McpToolCallResult
            {
                IsError = false,
                Content = new List<McpContentItem> { new() { Type = "text", Text = $"Successfully wrote {content.Length} bytes to {resolvedPath}" } }
            };
        }
        catch (Exception ex)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = $"Error writing file: {ex.Message}" } }
            };
        }
    }

    private async Task<McpToolCallResult> ExecuteGetSubstrateHealthAsync(CancellationToken ct)
    {
        var health = await _healthChecker.CheckHealthAsync(ct);
        var json = JsonSerializer.Serialize(health, new JsonSerializerOptions { WriteIndented = true });

        // A daemon that answers but enforces nothing is not a healthy substrate. Reporting only on
        // reachability let an agent client read "online and operational" off a process whose BPF
        // hooks were never loaded, which is exactly the state the daemon now refuses to start in.
        return new McpToolCallResult
        {
            IsError = !health.DaemonReachable || !health.Enforcing,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = json }
            }
        };
    }

    private async Task<McpToolCallResult> ExecuteListTemplatesAsync(JsonElement args, CancellationToken ct)
    {
        if (_templateRegistry == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Template registry not configured in MCP host." } }
            };
        }

        string? categoryFilter = args.TryGetProperty("category", out var catProp) ? catProp.GetString() : null;
        var all = await _templateRegistry.GetAllTemplatesAsync(ct);

        var filtered = all
            .Where(t => string.IsNullOrWhiteSpace(categoryFilter) ||
                        string.Equals(t.Category, categoryFilter, StringComparison.OrdinalIgnoreCase))
            .Select(t => new
            {
                t.TemplateId,
                t.Name,
                t.Category,
                t.Description,
                t.TargetModel,
                Tool = new
                {
                    t.Tool.Name,
                    t.Tool.ExecutablePath,
                    t.Tool.TimeoutSeconds,
                    MaxMemoryMb = t.Tool.MaxMemoryBytes / (1024 * 1024),
                    t.Tool.MaxCpuPercent
                }
            });

        return new McpToolCallResult
        {
            IsError = false,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = JsonSerializer.Serialize(filtered, new JsonSerializerOptions { WriteIndented = true }) }
            }
        };
    }

    private async Task<McpToolCallResult> ExecuteDiagnoseSystemAsync(JsonElement args, CancellationToken ct)
    {
        if (_missionEngine == null || _templateRegistry == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Mission execution engine or template registry not configured." } }
            };
        }

        string templateId = args.TryGetProperty("templateId", out var tProp) ? tProp.GetString() ?? "" : "";
        string userInstruction = args.TryGetProperty("userInstruction", out var uProp) ? uProp.GetString() ?? "" : "";

        var template = await _templateRegistry.GetTemplateByIdAsync(templateId, ct);
        if (template == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = $"Template '{templateId}' not found in catalog." } }
            };
        }

        var parameters = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(userInstruction))
        {
            parameters["UserInstruction"] = userInstruction;
        }

        if (args.TryGetProperty("parameters", out var pObj) && pObj.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in pObj.EnumerateObject())
            {
                if (prop.Value.GetString() is string val)
                {
                    parameters[prop.Name] = val;
                }
            }
        }

        var output = new StringBuilder();
        await foreach (var chunk in _missionEngine.ExecuteMissionAsync(template, parameters, await ResolveActorAsync(ct), ct))
        {
            switch (chunk.ChunkType)
            {
                case MissionChunkType.StatusChange:
                    output.AppendLine($"[STATUS] {chunk.Content}");
                    break;
                case MissionChunkType.Stdout:
                    output.AppendLine(chunk.Content);
                    break;
                case MissionChunkType.Stderr:
                    output.AppendLine($"[STDERR] {chunk.Content}");
                    break;
                case MissionChunkType.AiToken:
                    output.Append(chunk.Content);
                    break;
                case MissionChunkType.Completed:
                    output.AppendLine($"\n[COMPLETED] {chunk.Content}");
                    break;
            }
        }

        return new McpToolCallResult
        {
            IsError = false,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = output.ToString() }
            }
        };
    }

    private async Task<McpToolCallResult> ExecuteInvestigateSystemAsync(JsonElement args, CancellationToken ct)
    {
        if (_investigationLoop == null || _templateRegistry == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Investigation loop or template registry not configured." } }
            };
        }

        string startingId = args.TryGetProperty("startingTemplateId", out var sProp) ? sProp.GetString() ?? "" : "";
        string goal = args.TryGetProperty("investigationGoal", out var gProp) ? gProp.GetString() ?? "" : "";
        int maxSteps = GetSafeInt(args, "maxSteps", 3, 1, 5);

        var startingTemplate = await _templateRegistry.GetTemplateByIdAsync(startingId, ct);
        if (startingTemplate == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = $"Starting template '{startingId}' not found in catalog." } }
            };
        }

        var parameters = new Dictionary<string, string>();
        if (!string.IsNullOrWhiteSpace(goal))
        {
            parameters["UserInstruction"] = goal;
        }

        var liveChunks = new StringBuilder();
        var progress = new SynchronousProgress<MissionChunk>(chunk =>
        {
            lock (liveChunks)
            {
                if (chunk.ChunkType == MissionChunkType.StatusChange)
                {
                    liveChunks.AppendLine($"[STATUS] {chunk.Content}");
                }
            }
        });

        var result = await _investigationLoop.InvestigateAsync(
            startingTemplate,
            parameters,
            await ResolveActorAsync(ct),
            maxSteps,
            progress,
            ct);

        var reportSb = new StringBuilder();
        reportSb.AppendLine($"=== SPLAT INVESTIGATION REPORT: {result.OverallStatus} ===");
        reportSb.AppendLine($"Stop Reason: {result.StopReason} ({result.StopExplanation})\n");

        foreach (var step in result.Steps)
        {
            reportSb.AppendLine($"--- Step {step.StepNumber}: {step.TemplateName} ---");
            reportSb.AppendLine($"Selection Reason: {step.SelectionReason}");
            reportSb.AppendLine($"Status: {step.Verdict.OverallStatus} — {step.Verdict.StatusHeadline}");
            foreach (var f in step.Verdict.KeyFindings)
            {
                reportSb.AppendLine($"  * Finding: {f}");
            }
            if (step.Verdict.RecommendedActions != null)
            {
                foreach (var r in step.Verdict.RecommendedActions)
                {
                    reportSb.AppendLine($"  > Recommended Resolution: {r}");
                }
            }
            reportSb.AppendLine();
        }

        return new McpToolCallResult
        {
            IsError = result.OverallStatus == DiagnosticHealthStatus.Critical,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = reportSb.ToString() }
            }
        };
    }

    /// <summary>
    /// Exports the bundle for a mission that has ended. Everything in it comes from the ledger: the
    /// facts the engine sealed when the mission ended, and the mission's own rows. A mission with no
    /// facts row is refused rather than described from its remaining rows.
    /// </summary>
    private async Task<McpToolCallResult> ExecuteExportRunRecordAsync(JsonElement args, CancellationToken ct)
    {
        if (_runRecords == null)
        {
            return Refusal("Run record export is not configured on this server.");
        }

        string missionText = args.TryGetProperty("missionId", out var idProp) ? idProp.GetString() ?? string.Empty : string.Empty;
        if (!Guid.TryParse(missionText, out var missionId))
        {
            return Refusal($"'{missionText}' is not a mission id.");
        }

        string outputDirectory = args.TryGetProperty("outputDirectory", out var dirProp) ? dirProp.GetString() ?? string.Empty : string.Empty;

        string bundlePath;
        MissionRunRecord record;
        try
        {
            bundlePath = await _runRecords.AssembleAndExportBundleAsync(missionId, outputDirectory, ct);
            record = await _runRecords.AssembleRunRecordAsync(missionId, ct);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return Refusal(ex.Message);
        }

        var summary = new
        {
            bundle = bundlePath,
            missionId = record.MissionId,
            state = record.Outcome.ExecutionState,
            admission = record.EnforcementState.AdmissionVerdict,
            policy = record.RequestIdentity.PolicyVersionOrHash,
            entries = record.Integrity.TotalAuditEntries,
            chain = record.Integrity.ChainKind,
            merkleRoot = record.Integrity.MerkleRootHash,
            verifyWith = "python verify_proofs.py, or powershell -ExecutionPolicy Bypass -File .\\verify_proofs.ps1, from inside the bundle"
        };

        return new McpToolCallResult
        {
            IsError = false,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }) }
            }
        };
    }

    /// <summary>
    /// Holds a bundle up against this host's ledger and reports what agrees and what does not.
    ///
    /// The result is deliberately a list of named checks rather than a verdict line. A bundle that
    /// fails because the host's own chain is broken and one that fails because six of the mission's
    /// rows were left out are different problems for whoever is reading, and collapsing them into
    /// "invalid" loses the only part an auditor can act on.
    /// </summary>
    private async Task<McpToolCallResult> ExecuteVerifyRunRecordAsync(JsonElement args, CancellationToken ct)
    {
        if (_recordVerifier == null)
        {
            return Refusal("Run record verification is not configured on this server.");
        }

        string bundlePath = args.TryGetProperty("bundlePath", out var pathProp) ? pathProp.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(bundlePath))
        {
            return Refusal("'bundlePath' is required: the path to the RUN-RECORD-*.zip to check.");
        }

        LedgerAgreementResult result;
        try
        {
            result = await _recordVerifier.VerifyAsync(bundlePath, ct);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Refusal($"'{bundlePath}' could not be read: {ex.Message}");
        }

        await AppendScrubbedLogAsync(
            result.MissionId ?? Guid.Empty,
            "mcp-tool-verify_run_record",
            result.Agrees ? "RUN_RECORD_AGREES_WITH_LEDGER" : "RUN_RECORD_DISAGREES_WITH_LEDGER",
            $"Bundle='{bundlePath}' | {result.Verdict}",
            await ResolveActorAsync(ct),
            ct);

        var summary = new
        {
            bundle = result.BundlePath,
            missionId = result.MissionId,
            agrees = result.Agrees,
            verdict = result.Verdict,
            checks = result.Checks.Select(c => new
            {
                check = c.Name,
                result = c.Passed switch { true => "pass", false => "FAIL", null => "not checked" },
                detail = c.Detail
            })
        };

        return new McpToolCallResult
        {
            // A disagreement is an answer, not a tool malfunction - but it is the answer a caller must
            // not skim past, and isError is the only signal an MCP client reliably surfaces.
            IsError = !result.Agrees,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }) }
            }
        };
    }

    private static McpToolCallResult Refusal(string message) => new()
    {
        IsError = true,
        Content = new List<McpContentItem> { new() { Type = "text", Text = message } }
    };

    private async Task<McpToolCallResult> ExecuteSearchIncidentMemoryAsync(JsonElement args, CancellationToken ct)
    {
        if (_semanticMemory == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Semantic memory index not configured." } }
            };
        }

        string query = args.TryGetProperty("query", out var qProp) ? qProp.GetString() ?? "" : "";
        int topK = GetSafeInt(args, "topK", 5, 1, 20);

        var results = await _semanticMemory.SearchSimilarMissionsAsync(query, topK, 0.1, ct);

        var json = JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true });
        return new McpToolCallResult
        {
            IsError = false,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = json }
            }
        };
    }

    private async Task<McpToolCallResult> ExecuteRunAgentBrainAsync(JsonElement args, CancellationToken ct)
    {
        if (_agentBrain == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Agent Brain engine not configured." } }
            };
        }

        string userGoal = args.TryGetProperty("userGoal", out var gProp) ? gProp.GetString() ?? "" : "";
        if (string.IsNullOrWhiteSpace(userGoal))
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Parameter 'userGoal' is required." } }
            };
        }

        int maxSteps = GetSafeInt(args, "maxReasoningSteps", 3, 1, 5);

        var liveChunks = new StringBuilder();
        var progress = new SynchronousProgress<MissionChunk>(chunk =>
        {
            lock (liveChunks)
            {
                if (chunk.ChunkType == MissionChunkType.StatusChange || chunk.ChunkType == MissionChunkType.Completed)
                {
                    liveChunks.AppendLine($"[STATUS] {chunk.Content}");
                }
            }
        });

        var result = await _agentBrain.ProcessGoalAsync(
            userGoal: userGoal,
            operatorIdentity: await ResolveActorAsync(ct),
            maxReasoningSteps: maxSteps,
            progress: progress,
            cancellationToken: ct);

        var reportSb = new StringBuilder();
        reportSb.AppendLine($"=== SPLAT AUTONOMOUS AGENT BRAIN REPORT: {result.OverallStatus} ===");
        reportSb.AppendLine($"Headline: {result.ExecutiveHeadline}");
        reportSb.AppendLine($"Root Cause Analysis:\n{result.RootCauseAnalysis}\n");

        if (result.GroundedKeyFindings.Count > 0)
        {
            reportSb.AppendLine("Grounded Telemetry Findings:");
            foreach (var f in result.GroundedKeyFindings)
            {
                reportSb.AppendLine($"  * {f}");
            }
            reportSb.AppendLine();
        }

        if (result.EvaluatedHypotheses.Count > 0)
        {
            reportSb.AppendLine("Evaluated Hypotheses:");
            foreach (var h in result.EvaluatedHypotheses)
            {
                reportSb.AppendLine($"  [{h.Status}] {h.Statement} (Evidence: {h.GroundedEvidence ?? "None"})");
            }
            reportSb.AppendLine();
        }

        if (result.ExecutedSteps.Count > 0)
        {
            reportSb.AppendLine("Executed Investigation Steps:");
            foreach (var s in result.ExecutedSteps)
            {
                reportSb.AppendLine($"  Step {s.StepNumber}: {s.TemplateName} ({s.TemplateId}) -> {s.Verdict.OverallStatus}: {s.Verdict.StatusHeadline}");
            }
            reportSb.AppendLine();
        }

        if (result.AvailableRemediations.Count > 0)
        {
            reportSb.AppendLine("Recommended Self-Healing Remediations:");
            foreach (var r in result.AvailableRemediations)
            {
                reportSb.AppendLine($"  ⚡ {r.Title} ({r.ActionId}) - Risk: {r.RiskLevel}");
            }
            reportSb.AppendLine();
        }

        if (!string.IsNullOrWhiteSpace(result.AuditLedgerEntryHash))
        {
            reportSb.AppendLine($"Merkle Audit Chain Commitment: {result.AuditLedgerEntryHash}");
        }

        return new McpToolCallResult
        {
            IsError = result.OverallStatus == DiagnosticHealthStatus.Critical,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = reportSb.ToString() }
            }
        };
    }

    private async Task<McpToolCallResult> ExecuteListGovernedCrewsAsync(CancellationToken ct)
    {
        var allCrews = _crewRegistry != null
            ? await _crewRegistry.GetAllCrewsAsync(ct)
            : GovernedCrewCatalog.All;

        var crews = allCrews.Select(c => new
        {
            crewId = c.CrewId,
            name = c.Name,
            description = c.Description,
            processType = c.ProcessType.ToString(),
            agentCount = c.Agents.Count,
            taskCount = c.Tasks.Count,
            managerAgent = c.ManagerAgent?.Role
        }).ToList();

        var json = JsonSerializer.Serialize(crews, new JsonSerializerOptions { WriteIndented = true });
        return new McpToolCallResult
        {
            IsError = false,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = json }
            }
        };
    }

    private async Task<McpToolCallResult> ExecuteRunGovernedCrewAsync(JsonElement args, CancellationToken ct)
    {
        if (_crewEngine == null)
        {
            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem> { new() { Type = "text", Text = "Governed Crew engine not configured." } }
            };
        }

        GovernedCrewDefinition? crew = null;

        // 1. Check for dynamic inline crew definition (JSON object or JSON string)
        if (args.TryGetProperty("crewDefinition", out var defProp))
        {
            try
            {
                string rawJson = defProp.ValueKind == JsonValueKind.String
                    ? defProp.GetString() ?? ""
                    : defProp.GetRawText();

                crew = GovernedCrewParser.ParseJson(rawJson);
            }
            catch (Exception parseEx)
            {
                return new McpToolCallResult
                {
                    IsError = true,
                    Content = new List<McpContentItem> { new() { Type = "text", Text = $"Invalid crewDefinition JSON: {parseEx.Message}" } }
                };
            }
        }
        else
        {
            // 2. Look up by crewId in registry / catalog
            string crewId = args.TryGetProperty("crewId", out var cProp) ? cProp.GetString() ?? "" : "";
            if (string.IsNullOrWhiteSpace(crewId))
            {
                return new McpToolCallResult
                {
                    IsError = true,
                    Content = new List<McpContentItem> { new() { Type = "text", Text = "Either 'crewId' or 'crewDefinition' parameter is required." } }
                };
            }

            if (_crewRegistry != null)
            {
                crew = await _crewRegistry.GetCrewByIdAsync(crewId, ct);
            }
            crew ??= GovernedCrewCatalog.All.FirstOrDefault(c => string.Equals(c.CrewId, crewId, StringComparison.OrdinalIgnoreCase));

            if (crew == null)
            {
                return new McpToolCallResult
                {
                    IsError = true,
                    Content = new List<McpContentItem> { new() { Type = "text", Text = $"Crew '{crewId}' not found in registry or catalog." } }
                };
            }
        }

        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (args.TryGetProperty("parameters", out var paramsElem) && paramsElem.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in paramsElem.EnumerateObject())
            {
                parameters[prop.Name] = prop.Value.ToString();
            }
        }

        var liveChunks = new StringBuilder();
        var progress = new SynchronousProgress<MissionChunk>(chunk =>
        {
            lock (liveChunks)
            {
                if (chunk.ChunkType is MissionChunkType.StatusChange or MissionChunkType.Completed or MissionChunkType.Stderr)
                {
                    liveChunks.AppendLine($"[{chunk.ChunkType}] {chunk.Content}");
                }
            }
        });

        var actor = await ResolveActorAsync(ct);
        var result = await _crewEngine.RunCrewAsync(crew, parameters, actor, progress, ct);

        var reportSb = new StringBuilder();
        reportSb.AppendLine($"=== GOVERNED CREW EXECUTION REPORT: {result.OverallStatus} ===");
        reportSb.AppendLine($"Crew: {crew.Name} ({crew.CrewId})");
        reportSb.AppendLine($"Process: {crew.ProcessType} | Duration: {result.TotalDurationMs}ms | Cycle Detected: {result.CycleDetected}");
        reportSb.AppendLine();
        reportSb.AppendLine("Execution Trace:");
        reportSb.AppendLine(liveChunks.ToString());
        reportSb.AppendLine();
        reportSb.AppendLine("Executive Synthesis:");
        reportSb.AppendLine(result.ExecutiveSummary);

        return new McpToolCallResult
        {
            IsError = result.OverallStatus == DiagnosticHealthStatus.Critical,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = reportSb.ToString() }
            }
        };
    }

    /// <summary>
    /// Cross-cutting interop seam: correlates an external orchestrator's trace id with the ledger
    /// and stamps every tool result with the ledger's current chain-head hash.
    ///
    /// The anchor rides as a SECOND content item so the primary text payload existing clients parse
    /// stays byte-identical. Each ledger entry's hash covers its predecessor, so the chain head
    /// commits - transitively - to every entry this call produced: an external checkpointer that
    /// embeds the anchor makes its checkpoint cryptographically inseparable from the kernel-side
    /// record of what actually executed. When a trace id is supplied, the correlation row is written
    /// AFTER the tool ran so the row (and the anchor that commits to it) records the outcome, not
    /// just the intent.
    /// </summary>
    private async Task<McpToolCallResult> AttachAuditAnchorAsync(
        string toolName,
        JsonElement args,
        McpToolCallResult toolResult,
        CancellationToken ct)
    {
        string? traceId = ReadOptionalString(args, "traceId");
        string? clientName = ReadOptionalString(args, "clientName");
        if (traceId is not null) traceId = Scrub(traceId);
        if (clientName is not null) clientName = Scrub(clientName);

        try
        {
            if (!string.IsNullOrWhiteSpace(traceId))
            {
                await AppendScrubbedLogAsync(
                    Guid.NewGuid(),
                    $"mcp-tool-{toolName}",
                    "EXTERNAL_TRACE_CORRELATED",
                    $"Tool='{toolName}' TraceId='{traceId}' Client='{clientName ?? "unspecified"}' IsError={toolResult.IsError}",
                    await ResolveActorAsync(ct),
                    ct);
            }

            // Max-Id rather than first-row: the SQLite ledger returns newest-first, but the
            // interface does not promise an ordering and test fakes routinely append-order theirs.
            var recent = await _auditLedger.GetAuditLogsAsync(null, 1, ct);
            AuditLogEntry? head = null;
            foreach (var entry in recent)
            {
                if (head == null || entry.Id > head.Id)
                {
                    head = entry;
                }
            }

            if (head != null)
            {
                var anchorJson = JsonSerializer.Serialize(new
                {
                    auditAnchor = new
                    {
                        anchorHash = head.EntryHash,
                        anchorEntryId = head.Id,
                        traceId,
                        tool = toolName,
                        timestampUtc = head.TimestampUtc
                    }
                });

                toolResult.Content.Add(new McpContentItem { Type = "text", Text = anchorJson });
            }
        }
        catch (Exception ex)
        {
            // The tool already executed; a failed anchor must degrade the metadata, never the call.
            // Saying so beats silence - a checkpointer expecting an anchor can see why it is absent.
            toolResult.Content.Add(new McpContentItem
            {
                Type = "text",
                Text = $"{{\"auditAnchor\":null,\"anchorError\":{JsonSerializer.Serialize(Scrub(ex.Message))}}}"
            });
        }

        return toolResult;
    }

    private static string? ReadOptionalString(JsonElement args, string propertyName) =>
        args.ValueKind == JsonValueKind.Object &&
        args.TryGetProperty(propertyName, out var prop) &&
        prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;

    private static McpJsonRpcMessage CreateErrorResponse(JsonElement? id, int code, string message)
    {
        return new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = id,
            Error = new McpError
            {
                Code = code,
                Message = message
            }
        };
    }

    private sealed class SynchronousProgress<T> : IProgress<T>
    {
        private readonly Action<T> _handler;
        public SynchronousProgress(Action<T> handler) => _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        public void Report(T value) => _handler(value);
    }
}
