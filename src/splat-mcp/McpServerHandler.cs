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
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;

namespace SplatMcp;

public class McpServerHandler
{
    private readonly ILeasedExecutor _leasedExecutor;
    private readonly ITemplatePolicyCompiler _policyCompiler;
    private readonly IAuditLedger _auditLedger;
    private readonly WslSubstrateHealthChecker _healthChecker;
    private readonly IMissionExecutionEngine? _missionEngine;
    private readonly IGovernedInvestigationLoop? _investigationLoop;
    private readonly ITemplateRegistry? _templateRegistry;
    private readonly ISemanticMemoryIndex? _semanticMemory;
    private readonly IModelStreamClient? _modelClient;
    private readonly IAgentBrain? _agentBrain;
    private readonly IGovernedCrewEngine? _crewEngine;
    private readonly IGovernedCrewRegistry? _crewRegistry;
    private readonly IOperatorIdentityProvider _identityProvider;

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
    private readonly string _workspaceRoot;

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
        string? workspaceRoot = null)
    {
        _leasedExecutor = leasedExecutor ?? throw new ArgumentNullException(nameof(leasedExecutor));
        _policyCompiler = policyCompiler ?? throw new ArgumentNullException(nameof(policyCompiler));
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
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
        _workspaceRoot = Path.GetFullPath(workspaceRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SPLAT",
            "mcp-workspace"));
        Directory.CreateDirectory(_workspaceRoot);
    }

    /// <summary>
    /// Resolves a caller-supplied path against the workspace root, or returns null if it escapes.
    ///
    /// Containment is decided on the CANONICAL path from Path.GetFullPath, never on the raw string:
    /// a prefix test against unresolved input is defeated by <c>..</c> segments, by a path that is
    /// merely a string prefix of the root (<c>…\mcp-workspace-evil</c>), and by the several spellings
    /// Windows accepts for the same file. Relative paths are treated as workspace-relative, which is
    /// the shape an agent naturally sends.
    /// </summary>
    private string? ResolveWithinWorkspace(string requestedPath)
    {
        string candidate;
        try
        {
            candidate = Path.GetFullPath(Path.IsPathRooted(requestedPath)
                ? requestedPath
                : Path.Combine(_workspaceRoot, requestedPath));
        }
        catch (Exception)
        {
            // Malformed input (invalid characters, over-long, bad device name) is out of bounds by
            // definition - there is no path here to authorise.
            return null;
        }

        // The trailing separator makes this a true containment test rather than a prefix test.
        string rootWithSeparator = _workspaceRoot.EndsWith(Path.DirectorySeparatorChar)
            ? _workspaceRoot
            : _workspaceRoot + Path.DirectorySeparatorChar;

        return candidate.StartsWith(rootWithSeparator, StringComparison.OrdinalIgnoreCase)
            ? candidate
            : null;
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
            return CreateErrorResponse(request.Id, -32603, $"Internal server error: {ex.Message}");
        }
    }

    private McpJsonRpcMessage HandleInitialize(McpJsonRpcMessage request)
    {
        var result = new McpInitializeResult();
        return new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = request.Id,
            Result = JsonSerializer.SerializeToElement(result)
        };
    }

    private Task<McpJsonRpcMessage> HandleToolsListAsync(McpJsonRpcMessage request, CancellationToken ct)
    {
        var tools = new List<McpToolDefinition>
        {
            new()
            {
                Name = "run_command",
                Description = "Execute a command inside an in-kernel BPF-LSM capability lease with hardware isolation, memory/CPU clamps, and egress filtering.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""command"": { ""type"": ""string"", ""description"": ""The executable to run (e.g. /bin/bash, /usr/bin/python3, /bin/ls)"" },
                        ""arguments"": { ""type"": ""string"", ""description"": ""Command arguments"" },
                        ""workingDirectory"": { ""type"": ""string"", ""description"": ""Working directory inside sandbox"", ""default"": ""/tmp"" },
                        ""allowNetwork"": { ""type"": ""boolean"", ""description"": ""Whether network egress is permitted"", ""default"": false },
                        ""allowedEgressIps"": { ""type"": ""array"", ""items"": { ""type"": ""string"" }, ""description"": ""Allow-listed egress IPv4 addresses (e.g. 127.0.0.1)"" },
                        ""timeoutSeconds"": { ""type"": ""integer"", ""description"": ""Lease lifespan in seconds (5-300)"", ""default"": 30 },
                        ""readOnlyFs"": { ""type"": ""boolean"", ""description"": ""Mount root as read-only"", ""default"": false },
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
                        ""allowNetwork"": { ""type"": ""boolean"", ""description"": ""Allow network egress"", ""default"": false },
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
        await ResolveActorAsync(ct);

        McpToolCallResult toolResult;

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

    private async Task<McpToolCallResult> ExecuteRunCommandAsync(JsonElement args, CancellationToken ct)
    {
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

        string arguments = args.TryGetProperty("arguments", out var argProp) ? argProp.GetString() ?? "" : "";
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
        if (allowNetwork && egressIps.Count == 0)
        {
            egressIps.Add("127.0.0.1");
        }

        var missionId = Guid.NewGuid();
        var lease = new LeaseSpec(
            MissionId: missionId,
            WorkingDirectory: workDir,
            AllowNetwork: allowNetwork,
            AllowedEgressIps: egressIps,
            AllowedEgressPorts: new List<uint> { 80, 443 },
            ReadOnlyFs: readOnlyFs,
            ProtectedInodes: new List<InodeIdentifierModel>
            {
                new(1, 0, "/etc/shadow"),
                new(2, 0, "/etc/sudoers")
            },
            AllowedExecInodes: new List<InodeIdentifierModel>(),
            LeaseDurationSeconds: timeoutSec,
            Limits: new LeaseResourceLimits(
                MaxMemoryBytes: 256 * 1024 * 1024,
                MaxCpuPercent: 50,
                MaxPids: 100));

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
            arguments,
            violations: violationProgress,
            ct: ct);

        var outputSb = new StringBuilder();
        if (!string.IsNullOrEmpty(execResult.StandardOutput))
        {
            outputSb.AppendLine(execResult.StandardOutput);
        }
        if (!string.IsNullOrEmpty(execResult.StandardError))
        {
            outputSb.AppendLine(execResult.StandardError);
        }

        if (violations.Count > 0)
        {
            outputSb.AppendLine("\n[KERNEL VIOLATION CONTAINMENT REPORT]");
            foreach (var v in violations)
            {
                outputSb.AppendLine($"  -EPERM: Hook={v.Hook} Comm={v.ProcessComm} Detail={v.DetailText} (PID={v.ProcessId})");
            }
        }

        outputSb.AppendLine($"[Process Exited with code {execResult.ExitCode}]");

        // Record flight recorder log in audit ledger
        await _auditLedger.AppendLogAsync(
            missionId,
            "mcp-tool-run_command",
            "EXECUTED_LEASABLE_COMMAND",
            $"Command='{command}' Args='{arguments}' ExitCode={execResult.ExitCode} Violations={violations.Count}",
            await ResolveActorAsync(ct),
            ct);

        return new McpToolCallResult
        {
            IsError = execResult.ExitCode != 0 || execResult.TimedOut,
            Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = outputSb.ToString() }
            }
        };
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
            await _auditLedger.AppendLogAsync(
                Guid.NewGuid(),
                "mcp-tool-run_code",
                "DYNAMIC_CODE_AST_BLOCKED",
                astResult.RejectionReason ?? "Forbidden script primitive detected",
                await ResolveActorAsync(ct),
                ct);

            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem>
                {
                    new() { Type = "text", Text = $"[PRE-FLIGHT AST SECURITY REJECTION] {astResult.RejectionReason}" }
                }
            };
        }

        string workDir = args.TryGetProperty("workingDirectory", out var wdProp) ? wdProp.GetString() ?? "/tmp" : "/tmp";
        bool allowNetwork = GetSafeBool(args, "allowNetwork", false);
        uint timeoutSec = (uint)GetSafeInt(args, "timeoutSeconds", 30, 5, 300);

        string runner;
        string runnerArgs;

        // POSIX single-quote escaping: replace ' with '\'' and enclose within single quotes
        string escapedCode = code.Replace("'", "'\\''");

        switch (language.ToLowerInvariant())
        {
            case "python":
            case "python3":
            case "py":
                runner = "/usr/bin/python3";
                runnerArgs = $"-c '{escapedCode}'";
                break;

            case "sh":
                runner = "/bin/sh";
                runnerArgs = $"-c '{escapedCode}'";
                break;

            case "bash":
            default:
                runner = "/bin/bash";
                runnerArgs = $"-c '{escapedCode}'";
                break;
        }

        var wrappedArgs = JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new
        {
            command = runner,
            arguments = runnerArgs,
            workingDirectory = workDir,
            allowNetwork = allowNetwork,
            timeoutSeconds = timeoutSec
        }));

        return await ExecuteRunCommandAsync(wrappedArgs, ct);
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

        string? resolvedPath = ResolveWithinWorkspace(path);
        if (resolvedPath is null)
        {
            await _auditLedger.AppendLogAsync(
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
            if (!File.Exists(resolvedPath))
            {
                return new McpToolCallResult
                {
                    IsError = true,
                    Content = new List<McpContentItem> { new() { Type = "text", Text = $"File not found in workspace: {resolvedPath}" } }
                };
            }

            string content = await File.ReadAllTextAsync(resolvedPath, ct);
            await _auditLedger.AppendLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_read",
                "AUDITED_FILE_READ",
                $"Read {content.Length} bytes from '{resolvedPath}'",
                await ResolveActorAsync(ct),
                ct);

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

        string? resolvedPath = ResolveWithinWorkspace(path);
        if (resolvedPath is null)
        {
            await _auditLedger.AppendLogAsync(
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
            // Safe to create unconditionally: resolvedPath is already proven to sit under the
            // workspace root, so this can only ever materialise directories inside it.
            string? dir = Path.GetDirectoryName(resolvedPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await File.WriteAllTextAsync(resolvedPath, content, ct);
            await _auditLedger.AppendLogAsync(
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

        try
        {
            if (!string.IsNullOrWhiteSpace(traceId))
            {
                await _auditLedger.AppendLogAsync(
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
                Text = $"{{\"auditAnchor\":null,\"anchorError\":{JsonSerializer.Serialize(ex.Message)}}}"
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
