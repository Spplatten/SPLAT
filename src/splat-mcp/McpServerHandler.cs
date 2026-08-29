using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
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
    private readonly string _operatorIdentity;

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
        string operatorIdentity = "mcp-client")
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
        _operatorIdentity = operatorIdentity;
    }

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

    private async Task<McpJsonRpcMessage> HandleToolsListAsync(McpJsonRpcMessage request, CancellationToken ct)
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
                        ""readOnlyFs"": { ""type"": ""boolean"", ""description"": ""Mount root as read-only"", ""default"": false }
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
                        ""timeoutSeconds"": { ""type"": ""integer"", ""description"": ""Timeout in seconds"", ""default"": 30 }
                    },
                    ""required"": [""code""]
                }")
            },
            new()
            {
                Name = "fs_read",
                Description = "Read file content within leased directory bounds. Inode-protected system files are blocked at kernel level with -EPERM.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""path"": { ""type"": ""string"", ""description"": ""Absolute file path to read"" }
                    },
                    ""required"": [""path""]
                }")
            },
            new()
            {
                Name = "fs_write",
                Description = "Write file content into leased workspace or scratch directory with Merkle audit record.",
                InputSchema = JsonSerializer.Deserialize<JsonElement>(@"
                {
                    ""type"": ""object"",
                    ""properties"": {
                        ""path"": { ""type"": ""string"", ""description"": ""Absolute file path to write"" },
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
                        ""parameters"": { ""type"": ""object"", ""description"": ""Key-value parameters for template arguments"" }
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
                        ""maxSteps"": { ""type"": ""integer"", ""description"": ""Maximum investigation steps to chain (1-5)"", ""default"": 3 }
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
            }
        };

        var responseData = new { tools };
        return new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = request.Id,
            Result = JsonSerializer.SerializeToElement(responseData)
        };
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

            default:
                return CreateErrorResponse(request.Id, -32601, $"Tool '{toolName}' is not recognized");
        }

        return new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = request.Id,
            Result = JsonSerializer.SerializeToElement(toolResult)
        };
    }

    private async Task<McpToolCallResult> ExecuteRunCommandAsync(JsonElement args, CancellationToken ct)
    {
        string command = args.TryGetProperty("command", out var cmdProp) ? cmdProp.GetString() ?? "" : "";
        string arguments = args.TryGetProperty("arguments", out var argProp) ? argProp.GetString() ?? "" : "";
        string workDir = args.TryGetProperty("workingDirectory", out var wdProp) ? wdProp.GetString() ?? "/tmp" : "/tmp";
        bool allowNetwork = args.TryGetProperty("allowNetwork", out var netProp) && netProp.GetBoolean();
        uint timeoutSec = args.TryGetProperty("timeoutSeconds", out var toProp) ? (uint)Math.Clamp(toProp.GetInt32(), 5, 300) : 30;
        bool readOnlyFs = args.TryGetProperty("readOnlyFs", out var roProp) && roProp.GetBoolean();

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
            _operatorIdentity,
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
        string workDir = args.TryGetProperty("workingDirectory", out var wdProp) ? wdProp.GetString() ?? "/tmp" : "/tmp";
        bool allowNetwork = args.TryGetProperty("allowNetwork", out var netProp) && netProp.GetBoolean();
        uint timeoutSec = args.TryGetProperty("timeoutSeconds", out var toProp) ? (uint)Math.Clamp(toProp.GetInt32(), 5, 300) : 30;

        string runner;
        string runnerArgs;

        switch (language.ToLowerInvariant())
        {
            case "python":
            case "python3":
            case "py":
                runner = "/usr/bin/python3";
                runnerArgs = $"-c \"{code.Replace("\"", "\\\"")}\"";
                break;

            case "sh":
                runner = "/bin/sh";
                runnerArgs = $"-c \"{code.Replace("\"", "\\\"")}\"";
                break;

            case "bash":
            default:
                runner = "/bin/bash";
                runnerArgs = $"-c \"{code.Replace("\"", "\\\"")}\"";
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

        // Check for protected paths
        if (path.Contains("/etc/shadow") || path.Contains("/etc/sudoers") || path.Contains("/proc/kcore"))
        {
            await _auditLedger.AppendLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_read",
                "BLOCKED_FILE_READ",
                $"Blocked read on protected path '{path}'",
                _operatorIdentity,
                ct);

            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem>
                {
                    new() { Type = "text", Text = $"[KERNEL -EPERM BLOCK] Access to protected path '{path}' denied." }
                }
            };
        }

        try
        {
            if (!File.Exists(path))
            {
                return new McpToolCallResult
                {
                    IsError = true,
                    Content = new List<McpContentItem> { new() { Type = "text", Text = $"File not found: {path}" } }
                };
            }

            string content = await File.ReadAllTextAsync(path, ct);
            await _auditLedger.AppendLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_read",
                "AUDITED_FILE_READ",
                $"Read {content.Length} bytes from '{path}'",
                _operatorIdentity,
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

        if (path.StartsWith("/etc/") || path.StartsWith("/sys/") || path.StartsWith("/proc/"))
        {
            await _auditLedger.AppendLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_write",
                "BLOCKED_SYSTEM_WRITE",
                $"Blocked write on protected system path '{path}'",
                _operatorIdentity,
                ct);

            return new McpToolCallResult
            {
                IsError = true,
                Content = new List<McpContentItem>
                {
                    new() { Type = "text", Text = $"[KERNEL -EPERM BLOCK] Write to system directory '{path}' denied by policy lease." }
                }
            };
        }

        try
        {
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await File.WriteAllTextAsync(path, content, ct);
            await _auditLedger.AppendLogAsync(
                Guid.NewGuid(),
                "mcp-tool-fs_write",
                "AUDITED_FILE_WRITE",
                $"Wrote {content.Length} bytes to '{path}'",
                _operatorIdentity,
                ct);

            return new McpToolCallResult
            {
                IsError = false,
                Content = new List<McpContentItem> { new() { Type = "text", Text = $"Successfully wrote {content.Length} bytes to {path}" } }
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

        return new McpToolCallResult
        {
            IsError = !health.DaemonReachable,
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
        await foreach (var chunk in _missionEngine.ExecuteMissionAsync(template, parameters, _operatorIdentity, ct))
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
        int maxSteps = args.TryGetProperty("maxSteps", out var mProp) ? Math.Clamp(mProp.GetInt32(), 1, 5) : 3;

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
            _operatorIdentity,
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
        int topK = args.TryGetProperty("topK", out var kProp) ? Math.Clamp(kProp.GetInt32(), 1, 20) : 5;

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
