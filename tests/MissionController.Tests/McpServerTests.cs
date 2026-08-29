using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

public class McpServerTests
{
    private class MockLeasedExecutor : ILeasedExecutor
    {
        public LeaseSpec? LastLease { get; private set; }
        public string? LastCommand { get; private set; }
        public string? LastArguments { get; private set; }
        public bool SimulateViolation { get; set; }

        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease,
            string command,
            string arguments,
            IProgress<string>? stdout = null,
            IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default)
        {
            LastLease = lease;
            LastCommand = command;
            LastArguments = arguments;

            if (SimulateViolation)
            {
                var vEvent = new LeaseViolationEvent(
                    CgroupId: 42,
                    ProcessId: 1337,
                    Hook: KernelViolationHook.Open,
                    Detail: 12345,
                    DetailText: "Blocked attempt to open protected inode",
                    ProcessComm: "cat",
                    TimestampUtc: DateTime.UtcNow);

                violations?.Report(vEvent);
                stderr?.Report("[KERNEL -EPERM BLOCK] cat pid 1337 open denied (inode 12345)\n");
            }

            stdout?.Report("Mock execution successful\n");

            var result = new ProcessExecutionResult(
                ExitCode: SimulateViolation ? 1 : 0,
                StandardOutput: "Mock execution successful\n",
                StandardError: SimulateViolation ? "[KERNEL -EPERM BLOCK] cat pid 1337 open denied\n" : "",
                TimedOut: false,
                FinalMetrics: new JobResourceMetrics(1024 * 1024, 0, 50, 50, 1));

            return Task.FromResult(result);
        }
    }

    private class MockAuditLedger : IAuditLedger
    {
        public List<(Guid missionId, string templateId, string action, string details)> Logs { get; } = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            Logs.Add((missionId, templateId, action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AuditLogEntry>>(new List<AuditLogEntry>());
        }

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(true);
        }
    }

    private class MockMissionEngine : IMissionExecutionEngine
    {
        public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var missionId = Guid.NewGuid();
            yield return new MissionChunk(missionId, MissionChunkType.StatusChange, "Running diagnostic...", DateTime.UtcNow);
            yield return new MissionChunk(missionId, MissionChunkType.Stdout, "Adapter Name: Ethernet0\nStatus: Up\nDNS: 1.1.1.1", DateTime.UtcNow);
            yield return new MissionChunk(missionId, MissionChunkType.AiToken, "{\n  \"overallStatus\": \"Healthy\",\n  \"statusHeadline\": \"Network adapter operating normally\",\n  \"keyFindings\": [\"DNS responsive\"],\n  \"recommendedActions\": [\"None required\"]\n}", DateTime.UtcNow);
            yield return new MissionChunk(missionId, MissionChunkType.Completed, "Mission Complete", DateTime.UtcNow);
        }
    }

    private class MockInvestigationLoop : IGovernedInvestigationLoop
    {
        public Task<InvestigationResult> InvestigateAsync(
            SingleToolTemplate startingTemplate,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            int maxSteps = 3,
            IProgress<MissionChunk>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var invId = Guid.NewGuid();
            var verdict = new ExecutiveDiagnosisResult(
                OverallStatus: DiagnosticHealthStatus.Healthy,
                StatusHeadline: "Network healthy",
                KeyFindings: new[] { "All gateways reachable" },
                RecommendedActions: new[] { "No remediation needed" });

            var step = new InvestigationStep(1, startingTemplate.TemplateId, startingTemplate.Name, "Starting probe", verdict);
            var result = new InvestigationResult(invId, new[] { step }, DiagnosticHealthStatus.Healthy, InvestigationStopReason.SystemHealthy, "Healthy");
            return Task.FromResult(result);
        }
    }

    private class MockTemplateRegistry : ITemplateRegistry
    {
        private readonly List<SingleToolTemplate> _templates = new();

        public MockTemplateRegistry(IEnumerable<SingleToolTemplate>? initial = null)
        {
            if (initial != null) _templates.AddRange(initial);
        }

        public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<SingleToolTemplate>>(_templates);
        }

        public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default)
        {
            var t = _templates.Find(x => string.Equals(x.TemplateId, templateId, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(t);
        }

        public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default)
        {
            _templates.Add(template);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task Initialize_ReturnsProtocolVersionAndCapabilities()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "initialize",
            Params = JsonSerializer.SerializeToElement(new { protocolVersion = "2024-11-05" })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.Equal("2.0", response.JsonRpc);
        Assert.NotNull(response.Result);

        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.Equal("2024-11-05", doc.RootElement.GetProperty("protocolVersion").GetString());
        Assert.Equal("splat-mcp", doc.RootElement.GetProperty("serverInfo").GetProperty("name").GetString());
    }

    [Fact]
    public async Task ToolsList_ReturnsAllDefinedToolsIncludingBrain()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(2),
            Method = "tools/list"
        };

        var response = await handler.ProcessMessageAsync(request);
        Assert.NotNull(response.Result);

        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        var tools = doc.RootElement.GetProperty("tools");

        var toolNames = new HashSet<string>();
        foreach (var t in tools.EnumerateArray())
        {
            toolNames.Add(t.GetProperty("name").GetString()!);
        }

        Assert.Contains("run_command", toolNames);
        Assert.Contains("run_code", toolNames);
        Assert.Contains("fs_read", toolNames);
        Assert.Contains("fs_write", toolNames);
        Assert.Contains("get_substrate_health", toolNames);
        Assert.Contains("list_diagnostic_templates", toolNames);
        Assert.Contains("diagnose_system", toolNames);
        Assert.Contains("investigate_system", toolNames);
        Assert.Contains("search_incident_memory", toolNames);
    }

    [Fact]
    public async Task RunCommand_ExecutesSandboxedAndRecordsAuditLog()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(3),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_command",
                arguments = new
                {
                    command = "/bin/uname",
                    arguments = "-r",
                    workingDirectory = "/workspace",
                    allowNetwork = true,
                    allowedEgressIps = new[] { "127.0.0.1", "192.168.1.1" },
                    timeoutSeconds = 45
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.False(doc.RootElement.GetProperty("isError").GetBoolean());

        Assert.NotNull(executor.LastLease);
        Assert.Equal("/bin/uname", executor.LastCommand);
        Assert.Equal("-r", executor.LastArguments);
        Assert.Equal("/workspace", executor.LastLease.WorkingDirectory);
        Assert.True(executor.LastLease.AllowNetwork);
        Assert.Contains("127.0.0.1", executor.LastLease.AllowedEgressIps);
        Assert.Contains("192.168.1.1", executor.LastLease.AllowedEgressIps);
        Assert.Equal(45u, executor.LastLease.LeaseDurationSeconds);

        Assert.Single(ledger.Logs);
        Assert.Equal("mcp-tool-run_command", ledger.Logs[0].templateId);
        Assert.Equal("EXECUTED_LEASABLE_COMMAND", ledger.Logs[0].action);
    }

    [Fact]
    public async Task RunCommand_SurfacesKernelViolationsInBand()
    {
        var executor = new MockLeasedExecutor { SimulateViolation = true };
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(4),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_command",
                arguments = new
                {
                    command = "/bin/cat",
                    arguments = "/etc/shadow"
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("[KERNEL VIOLATION CONTAINMENT REPORT]", outputText);
        Assert.Contains("-EPERM", outputText);
    }

    [Fact]
    public async Task FsRead_BlocksProtectedInodesWithEperm()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(5),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "fs_read",
                arguments = new
                {
                    path = "/etc/shadow"
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("[KERNEL -EPERM BLOCK]", outputText);

        Assert.Single(ledger.Logs);
        Assert.Equal("BLOCKED_FILE_READ", ledger.Logs[0].action);
    }

    [Fact]
    public async Task FsWrite_BlocksProtectedSystemPaths()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(6),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "fs_write",
                arguments = new
                {
                    path = "/etc/malicious.conf",
                    content = "evil_config=true"
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("[KERNEL -EPERM BLOCK]", outputText);

        Assert.Single(ledger.Logs);
        Assert.Equal("BLOCKED_SYSTEM_WRITE", ledger.Logs[0].action);
    }

    [Fact]
    public async Task DiagnoseSystem_ExecutesMissionThroughEngine()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var sampleTemplate = GovernedTemplateCatalog.All[0];
        var registry = new MockTemplateRegistry(new[] { sampleTemplate });
        var engine = new MockMissionEngine();

        var handler = new McpServerHandler(
            executor,
            compiler,
            ledger,
            missionEngine: engine,
            templateRegistry: registry);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(7),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "diagnose_system",
                arguments = new
                {
                    templateId = sampleTemplate.TemplateId,
                    userInstruction = "Check network connectivity"
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.False(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("Running diagnostic...", outputText);
        Assert.Contains("Ethernet0", outputText);
        Assert.Contains("Network adapter operating normally", outputText);
    }

    [Fact]
    public async Task InvestigateSystem_ExecutesAutonomousCognitiveLoop()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var sampleTemplate = GovernedTemplateCatalog.All[0];
        var registry = new MockTemplateRegistry(new[] { sampleTemplate });
        var loop = new MockInvestigationLoop();

        var handler = new McpServerHandler(
            executor,
            compiler,
            ledger,
            investigationLoop: loop,
            templateRegistry: registry);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(8),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "investigate_system",
                arguments = new
                {
                    startingTemplateId = sampleTemplate.TemplateId,
                    investigationGoal = "Investigate slow DNS lookup",
                    maxSteps = 3
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.False(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("SPLAT INVESTIGATION REPORT", outputText);
        Assert.Contains("All gateways reachable", outputText);
    }
}
