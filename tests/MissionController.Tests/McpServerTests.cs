using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Brain;
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
        public IReadOnlyList<string>? LastArgv { get; private set; }
        public bool SimulateViolation { get; set; }

        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease,
            string command,
            IReadOnlyList<string> argv,
            IProgress<string>? stdout = null,
            IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default)
        {
            LastLease = lease;
            LastCommand = command;
            LastArgv = argv;
            LastArguments = string.Join(" ", argv);

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
            // Mock yields synchronously; the await satisfies the async-iterator contract without CS1998.
            await Task.CompletedTask;
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
        Assert.Contains("run_agent_brain", toolNames);
        Assert.Contains("list_governed_crews", toolNames);
        Assert.Contains("run_governed_crew", toolNames);
    }

    [Fact]
    public async Task RunCommand_ExecutesSandboxedAndRecordsAuditLog()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        // Both addresses are inside the operator's policy, so the request is granted as sent.
        var handler = new McpServerHandler(executor, compiler, ledger,
            egressPolicy: McpEgressPolicy.Parse("127.0.0.1:443, 192.168.1.1:443"));

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
        // Only the port the operator approved for both addresses - not the 80 and 443 once added to every lease.
        Assert.Equal(new uint[] { 443 }, executor.LastLease.AllowedEgressPorts);
        Assert.Equal(45u, executor.LastLease.LeaseDurationSeconds);

        // Two rows: the flight-recorder line, then the facts the run record is assembled from.
        Assert.Equal(2, ledger.Logs.Count);
        Assert.Equal("mcp-tool-run_command", ledger.Logs[0].templateId);
        Assert.Equal("EXECUTED_LEASABLE_COMMAND", ledger.Logs[0].action);
        Assert.Equal(MissionRunFacts.LedgerAction, ledger.Logs[1].action);
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

    /// <summary>
    /// Creates a handler whose fs_* tools are rooted in a throwaway workspace, so a test can prove
    /// containment against a real directory instead of the caller's LocalAppData.
    /// </summary>
    private static (McpServerHandler Handler, MockAuditLedger Ledger, string Root) CreateFsHandler()
    {
        string root = Path.Combine(Path.GetTempPath(), "splat-fs-tests", Guid.NewGuid().ToString("N"));
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(
            new MockLeasedExecutor(),
            new TemplatePolicyCompiler(),
            ledger,
            workspaceRoot: root);
        return (handler, ledger, root);
    }

    private static McpJsonRpcMessage FsCall(int id, string tool, object arguments) => new()
    {
        JsonRpc = "2.0",
        Id = JsonSerializer.SerializeToElement(id),
        Method = "tools/call",
        Params = JsonSerializer.SerializeToElement(new { name = tool, arguments })
    };

    /// <summary>
    /// These previously asserted the literal string "[KERNEL -EPERM BLOCK]" against a
    /// <c>string.Contains("/etc/shadow")</c> check, which pinned the defect in place: the tools read
    /// and wrote anywhere on the Windows host, and the only thing under test was that they said
    /// otherwise. What is asserted now is the property that actually matters - a path outside the
    /// workspace is refused - plus the negative assertion that the refusal does not claim kernel
    /// enforcement it never performed.
    /// </summary>
    [Theory]
    [InlineData("/etc/shadow")]
    [InlineData(@"C:\Windows\System32\drivers\etc\hosts")]
    [InlineData("../../../../Windows/System32/config/SAM")]
    [InlineData(@"..\..\escape.txt")]
    public async Task FsRead_RefusesPathsOutsideTheWorkspace(string path)
    {
        var (handler, ledger, _) = CreateFsHandler();

        var response = await handler.ProcessMessageAsync(FsCall(5, "fs_read", new { path }));

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("[SPLAT POLICY]", outputText);
        // The refusal must not dress a user-space check up as kernel enforcement. It may still say
        // the words "not a kernel denial" - disclaiming the mechanism is the point.
        Assert.DoesNotContain("[KERNEL -EPERM BLOCK]", outputText);
        Assert.DoesNotContain("-EPERM", outputText);

        Assert.Single(ledger.Logs);
        Assert.Equal("REFUSED_FILE_READ_OUT_OF_WORKSPACE", ledger.Logs[0].action);
    }

    [Theory]
    [InlineData("/etc/malicious.conf")]
    [InlineData(@"C:\Windows\System32\evil.dll")]
    [InlineData("../../../escaped.conf")]
    public async Task FsWrite_RefusesPathsOutsideTheWorkspace(string path)
    {
        var (handler, ledger, root) = CreateFsHandler();

        var response = await handler.ProcessMessageAsync(
            FsCall(6, "fs_write", new { path, content = "evil_config=true" }));

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("[SPLAT POLICY]", outputText);
        // The refusal must not dress a user-space check up as kernel enforcement. It may still say
        // the words "not a kernel denial" - disclaiming the mechanism is the point.
        Assert.DoesNotContain("[KERNEL -EPERM BLOCK]", outputText);
        Assert.DoesNotContain("-EPERM", outputText);

        Assert.Single(ledger.Logs);
        Assert.Equal("REFUSED_FILE_WRITE_OUT_OF_WORKSPACE", ledger.Logs[0].action);

        // The refusal must be a refusal, not a message: nothing may have reached the disk.
        Assert.Empty(Directory.GetFiles(root, "*", SearchOption.AllDirectories));
    }

    /// <summary>
    /// The containment must not have been bought by breaking the tools. A relative path stays inside
    /// the workspace and round-trips, which is the legitimate use these tools exist for.
    /// </summary>
    [Fact]
    public async Task FsWriteThenRead_RoundTripsInsideTheWorkspace()
    {
        var (handler, ledger, root) = CreateFsHandler();

        var writeResponse = await handler.ProcessMessageAsync(
            FsCall(7, "fs_write", new { path = "notes/finding.txt", content = "sandbox holds" }));

        var writeDoc = JsonDocument.Parse(writeResponse.Result!.Value.GetRawText());
        Assert.False(writeDoc.RootElement.GetProperty("isError").GetBoolean());
        Assert.True(File.Exists(Path.Combine(root, "notes", "finding.txt")));

        var readResponse = await handler.ProcessMessageAsync(
            FsCall(8, "fs_read", new { path = "notes/finding.txt" }));

        var readDoc = JsonDocument.Parse(readResponse.Result!.Value.GetRawText());
        Assert.False(readDoc.RootElement.GetProperty("isError").GetBoolean());
        Assert.Equal(
            "sandbox holds",
            readDoc.RootElement.GetProperty("content")[0].GetProperty("text").GetString());

        Assert.Equal(new[] { "AUDITED_FILE_WRITE", "AUDITED_FILE_READ" }, ledger.Logs.Select(l => l.action));
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

    private class MockAgentBrain : IAgentBrain
    {
        public Task<GoalDecompositionResult> DecomposeGoalAsync(
            string userGoal,
            CancellationToken cancellationToken = default)
        {
            var result = new GoalDecompositionResult(
                UserGoal: userGoal,
                SubGoals: new[] { "Check DNS" },
                RecommendedTemplateIds: new[] { "net-dns-audit" },
                ConfidenceScore: 0.95,
                ReasoningRationale: "DNS test");
            return Task.FromResult(result);
        }

        public Task<BrainExecutionResult> ProcessGoalAsync(
            string userGoal,
            string operatorIdentity,
            int maxReasoningSteps = 3,
            IProgress<MissionChunk>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var result = new BrainExecutionResult(
                SessionId: Guid.NewGuid(),
                UserGoal: userGoal,
                OverallStatus: DiagnosticHealthStatus.Healthy,
                ExecutiveHeadline: "Autonomous Brain: All Systems Healthy",
                RootCauseAnalysis: "No network or security anomalies detected during cognitive decomposition.",
                GroundedKeyFindings: new[] { "🟢 Latency under 15ms", "🟢 DNS resolved 0.0.0.0 correctly" },
                EvaluatedHypotheses: new[]
                {
                    new BrainHypothesis("HYP-1", "Hypothesis 1: DNS degraded", "net-dns-audit", HypothesisStatus.Refuted, "DNS responded in 4ms", 0.9),
                    new BrainHypothesis("HYP-2", "Hypothesis 2: Packet loss", "net-dns-audit", HypothesisStatus.Refuted, "0% packet loss observed", 0.9)
                },
                ExecutedSteps: new[]
                {
                    new InvestigationStep(1, "net-dns-audit", "Network Diagnostics", "Initial", new ExecutiveDiagnosisResult(
                        DiagnosticHealthStatus.Healthy, "DNS operational", new[] { "All healthy" }, Array.Empty<string>()))
                },
                AvailableRemediations: new[]
                {
                    new RemediationAction("flush-dns", "net-dns-audit", "Flush DNS Cache", "Flushes the local resolver cache", RemediationRiskLevel.Safe, false, "ipconfig.exe", "/flushdns")
                },
                AuditLedgerEntryHash: "sha256:abc123merkleproof",
                TimestampUtc: DateTime.UtcNow);

            return Task.FromResult(result);
        }
    }

    [Fact]
    public async Task RunAgentBrain_ExecutesGoalThroughAgentBrainEngine()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var brain = new MockAgentBrain();

        var handler = new McpServerHandler(
            executor,
            compiler,
            ledger,
            agentBrain: brain);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(9),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_agent_brain",
                arguments = new
                {
                    userGoal = "Diagnose slow network requests",
                    maxReasoningSteps = 3
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);

        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.False(doc.RootElement.GetProperty("isError").GetBoolean());

        string outputText = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("SPLAT AUTONOMOUS AGENT BRAIN REPORT", outputText);
        Assert.Contains("Autonomous Brain: All Systems Healthy", outputText);
        Assert.Contains("Flush DNS Cache", outputText);
        Assert.Contains("sha256:abc123merkleproof", outputText);
    }

    [Fact]
    public async Task RunCommand_RejectsEmptyCommand()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(10),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_command",
                arguments = new
                {
                    command = "   "
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);
        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());
        string text = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("command", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("cannot be empty", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RunCode_SendsTheCodeAsOneUnmodifiedArgument()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(11),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_code",
                arguments = new
                {
                    language = "bash",
                    code = "echo 'hello world' && echo \"nested quotes\""
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);
        Assert.NotNull(response.Result);
        Assert.NotNull(executor.LastArgv);

        // This used to assert POSIX single-quote escaping, because the code was spliced into a
        // command STRING that the guest daemon then split on whitespace. Both halves of that are
        // gone: the code is one element of an argv array, so there is nothing to escape for and
        // nothing downstream to re-split. Escaping correctly for a split that should not happen
        // is a smaller bug than the split.
        Assert.Equal(2, executor.LastArgv!.Count);
        Assert.Equal("-c", executor.LastArgv[0]);
        Assert.Equal("echo 'hello world' && echo \"nested quotes\"", executor.LastArgv[1]);
    }

    [Fact]
    public async Task RunCode_RejectsEmptyCode()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger);

        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(12),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_code",
                arguments = new
                {
                    language = "bash",
                    code = ""
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);
        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());
        string text = doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString()!;
        Assert.Contains("code", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ToolsCall_ToleratesStringAndNumberTypeRepresentations()
    {
        var executor = new MockLeasedExecutor();
        var compiler = new TemplatePolicyCompiler();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, compiler, ledger,
            egressPolicy: McpEgressPolicy.Parse("127.0.0.1:443"));

        // Send timeoutSeconds as string "45" and allowNetwork as string "true"
        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(13),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_command",
                arguments = new
                {
                    command = "/bin/ls",
                    timeoutSeconds = "45",
                    allowNetwork = "true"
                }
            })
        };

        var response = await handler.ProcessMessageAsync(request);
        Assert.NotNull(response.Result);
        Assert.NotNull(executor.LastLease);
        Assert.Equal(45u, executor.LastLease.LeaseDurationSeconds);
        Assert.True(executor.LastLease.AllowNetwork);
    }

    /// <summary>
    /// The network half of a run_command lease used to be whatever the caller sent: allowNetwork and
    /// allowedEgressIps went into the lease as they came, with 80 and 443 added for every address.
    /// This and the three tests after it fail against the parent commit, where each request reached
    /// the executor.
    /// </summary>
    [Fact]
    public async Task RunCommand_RefusesNetwork_WhenTheHostHasNoEgressPolicy()
    {
        var executor = new MockLeasedExecutor();
        var ledger = new MockAuditLedger();
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), ledger);

        var response = await handler.ProcessMessageAsync(FsCall(20, "run_command", new
        {
            command = "/usr/bin/curl",
            args = new[] { "http://203.0.113.7/" },
            allowNetwork = true,
            allowedEgressIps = new[] { "203.0.113.7" }
        }));

        var doc = JsonDocument.Parse(response.Result!.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());
        Assert.Contains("[SPLAT POLICY]", doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString());
        Assert.Null(executor.LastLease);
        Assert.Contains(ledger.Logs, log => log.action == "EGRESS_REQUEST_REFUSED");
    }

    [Fact]
    public async Task RunCommand_RefusesAnAddressTheEgressPolicyDoesNotName()
    {
        var executor = new MockLeasedExecutor();
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), new MockAuditLedger(),
            egressPolicy: McpEgressPolicy.Parse("127.0.0.1:443"));

        var response = await handler.ProcessMessageAsync(FsCall(21, "run_command", new
        {
            command = "/usr/bin/curl",
            allowNetwork = true,
            allowedEgressIps = new[] { "127.0.0.1", "203.0.113.7" }
        }));

        var doc = JsonDocument.Parse(response.Result!.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());
        Assert.Contains("203.0.113.7", doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString());
        Assert.Null(executor.LastLease);
    }

    [Fact]
    public async Task RunCommand_RefusesAddressesSentWithoutAllowNetwork()
    {
        // The daemon installs endpoints only when allowNetwork is set, so these addresses used to ride
        // in the lease and be ignored - a request that read back to its caller as accepted.
        var executor = new MockLeasedExecutor();
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), new MockAuditLedger(),
            egressPolicy: McpEgressPolicy.Parse("203.0.113.7:443"));

        var response = await handler.ProcessMessageAsync(FsCall(22, "run_command", new
        {
            command = "/usr/bin/curl",
            allowedEgressIps = new[] { "203.0.113.7" }
        }));

        var doc = JsonDocument.Parse(response.Result!.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());
        Assert.Null(executor.LastLease);
    }

    [Fact]
    public async Task RunCode_IsHeldToTheSameEgressPolicy()
    {
        var executor = new MockLeasedExecutor();
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), new MockAuditLedger());

        var response = await handler.ProcessMessageAsync(FsCall(23, "run_code", new
        {
            language = "sh",
            code = "echo hello",
            allowNetwork = true
        }));

        var doc = JsonDocument.Parse(response.Result!.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());
        Assert.Null(executor.LastLease);
    }

    /// <summary>
    /// The negative control, and a second attack. The legitimate request still runs, and its lease
    /// names only what the operator approved for that address: the parent commit leased 80 and 443 to
    /// every address, so approving 203.0.113.7:443 also opened 203.0.113.7:80.
    /// </summary>
    [Fact]
    public async Task RunCommand_LeasesOnlyTheEndpointsTheOperatorApproved()
    {
        var executor = new MockLeasedExecutor();
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), new MockAuditLedger(),
            egressPolicy: McpEgressPolicy.Parse("203.0.113.7:443, 127.0.0.1:80"));

        var response = await handler.ProcessMessageAsync(FsCall(24, "run_command", new
        {
            command = "/usr/bin/curl",
            allowNetwork = true,
            allowedEgressIps = new[] { "203.0.113.7" }
        }));

        var doc = JsonDocument.Parse(response.Result!.Value.GetRawText());
        Assert.False(doc.RootElement.GetProperty("isError").GetBoolean());
        Assert.NotNull(executor.LastLease);
        Assert.True(executor.LastLease!.AllowNetwork);
        Assert.Equal(new[] { "203.0.113.7" }, executor.LastLease.AllowedEgressIps);
        Assert.Equal(new uint[] { 443 }, executor.LastLease.AllowedEgressPorts);
    }

    /// <summary>
    /// A policy that is half understood is not a policy, so one malformed entry refuses the list.
    /// "1:443" is the entry a loose parser gets wrong: IPAddress.TryParse reads "1" as 0.0.0.1.
    /// </summary>
    [Theory]
    [InlineData("example.com:443")]
    [InlineData("203.0.113.7")]
    [InlineData("203.0.113.7:0")]
    [InlineData("1:443")]
    public void EgressPolicy_RefusesAMalformedEntry(string spec)
    {
        Assert.Throws<FormatException>(() => McpEgressPolicy.Parse(spec));
    }
}
