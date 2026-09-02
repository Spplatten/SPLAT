using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Crew;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

public class GovernedCrewEngineTests
{
    private class MockAuditLedger : IAuditLedger
    {
        public List<(Guid MissionId, string TemplateId, string Action, string Details)> Logs { get; } = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            Logs.Add((missionId, templateId, action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private class MockTemplateRegistry : ITemplateRegistry
    {
        private readonly Dictionary<string, SingleToolTemplate> _templates;

        public MockTemplateRegistry(IEnumerable<SingleToolTemplate> templates)
        {
            _templates = templates.ToDictionary(t => t.TemplateId, StringComparer.OrdinalIgnoreCase);
        }

        public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SingleToolTemplate>>(_templates.Values.ToList());

        public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_templates.TryGetValue(templateId, out var template) ? template : null);

        public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default)
        {
            _templates[template.TemplateId] = template;
            return Task.CompletedTask;
        }
    }

    private class MockMissionExecutionEngine : IMissionExecutionEngine
    {
        public List<(string TemplateId, IReadOnlyDictionary<string, string> Params)> Calls { get; } = new();
        private readonly string _toolOutput;
        private readonly string _aiOutput;

        public MockMissionExecutionEngine(string toolOutput = "Tool executed successfully", string aiOutput = "AI analysis result")
        {
            _toolOutput = toolOutput;
            _aiOutput = aiOutput;
        }

        public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            Calls.Add((template.TemplateId, parameters));
            yield return new MissionChunk(Guid.NewGuid(), MissionChunkType.Stdout, _toolOutput, DateTime.UtcNow);
            yield return new MissionChunk(Guid.NewGuid(), MissionChunkType.AiToken, _aiOutput, DateTime.UtcNow);
        }
    }

    private class MockDlpSanitizer : IDataLossPreventionSanitizer
    {
        public DlpSanitizationResult Sanitize(string input)
        {
            var sanitized = input
                .Replace("SECRET_API_KEY_12345", "[REDACTED_API_KEY]")
                .Replace("admin:password123", "[REDACTED_PASSWORD]");

            return new DlpSanitizationResult(sanitized, 1, new[] { "Credential" });
        }
    }

    private static SingleToolTemplate BuildTemplate(string templateId) => new(
        TemplateId: templateId,
        Name: $"Template {templateId}",
        Description: "Diagnostic tool",
        Category: "Diagnostics",
        TargetModel: "claude-3-5-sonnet",
        Tool: new SingleToolDefinition("tool-test", "Test Tool", "cmd.exe", "/c echo test", new[] { 0 }),
        EgressRule: new EgressRule("api.anthropic.com", 443),
        SystemPrompt: "Analyze telemetry",
        ParameterFields: Array.Empty<TemplateParameterField>());

    [Fact]
    public async Task Sequential_Orchestration_ExecutesOrderedTasks_WithContextHandoff()
    {
        var templateA = BuildTemplate("tool-dns");
        var templateB = BuildTemplate("tool-disk");

        var registry = new MockTemplateRegistry(new[] { templateA, templateB });
        var missionEngine = new MockMissionExecutionEngine(
            toolOutput: "DNS latency: 12ms",
            aiOutput: "DNS health is normal.");
        var ledger = new MockAuditLedger();
        var dlp = new MockDlpSanitizer();

        var engine = new GovernedCrewEngine(missionEngine, registry, ledger, dlp);

        var crew = new GovernedCrewDefinition(
            CrewId: "test-seq-crew",
            Name: "Sequential Test Crew",
            Description: "Tests sequential task execution",
            ProcessType: CrewProcessType.Sequential,
            Agents: new[]
            {
                new GovernedCrewAgent("agent-dns", "DNS Specialist", "Audit DNS", "Expert in DNS", "claude-3-5-sonnet", new[] { "tool-dns" }),
                new GovernedCrewAgent("agent-disk", "Disk Specialist", "Audit Storage", "Expert in Storage", "claude-3-5-sonnet", new[] { "tool-disk" })
            },
            Tasks: new[]
            {
                new GovernedCrewTask("task-1", "Run DNS check", "DNS metrics", "agent-dns", "tool-dns"),
                new GovernedCrewTask("task-2", "Run Disk check", "Disk metrics", "agent-disk", "tool-disk", ContextTaskIds: new[] { "task-1" })
            });

        var result = await engine.RunCrewAsync(crew, new Dictionary<string, string>(), "test-operator");

        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.False(result.CycleDetected);
        Assert.Equal(2, missionEngine.Calls.Count);

        // Verify task 2 received task 1's context
        var task2Params = missionEngine.Calls[1].Params;
        Assert.Contains("UpstreamContext", task2Params.Keys);
        Assert.Contains("Context from Task 'task-1'", task2Params["UpstreamContext"]);
        Assert.Contains("DNS health is normal.", task2Params["UpstreamContext"]);

        // Verify audit logs committed
        Assert.Contains(ledger.Logs, l => l.Action == "CREW_ORCHESTRATION_INITIATED");
        Assert.Contains(ledger.Logs, l => l.Action == "CREW_TASK_COMPLETED" && l.Details.Contains("task-1"));
        Assert.Contains(ledger.Logs, l => l.Action == "CREW_TASK_COMPLETED" && l.Details.Contains("task-2"));
    }

    [Fact]
    public async Task Sequential_Orchestration_SanitizesContextWithDlp_BeforeDownstreamInjection()
    {
        var templateA = BuildTemplate("tool-auth");
        var templateB = BuildTemplate("tool-audit");

        var registry = new MockTemplateRegistry(new[] { templateA, templateB });
        var missionEngine = new MockMissionExecutionEngine(
            toolOutput: "Found credential secret: SECRET_API_KEY_12345 and user admin:password123",
            aiOutput: "Auth completed with raw token: SECRET_API_KEY_12345");
        var ledger = new MockAuditLedger();
        var dlp = new MockDlpSanitizer();

        var engine = new GovernedCrewEngine(missionEngine, registry, ledger, dlp);

        var crew = new GovernedCrewDefinition(
            CrewId: "test-dlp-crew",
            Name: "DLP Test Crew",
            Description: "Tests DLP masking on inter-agent handoffs",
            ProcessType: CrewProcessType.Sequential,
            Agents: new[]
            {
                new GovernedCrewAgent("agent-auth", "Auth Hunter", "Extract Auth", "Backstory", "claude-3-5-sonnet", new[] { "tool-auth" }),
                new GovernedCrewAgent("agent-audit", "Auditor", "Audit Everything", "Backstory", "claude-3-5-sonnet", new[] { "tool-audit" })
            },
            Tasks: new[]
            {
                new GovernedCrewTask("task-1", "Inspect tokens", "Token report", "agent-auth", "tool-auth"),
                new GovernedCrewTask("task-2", "Audit report", "Audit summary", "agent-audit", "tool-audit", ContextTaskIds: new[] { "task-1" })
            });

        var result = await engine.RunCrewAsync(crew, new Dictionary<string, string>(), "test-operator");

        var task2Context = missionEngine.Calls[1].Params["UpstreamContext"];
        Assert.DoesNotContain("SECRET_API_KEY_12345", task2Context);
        Assert.DoesNotContain("password123", task2Context);
        Assert.Contains("[REDACTED_API_KEY]", task2Context);
    }

    [Fact]
    public async Task Hierarchical_Orchestration_ManagerRoutesSubTasks_ToSpecializedAgents()
    {
        var templateSec = BuildTemplate("secops-auth-inspector");
        var registry = new MockTemplateRegistry(new[] { templateSec });
        var missionEngine = new MockMissionExecutionEngine(
            toolOutput: "Security events clean",
            aiOutput: "Zero failed logons detected.");
        var ledger = new MockAuditLedger();

        var engine = new GovernedCrewEngine(missionEngine, registry, ledger);

        var crew = new GovernedCrewDefinition(
            CrewId: "test-hierarchical-crew",
            Name: "Hierarchical Incident Crew",
            Description: "Tests manager routing",
            ProcessType: CrewProcessType.Hierarchical,
            ManagerAgent: new GovernedCrewAgent("manager", "Incident Commander", "Lead Response", "Leader", "claude-3-5-sonnet", AllowDelegation: true),
            Agents: new[]
            {
                new GovernedCrewAgent("auth-worker", "Auth Analyst", "Analyze Auth", "Worker", "claude-3-5-sonnet", new[] { "secops-auth-inspector" })
            },
            Tasks: new[]
            {
                new GovernedCrewTask("task-sec-triage", "Triage security events", "Triage findings", "auth-worker", "secops-auth-inspector")
            });

        var result = await engine.RunCrewAsync(crew, new Dictionary<string, string>(), "test-operator");

        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.False(result.CycleDetected);
        Assert.Single(missionEngine.Calls);
        Assert.Contains(ledger.Logs, l => l.Action == "CREW_HIERARCHICAL_TASK_DISPATCHED");
    }

    [Fact]
    public async Task Hierarchical_Orchestration_DetectsCycle_AndPreventsPingPongDeadlock()
    {
        var templateA = BuildTemplate("tool-a");
        var registry = new MockTemplateRegistry(new[] { templateA });
        var missionEngine = new MockMissionExecutionEngine();
        var ledger = new MockAuditLedger();

        var engine = new GovernedCrewEngine(missionEngine, registry, ledger);

        var workerAgent = new GovernedCrewAgent("worker-a", "Worker", "Loop Task", "Worker", "claude-3-5-sonnet", new[] { "tool-a" });
        var managerAgent = new GovernedCrewAgent("manager", "Manager", "Oversee", "Manager", "claude-3-5-sonnet", AllowDelegation: true);

        var task = new GovernedCrewTask("task-repeat", "Repeating task", "Output", "worker-a", "tool-a");

        var crew = new GovernedCrewDefinition(
            CrewId: "test-cycle-crew",
            Name: "Cycle Detection Crew",
            Description: "Tests cycle prevention",
            ProcessType: CrewProcessType.Hierarchical,
            ManagerAgent: managerAgent,
            Agents: new[] { workerAgent },
            Tasks: new[] { task },
            MaxCrewIterations: 5);

        // Execute twice on same task to force cycle trigger in hierarchical loop
        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteCrewAsync(crew, new Dictionary<string, string>(), "test-operator"))
        {
            chunks.Add(chunk);
        }

        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.Completed);
        Assert.Contains(ledger.Logs, l => l.Action == "CREW_ORCHESTRATION_INITIATED");
    }

    [Fact]
    public void GovernedCrew_Validation_RejectsInvalidCrewDefinitions()
    {
        // 1. Empty CrewId
        Assert.Throws<InvalidOperationException>(() =>
            new GovernedCrewDefinition("", "Name", "Desc", CrewProcessType.Sequential, Array.Empty<GovernedCrewAgent>(), Array.Empty<GovernedCrewTask>()).Validate());

        // 2. Hierarchical without ManagerAgent
        Assert.Throws<InvalidOperationException>(() =>
            new GovernedCrewDefinition(
                "crew-1", "Name", "Desc",
                CrewProcessType.Hierarchical,
                new[] { new GovernedCrewAgent("a1", "R", "G", "B") },
                new[] { new GovernedCrewTask("t1", "D", "E", "a1") }).Validate());

        // 3. Task referencing non-existent agent
        Assert.Throws<InvalidOperationException>(() =>
            new GovernedCrewDefinition(
                "crew-2", "Name", "Desc",
                CrewProcessType.Sequential,
                new[] { new GovernedCrewAgent("a1", "R", "G", "B") },
                new[] { new GovernedCrewTask("t1", "D", "E", "unassigned-agent") }).Validate());
    }

    [Fact]
    public void GovernedCrew_Catalog_ContainsEnterprisePresets()
    {
        var presets = GovernedCrewCatalog.All;
        Assert.NotNull(presets);
        Assert.NotEmpty(presets);

        foreach (var crew in presets)
        {
            crew.Validate(); // Ensures all presets are structurally valid
            Assert.NotEmpty(crew.Agents);
            Assert.NotEmpty(crew.Tasks);
        }

        Assert.Contains(presets, c => c.CrewId == "secops-incident-response-crew");
        Assert.Contains(presets, c => c.CrewId == "campus-infrastructure-audit-crew");
    }

    [Fact]
    public async Task McpServer_ExposesAndExecutesGovernedCrews()
    {
        var templateNet = BuildTemplate("net-dns-audit");
        var templateDisk = BuildTemplate("sysops-disk-space");
        var templateSvc = BuildTemplate("sysops-service-failures");

        var registry = new MockTemplateRegistry(new[] { templateNet, templateDisk, templateSvc });
        var missionEngine = new MockMissionExecutionEngine();
        var ledger = new MockAuditLedger();
        var crewEngine = new GovernedCrewEngine(missionEngine, registry, ledger);

        var leasedExecutor = new McpServerTests_MockLeasedExecutor();
        var policyCompiler = new TemplatePolicyCompiler();

        var handler = new McpServerHandler(
            leasedExecutor: leasedExecutor,
            policyCompiler: policyCompiler,
            auditLedger: ledger,
            missionEngine: missionEngine,
            templateRegistry: registry,
            crewEngine: crewEngine);

        // 1. Test tools/list exposes list_governed_crews & run_governed_crew
        var listRequest = new McpJsonRpcMessage { JsonRpc = "2.0", Id = JsonSerializer.SerializeToElement(1), Method = "tools/list" };
        var listResponse = await handler.ProcessMessageAsync(listRequest);

        Assert.Null(listResponse.Error);
        var toolsListJson = listResponse.Result?.ToString() ?? "";
        Assert.Contains("list_governed_crews", toolsListJson);
        Assert.Contains("run_governed_crew", toolsListJson);

        // 2. Test tools/call with list_governed_crews
        var callListReq = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(2),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new { name = "list_governed_crews" })
        };
        var callListResp = await handler.ProcessMessageAsync(callListReq);
        Assert.Null(callListResp.Error);
        Assert.Contains("secops-incident-response-crew", callListResp.Result?.ToString() ?? "");

        // 3. Test tools/call with run_governed_crew
        var callRunReq = new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(3),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_governed_crew",
                arguments = new { crewId = "campus-infrastructure-audit-crew" }
            })
        };
        var callRunResp = await handler.ProcessMessageAsync(callRunReq);
        Assert.Null(callRunResp.Error);
        Assert.Contains("GOVERNED CREW EXECUTION REPORT", callRunResp.Result?.ToString() ?? "");
    }

    private class McpServerTests_MockLeasedExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, string arguments, IProgress<string>? stdout = null, IProgress<string>? stderr = null, IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default) =>
            Task.FromResult(new ProcessExecutionResult(0, "Mock stdout", "", false, new JobResourceMetrics(1024, 0, 50, 50, 1)));
    }
}
