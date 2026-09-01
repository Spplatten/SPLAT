using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Crew;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Regression cover for four defects the crew engine shipped with: enum-order severity ranking,
/// task results dying inside the streaming iterator, an unreachable delegation guard, and
/// fabricated success strings reaching the non-repudiation ledger. Kept in its own file so a
/// rewrite of the broader orchestration suite cannot silently drop these cases.
/// </summary>
public class GovernedCrewDefectRegressionTests
{
    private static SingleToolTemplate MakeTemplate(string templateId) => new(
        TemplateId: templateId,
        Name: $"Template {templateId}",
        Description: "Test template",
        Category: "Test",
        TargetModel: "claude-sonnet-5",
        Tool: new SingleToolDefinition("tool-echo", "Echo Tool", "cmd.exe", "/c echo test", new[] { 0 }),
        EgressRule: new EgressRule("api.anthropic.com", 443),
        SystemPrompt: "Test analysis",
        ParameterFields: Array.Empty<TemplateParameterField>(),
        AvailableRemediations: Array.Empty<RemediationAction>());

    private static GovernedCrewAgent MakeAgent(string agentId, IReadOnlyList<string>? templateIds = null) => new(
        AgentId: agentId,
        Role: $"Role {agentId}",
        Goal: "Test goal",
        Backstory: "Test backstory",
        AssignedTemplateIds: templateIds);

    [Fact]
    public async Task RunCrewAsync_RanksCriticalAboveUnknown_AndSurfacesTaskResults()
    {
        // Unknown is declared AFTER Critical in DiagnosticHealthStatus, so a raw '>' comparison
        // would let an Unknown verdict outrank a Critical one in the aggregate.
        var engine = new ScriptedMissionEngine(t => t.TemplateId == "tpl-critical"
            ? ("CRITICAL_MARKER breach detected", null)
            : ("unparseable sensor noise", null));
        var registry = new StubTemplateRegistry(new[] { MakeTemplate("tpl-critical"), MakeTemplate("tpl-unknown") });
        var ledger = new RecordingLedger();

        var crewEngine = new GovernedCrewEngine(
            engine, registry, ledger, findingsExtractor: new MarkerFindingsExtractor());

        var crew = new GovernedCrewDefinition(
            CrewId: "crew-status",
            Name: "Status Crew",
            Description: "Aggregation test crew",
            ProcessType: CrewProcessType.Sequential,
            Agents: new[] { MakeAgent("agent-1") },
            Tasks: new[]
            {
                new GovernedCrewTask("task-1", "Find breaches", "Report", "agent-1", TemplateId: "tpl-critical"),
                new GovernedCrewTask("task-2", "Read noisy sensor", "Report", "agent-1", TemplateId: "tpl-unknown")
            });

        var result = await crewEngine.RunCrewAsync(crew, new Dictionary<string, string>(), "corp\\alice");

        Assert.Equal(2, result.TaskResults.Count);
        Assert.Equal(DiagnosticHealthStatus.Critical, result.TaskResults[0].ExtractedFindings!.OverallStatus);
        Assert.Equal(DiagnosticHealthStatus.Unknown, result.TaskResults[1].ExtractedFindings!.OverallStatus);
        Assert.Equal(DiagnosticHealthStatus.Critical, result.OverallStatus);
        Assert.All(result.TaskResults, t => Assert.True(t.Success));
    }

    [Fact]
    public async Task Sequential_TaskWithoutTemplateOrModel_IsRecordedUnexecutable_NotFabricatedSuccess()
    {
        var engine = new ScriptedMissionEngine(_ => ("unused", null));
        var registry = new StubTemplateRegistry(Array.Empty<SingleToolTemplate>());
        var ledger = new RecordingLedger();

        // No model client and the task resolves no template: the engine must record an honest
        // failure, not a synthesized "evaluated successfully" string.
        var crewEngine = new GovernedCrewEngine(
            engine, registry, ledger, findingsExtractor: new MarkerFindingsExtractor());

        var crew = new GovernedCrewDefinition(
            CrewId: "crew-unexecutable",
            Name: "Unexecutable Crew",
            Description: "Fallback honesty test crew",
            ProcessType: CrewProcessType.Sequential,
            Agents: new[] { MakeAgent("agent-1") },
            Tasks: new[] { new GovernedCrewTask("task-1", "Analytical work", "Report", "agent-1") });

        var result = await crewEngine.RunCrewAsync(crew, new Dictionary<string, string>(), "corp\\alice");

        Assert.Equal(0, engine.Executions);
        var task = Assert.Single(result.TaskResults);
        Assert.False(task.Success);
        Assert.DoesNotContain("successfully", task.RawOutput, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(DiagnosticHealthStatus.Warning, result.OverallStatus);
        Assert.Contains("0/1", result.ExecutiveSummary);
    }

    [Fact]
    public async Task Hierarchical_FailingTask_RetriesOnce_ThenAntiLivelockHalts()
    {
        var engine = new ScriptedMissionEngine(_ => ("attempt output", "tool exploded"));
        var registry = new StubTemplateRegistry(new[] { MakeTemplate("tpl-fail") });
        var ledger = new RecordingLedger();

        var crewEngine = new GovernedCrewEngine(
            engine, registry, ledger, findingsExtractor: new MarkerFindingsExtractor());

        var crew = new GovernedCrewDefinition(
            CrewId: "crew-livelock",
            Name: "Livelock Crew",
            Description: "Anti-livelock guard test crew",
            ProcessType: CrewProcessType.Hierarchical,
            Agents: new[] { MakeAgent("agent-1") },
            Tasks: new[] { new GovernedCrewTask("task-1", "Doomed work", "Report", "agent-1", TemplateId: "tpl-fail") },
            ManagerAgent: MakeAgent("manager-1"),
            MaxCrewIterations: 10);

        var result = await crewEngine.RunCrewAsync(crew, new Dictionary<string, string>(), "corp\\alice");

        // Initial dispatch + exactly one retry; the third selection must halt, not execute.
        Assert.Equal(2, engine.Executions);
        Assert.Equal(2, result.TaskResults.Count);
        Assert.All(result.TaskResults, t => Assert.False(t.Success));
        Assert.True(result.CycleDetected);
        Assert.Equal(DiagnosticHealthStatus.Warning, result.OverallStatus);
        Assert.Contains(ledger.Entries, e => e.Action == "CREW_DELEGATION_CYCLE_HALTED");
    }

    [Fact]
    public async Task Hierarchical_ModelDrivenManager_PicksFromClosedSet_AndConcludes()
    {
        var engine = new ScriptedMissionEngine(_ => ("HEALTHY_MARKER all clear", null));
        var registry = new StubTemplateRegistry(new[] { MakeTemplate("tpl-a"), MakeTemplate("tpl-b") });
        var ledger = new RecordingLedger();
        var manager = new ScriptedManagerModelClient(
            "Data must exist before analysis.\n```json\n{ \"action\": \"continue\", \"taskId\": \"task-b\", \"reason\": \"Collect data first.\" }\n```",
            "Goal met.\n```json\n{ \"action\": \"stop\", \"taskId\": null, \"reason\": \"All required work is complete.\" }\n```");

        var crewEngine = new GovernedCrewEngine(
            engine, registry, ledger, findingsExtractor: new MarkerFindingsExtractor(), modelClient: manager);

        var crew = new GovernedCrewDefinition(
            CrewId: "crew-manager",
            Name: "Managed Crew",
            Description: "Model-driven delegation test crew",
            ProcessType: CrewProcessType.Hierarchical,
            Agents: new[] { MakeAgent("agent-1"), MakeAgent("agent-2") },
            Tasks: new[]
            {
                new GovernedCrewTask("task-a", "Analyze data", "Report", "agent-1", TemplateId: "tpl-a"),
                new GovernedCrewTask("task-b", "Collect data", "Raw data", "agent-2", TemplateId: "tpl-b")
            },
            ManagerAgent: MakeAgent("manager-1"),
            MaxCrewIterations: 10);

        var result = await crewEngine.RunCrewAsync(crew, new Dictionary<string, string>(), "corp\\alice");

        // The manager chose task-b out of declared order, then concluded before task-a ran.
        var task = Assert.Single(result.TaskResults);
        Assert.Equal("task-b", task.TaskId);
        Assert.True(task.Success);
        Assert.False(result.CycleDetected);
        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.Contains(ledger.Entries, e => e.Action == "CREW_MANAGER_CONCLUDED");
    }

    private sealed class ScriptedMissionEngine : IMissionExecutionEngine
    {
        private readonly Func<SingleToolTemplate, (string Stdout, string? Stderr)> _script;

        public ScriptedMissionEngine(Func<SingleToolTemplate, (string Stdout, string? Stderr)> script) => _script = script;

        public int Executions { get; private set; }

        public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            Executions++;
            var id = Guid.NewGuid();
            var (stdout, stderr) = _script(template);
            yield return new MissionChunk(id, MissionChunkType.Stdout, stdout, DateTime.UtcNow);
            if (stderr != null)
            {
                yield return new MissionChunk(id, MissionChunkType.Stderr, stderr, DateTime.UtcNow);
            }

            yield return new MissionChunk(id, MissionChunkType.Completed, "Done", DateTime.UtcNow);
            await Task.Yield();
        }
    }

    private sealed class MarkerFindingsExtractor : IDiagnosticFindingsExtractor
    {
        public ExecutiveDiagnosisResult ExtractFindings(string aiOutput, string? rawToolOutput = null, string? templateName = null)
        {
            var status = aiOutput.Contains("CRITICAL_MARKER") ? DiagnosticHealthStatus.Critical
                : aiOutput.Contains("WARNING_MARKER") ? DiagnosticHealthStatus.Warning
                : aiOutput.Contains("HEALTHY_MARKER") ? DiagnosticHealthStatus.Healthy
                : DiagnosticHealthStatus.Unknown;

            return new ExecutiveDiagnosisResult(status, $"Status {status}", Array.Empty<string>());
        }
    }

    private sealed class ScriptedManagerModelClient : IModelStreamClient
    {
        private readonly Queue<string> _responses;

        public ScriptedManagerModelClient(params string[] responses) => _responses = new Queue<string>(responses);

        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(false, "Simulated", requestedModel, "No real key configured"));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel,
            string systemPrompt,
            string userPrompt,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return _responses.Count > 0
                ? _responses.Dequeue()
                : "```json\n{ \"action\": \"stop\", \"reason\": \"No scripted response remaining.\" }\n```";
        }
    }

    private sealed class StubTemplateRegistry : ITemplateRegistry
    {
        private readonly IReadOnlyList<SingleToolTemplate> _templates;

        public StubTemplateRegistry(IReadOnlyList<SingleToolTemplate> templates) => _templates = templates;

        public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(_templates);

        public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_templates.FirstOrDefault(t => string.Equals(t.TemplateId, templateId, StringComparison.OrdinalIgnoreCase)));

        public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class RecordingLedger : IAuditLedger
    {
        public List<AuditLogEntry> Entries { get; } = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            long id = Entries.Count + 1;
            string hash = Guid.NewGuid().ToString("N");
            string prevHash = Entries.Count > 0 ? Entries[^1].EntryHash : new string('0', 64);
            Entries.Add(new AuditLogEntry(id, DateTime.UtcNow, missionId, templateId, action, details, operatorIdentity, hash, prevHash));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Entries);

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }
}
