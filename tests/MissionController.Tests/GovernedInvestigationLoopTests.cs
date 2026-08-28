using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The ReAct loop chains sandboxed executions against a live endpoint, so its governance limits are
/// the tests that matter: the model may only pick from the governed catalog, may never repeat a
/// step, may never exceed the budget, and may never talk the loop past its hard ceiling.
/// </summary>
public class GovernedInvestigationLoopTests
{
    // ---------------------------------------------------------------- fakes

    /// <summary>Replays a scripted mission per template without touching a real sandbox.</summary>
    private sealed class ScriptedEngine : IMissionExecutionEngine
    {
        public readonly List<string> ExecutedTemplateIds = new();
        public readonly Dictionary<string, string> AnalysisByTemplateId = new();
        public bool FailNextMission;

        public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template, IReadOnlyDictionary<string, string> parameters, string operatorIdentity,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            ExecutedTemplateIds.Add(template.TemplateId);
            await Task.Yield();

            var missionId = Guid.NewGuid();
            yield return new MissionChunk(missionId, MissionChunkType.Stdout, "raw telemetry", DateTime.UtcNow);

            string analysis = AnalysisByTemplateId.TryGetValue(template.TemplateId, out var scripted)
                ? scripted
                : BuildVerdict("Critical", $"{template.Name} found a problem");

            yield return new MissionChunk(missionId, MissionChunkType.AiToken, analysis, DateTime.UtcNow);

            if (FailNextMission)
            {
                FailNextMission = false;
                yield return new MissionChunk(missionId, MissionChunkType.Stderr, "MISSION FAILED", DateTime.UtcNow);
                yield break; // no Completed chunk - the loop must treat this as a failed step
            }

            yield return new MissionChunk(missionId, MissionChunkType.Completed, "done", DateTime.UtcNow);
        }
    }

    private sealed class InMemoryTemplateRegistry : ITemplateRegistry
    {
        private readonly List<SingleToolTemplate> _templates = new();

        public InMemoryTemplateRegistry(params string[] templateIds)
        {
            foreach (var id in templateIds)
            {
                _templates.Add(BuildTemplate(id));
            }
        }

        public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SingleToolTemplate>>(_templates);

        public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default)
        {
            foreach (var template in _templates)
            {
                if (template.TemplateId.Equals(templateId, StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult<SingleToolTemplate?>(template);
            }

            return Task.FromResult<SingleToolTemplate?>(null);
        }

        public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default)
        {
            _templates.Add(template);
            return Task.CompletedTask;
        }
    }

    /// <summary>Returns a scripted decision per call, and records the prompts it was handed.</summary>
    private sealed class ScriptedDecisionClient : IModelStreamClient
    {
        private readonly Queue<string> _decisions;
        public readonly List<string> CapturedPrompts = new();

        public ScriptedDecisionClient(params string[] decisions) => _decisions = new Queue<string>(decisions);

        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, "Fake", requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(string requestedModel, string systemPrompt,
            string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            CapturedPrompts.Add(systemPrompt);
            await Task.Yield();
            yield return _decisions.Count > 0 ? _decisions.Dequeue() : Continue("nonexistent-template");
        }
    }

    private sealed class RecordingAuditLedger : IAuditLedger
    {
        public readonly List<(string Action, string Details)> Entries = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (Entries) Entries.Add((action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    // ---------------------------------------------------------------- helpers

    private static SingleToolTemplate BuildTemplate(string templateId) => new(
        templateId,
        $"Agent {templateId}",
        $"Diagnostic template {templateId}",
        "Net",
        "gemini-2.0-flash",
        new SingleToolDefinition($"tool-{templateId}", "ping", "cmd.exe", "/c ping 127.0.0.1", new[] { 0 }),
        new EgressRule("googleapis.com"),
        "Analyze output",
        new Dictionary<string, string>());

    private static string BuildVerdict(string status, string headline) => $$"""
        ```json
        {"status":"{{status}}","headline":"{{headline}}","findings":["{{headline}}"]}
        ```
        """;

    private static string Continue(string templateId) => $$"""
        ```json
        {"action":"continue","templateId":"{{templateId}}","reason":"Following the unexplained signal."}
        ```
        """;

    private const string StopDecision = """
        ```json
        {"action":"stop","templateId":null,"reason":"The finding is already fully explained."}
        ```
        """;

    private static GovernedInvestigationLoop BuildLoop(
        ScriptedEngine engine, InMemoryTemplateRegistry registry, ScriptedDecisionClient client,
        RecordingAuditLedger ledger) =>
        new(engine, registry, client, ledger, new JsonFindingsExtractor());

    // ---------------------------------------------------------------- governance

    [Fact]
    public async Task ModelSelectingATemplateOutsideTheCatalog_StopsTheChain_AndSpawnsNothing()
    {
        var engine = new ScriptedEngine();
        var registry = new InMemoryTemplateRegistry("net-dns-audit", "sysops-disk-space");
        // A plausible-looking id that was never offered - the case that must never reach a sandbox.
        var client = new ScriptedDecisionClient(Continue("powershell-remote-exec"));
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        var result = await loop.InvestigateAsync(
            BuildTemplate("net-dns-audit"), new Dictionary<string, string>(), "op", maxSteps: 3);

        Assert.Equal(InvestigationStopReason.ModelDeclinedToContinue, result.StopReason);
        Assert.Contains("not in the governed catalog", result.StopExplanation);
        // The decisive assertion: only the operator's own starting template ever executed.
        Assert.Equal(new[] { "net-dns-audit" }, engine.ExecutedTemplateIds);
    }

    [Fact]
    public async Task ChainStopsAtTheRequestedBudget_EvenWhenTheModelKeepsAskingForMore()
    {
        var engine = new ScriptedEngine();
        var registry = new InMemoryTemplateRegistry("t1", "t2", "t3", "t4", "t5");
        var client = new ScriptedDecisionClient(Continue("t2"), Continue("t3"), Continue("t4"), Continue("t5"));
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 2);

        Assert.Equal(InvestigationStopReason.StepBudgetExhausted, result.StopReason);
        Assert.Equal(2, result.Steps.Count);
        Assert.Equal(2, engine.ExecutedTemplateIds.Count);
    }

    [Fact]
    public async Task RequestedBudgetCannotExceedTheHardCeiling()
    {
        var engine = new ScriptedEngine();
        var registry = new InMemoryTemplateRegistry("t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8");
        var client = new ScriptedDecisionClient(
            Continue("t2"), Continue("t3"), Continue("t4"), Continue("t5"), Continue("t6"), Continue("t7"));
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        // A caller asking for 99 chained sandboxed executions must still be clamped.
        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 99);

        Assert.Equal(GovernedInvestigationLoop.AbsoluteMaxSteps, result.Steps.Count);
        Assert.Equal(GovernedInvestigationLoop.AbsoluteMaxSteps, engine.ExecutedTemplateIds.Count);
    }

    [Fact]
    public async Task AlreadyRunTemplatesAreNotOfferedAgain_SoTheChainCannotOscillate()
    {
        var engine = new ScriptedEngine();
        var registry = new InMemoryTemplateRegistry("t1", "t2", "t3");
        // Second decision asks to go back to the starting template. It is no longer a candidate, so
        // the whitelist refuses it and the chain ends instead of ping-ponging until the budget drains.
        var client = new ScriptedDecisionClient(Continue("t2"), Continue("t1"));
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 4);

        Assert.Equal(new[] { "t1", "t2" }, engine.ExecutedTemplateIds);
        Assert.Equal(InvestigationStopReason.ModelDeclinedToContinue, result.StopReason);

        // The second decision prompt offered only the unvisited template.
        string secondCandidateList = client.CapturedPrompts[1].Split("[AVAILABLE")[1];
        Assert.Contains("t3", secondCandidateList);
        Assert.DoesNotContain("t1", secondCandidateList);
    }

    [Fact]
    public async Task ExhaustedCatalog_StopsWithoutEvenConsultingTheModel()
    {
        var engine = new ScriptedEngine();
        var registry = new InMemoryTemplateRegistry("t1", "t2");
        var client = new ScriptedDecisionClient(Continue("t2"));
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 4);

        Assert.Equal(new[] { "t1", "t2" }, engine.ExecutedTemplateIds);
        Assert.Equal(InvestigationStopReason.NoGovernedCandidateRemaining, result.StopReason);
        // Only one decision was ever needed; with nothing left to offer there is no question to ask.
        Assert.Single(client.CapturedPrompts);
    }

    // ---------------------------------------------------------------- stopping behaviour

    [Fact]
    public async Task HealthyVerdict_EndsTheChainImmediately()
    {
        var engine = new ScriptedEngine();
        engine.AnalysisByTemplateId["t1"] = BuildVerdict("Healthy", "Everything checks out");
        var registry = new InMemoryTemplateRegistry("t1", "t2");
        var client = new ScriptedDecisionClient(Continue("t2"));
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 3);

        Assert.Equal(InvestigationStopReason.SystemHealthy, result.StopReason);
        Assert.Single(result.Steps);
        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        // The model was never even consulted - there was nothing to follow up.
        Assert.Empty(client.CapturedPrompts);
    }

    [Fact]
    public async Task FailedStep_EndsTheChain_RatherThanChainingOffAMissionThatNeverCompleted()
    {
        var engine = new ScriptedEngine { FailNextMission = true };
        var registry = new InMemoryTemplateRegistry("t1", "t2");
        var client = new ScriptedDecisionClient(Continue("t2"));
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 3);

        Assert.Equal(InvestigationStopReason.StepFailed, result.StopReason);
        Assert.Single(engine.ExecutedTemplateIds);
    }

    [Fact]
    public async Task ModelDecliningToContinue_IsHonouredAndExplainedToTheOperator()
    {
        var engine = new ScriptedEngine();
        var registry = new InMemoryTemplateRegistry("t1", "t2");
        var client = new ScriptedDecisionClient(StopDecision);
        var loop = BuildLoop(engine, registry, client, new RecordingAuditLedger());

        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 3);

        Assert.Equal(InvestigationStopReason.ModelDeclinedToContinue, result.StopReason);
        Assert.Equal("The finding is already fully explained.", result.StopExplanation);
        Assert.Single(result.Steps);
    }

    [Fact]
    public async Task MultiStepChain_RecordsEachStepWithItsSelectionReason_AndAuditsTheWholeInvestigation()
    {
        var engine = new ScriptedEngine();
        engine.AnalysisByTemplateId["t2"] = BuildVerdict("Critical", "Port 443 handshake failed");
        var registry = new InMemoryTemplateRegistry("t1", "t2", "t3");
        var client = new ScriptedDecisionClient(Continue("t2"), StopDecision);
        var ledger = new RecordingAuditLedger();
        var loop = BuildLoop(engine, registry, client, ledger);

        var chunks = new List<MissionChunk>();
        var result = await loop.InvestigateAsync(
            BuildTemplate("t1"), new Dictionary<string, string>(), "op", maxSteps: 3,
            progress: new Progress<MissionChunk>(chunks.Add));

        Assert.Equal(2, result.Steps.Count);
        Assert.Equal("Operator-selected starting diagnostic.", result.Steps[0].SelectionReason);
        Assert.Equal("Following the unexplained signal.", result.Steps[1].SelectionReason);
        Assert.Equal("Port 443 handshake failed", result.Steps[1].Verdict.StatusHeadline);
        Assert.Equal(DiagnosticHealthStatus.Critical, result.OverallStatus);

        Assert.Contains(ledger.Entries, e => e.Action == "INVESTIGATION_STARTED");
        Assert.Contains(ledger.Entries, e => e.Action == "INVESTIGATION_STEP_SELECTED");
        Assert.Contains(ledger.Entries, e => e.Action == "INVESTIGATION_COMPLETED" && e.Details.Contains("Steps: 2"));
    }

    // ---------------------------------------------------------------- decision parsing

    [Theory]
    [InlineData("not json at all")]
    [InlineData("")]
    [InlineData("{\"action\":\"continue\"}")]
    [InlineData("{\"action\":\"continue\",\"templateId\":\"\"}")]
    public void MalformedOrIncompleteDecision_ResolvesToStop(string modelOutput)
    {
        var decision = ReActDecisionContract.Parse(modelOutput, new[] { "t1", "t2" });

        Assert.False(decision.ShouldContinue);
        Assert.Null(decision.TemplateId);
    }

    [Fact]
    public void DecisionParsing_IsCaseInsensitiveOnTemplateId_ButStillWhitelisted()
    {
        var accepted = ReActDecisionContract.Parse(Continue("NET-DNS-AUDIT"), new[] { "net-dns-audit" });
        Assert.True(accepted.ShouldContinue);
        Assert.Equal("net-dns-audit", accepted.TemplateId);

        var refused = ReActDecisionContract.Parse(Continue("net-dns-audit-v2"), new[] { "net-dns-audit" });
        Assert.False(refused.ShouldContinue);
    }
}
