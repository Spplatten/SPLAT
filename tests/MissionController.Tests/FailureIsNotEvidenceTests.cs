using System;
using Microsoft.Win32.SafeHandles;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.QualityIsland;
using MissionController.Core.QualityIsland.Contracts;
using MissionController.Core.Workflow;
using MissionController.Infrastructure.Windows.Remediation;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Wave 2 of the audit remediation: a run that did not do the work must not read as one that did.
///
/// Each case here was a path that produced a confident result from an absent service, a discarded
/// evaluation or an unread exit condition - the shapes that turn a failed run into accepted
/// evidence and then into indexed memory.
/// </summary>
public class FailureIsNotEvidenceTests
{
    private sealed class NullLedger : IAuditLedger
    {
        public readonly List<string> Actions = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (Actions) Actions.Add(action);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private sealed class FakeJobSandbox : IJobSandbox
    {
        public string JobName => "failure-evidence-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(SafeProcessHandle processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(0, 0, 0, 0, 0);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    private sealed class NoJailManager : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult(AppContext.BaseDirectory);

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) =>
            Task.CompletedTask;

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    /// <summary>A launcher whose process is killed at its ceiling: TimedOut set, exit code clean.</summary>
    private sealed class TimingOutLauncher : IProcessLauncher
    {
        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            Task.FromResult(new ProcessExecutionResult(
                0, "partial output before the kill", "", true, JobResourceMetrics.Unavailable));
    }

    private sealed class SilentModelClient : IModelStreamClient
    {
        private readonly bool _isLive;

        public SilentModelClient(bool isLive = true) => _isLive = isLive;

        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(_isLive, "stub-provider", requestedModel, _isLive ? null : "no provider configured"));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel, string systemPrompt, string userPrompt,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return "analysis";
        }
    }

    // ------------------------------------------------------------------ absent services

    [Fact]
    public async Task AnAgentNodeWithNoModel_FailsInsteadOfReportingVerified()
    {
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-no-model",
            Name: "No Model",
            Description: "An analysis leg with nothing to analyse with.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("analyse", "Triage", WorkflowNodeType.AgentReasoning,
                    new Dictionary<string, string> { { "Prompt", "State the root cause." } },
                    TargetModel: "claude-sonnet-5")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        // The old branch emitted "Status: VERIFIED" over a character count - a named verdict on
        // evidence it never evaluated, which is the worst shape a governed result can take.
        Assert.False(result.Success);
        Assert.Contains("no model client", result.FailureReason);
        Assert.DoesNotContain("VERIFIED", string.Join(" ", result.ExecutionLogs));
    }

    [Fact]
    public async Task AMissionNodeWithNoMissionEngine_FailsInsteadOfSimulating()
    {
        // Same honesty property the old SandboxedScript version tested, transposed onto the node
        // type that replaced it. There is deliberately no simulation escape hatch here: a script
        // node could be demoed because nothing about it was ever contained, whereas a mission node
        // IS its containment, so a mission with no engine behind it has nothing to pretend with.
        var graph = new WorkflowGraph(
            WorkflowId: "flow-no-engine",
            Name: "No Mission Engine",
            Description: "A governed step with no substrate wired underneath it.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                WorkflowMissionDoubles.MissionNode("probe", "Probe", "test-probe")
            },
            Edges: new List<WorkflowEdge>());

        // Default composition wires neither engine nor registry, and allowSimulatedExecution must
        // not buy its way past that.
        var strict = new WorkflowExecutionEngine(allowSimulatedExecution: true);
        var refused = await strict.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.False(refused.Success);
        Assert.Contains("no mission engine is wired", refused.FailureReason);
        Assert.DoesNotContain("SIMULATED", string.Join(" ", refused.ExecutionLogs));

        // The control: the identical graph succeeds the moment a substrate is present, so the
        // refusal above is about the missing engine and not about the graph.
        var wired = new WorkflowExecutionEngine(
            missionEngine: new RecordingMissionEngine("real output"),
            templateRegistry: new StubTemplateRegistry("test-probe"));
        var ran = await wired.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(ran.Success, ran.FailureReason);
        Assert.Contains("real output", ran.NodeOutputs["probe"]);
    }

    [Fact]
    public async Task AWorkflowWhoseAnalysisRuns_StillSucceeds()
    {
        // The refusals above must not cost the working path. Same graph shape, services present.
        var engine = new WorkflowExecutionEngine(
            modelClient: new SilentModelClient(),
            missionEngine: new RecordingMissionEngine("hello"),
            templateRegistry: new StubTemplateRegistry("test-probe"));

        var graph = new WorkflowGraph(
            WorkflowId: "flow-wired",
            Name: "Wired",
            Description: "Mission then analysis, both serviced.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                WorkflowMissionDoubles.MissionNode("probe", "Probe", "test-probe"),
                new("analyse", "Triage", WorkflowNodeType.AgentReasoning,
                    new Dictionary<string, string> { { "Prompt", "Summarise." } })
            },
            Edges: new List<WorkflowEdge> { new("probe", "analyse") });

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(result.Success, result.FailureReason);
        Assert.Contains("analysis", result.NodeOutputs["analyse"]);
    }

    // ------------------------------------------------------------------ discarded evaluations

    [Fact]
    public async Task TheOfflineQualityIsland_ReportsItsOwnEvaluationVerdict()
    {
        // isLive: false is what routes the request to the offline/deterministic path.
        var engine = new QualityIslandEngine(new SilentModelClient(isLive: false), new NullLedger());

        // The offline path emits a StructuredDiagnosis artifact. Demanding a ReActDecision contract
        // makes its own oracle reject it, which is the verdict the result must now carry - the path
        // used to compute this evaluation and then hardcode IsSuccess: true over the top of it.
        var mismatched = await engine.ExecuteIslandAsync(new QualityIslandRequest(
            MissionId: Guid.NewGuid(),
            TemplateId: "tpl-offline",
            TargetModel: "offline",
            SystemPrompt: "Diagnose.",
            UserPayload: "disk at 94 percent",
            OperatorIdentity: "operator",
            RequiredSchema: SchemaContractType.ReActDecision));

        Assert.False(mismatched.IsSuccess);
        Assert.NotNull(mismatched.Telemetry.InitialFailureReason);

        // A matching contract with captured telemetry still passes. UserPayload alone is not
        // the grounding haystack: production keeps the model's wrapper out of evidence checks.
        var matched = await engine.ExecuteIslandAsync(new QualityIslandRequest(
            MissionId: Guid.NewGuid(),
            TemplateId: "tpl-offline",
            TargetModel: "offline",
            SystemPrompt: "Diagnose.",
            UserPayload: "disk at 94 percent",
            OperatorIdentity: "operator",
            RequiredSchema: SchemaContractType.StructuredDiagnosis,
            ExpectedTelemetryHaystack: "disk at 94 percent"));

        Assert.True(matched.IsSuccess);
    }

    // ------------------------------------------------------------------ unread exit conditions

    [Fact]
    public async Task ARemediationKilledAtItsTimeout_IsNotASuccess()
    {
        var ledger = new NullLedger();
        var engine = new SandboxedRemediationEngine(
            new NoJailManager(),
            new TimingOutLauncher(),
            ledger,
            _ => new FakeJobSandbox());

        var action = new RemediationAction(
            "fix-slow-repair",
            "sysops-disk-space",
            "Slow Repair",
            "A repair that outlives its budget.",
            RemediationRiskLevel.Safe,
            CanRollback: false,
            FixExecutable: "cmd.exe",
            FixArguments: "/c \"echo working\"",
            // Declared so the fix is run at all; the timeout means the probe is never reached.
            ValidationExecutable: "cmd.exe",
            ValidationArguments: "/c exit 0");

        var result = await engine.ExecuteFixAsync(action, "operator");

        // Exit code 0 from a process the job object killed says nothing about whether the repair
        // finished. Reading only the exit code reported a half-applied change as a completed one.
        Assert.False(result.Success);
        Assert.Contains("half-applied", result.ErrorMessage);
        Assert.Contains("REMEDIATION_FIX_FAILED", ledger.Actions);
        Assert.DoesNotContain("REMEDIATION_FIX_COMPLETED", ledger.Actions);
    }

    // ------------------------------------------------------------------ the mission engine

    private sealed class FakeJailManager : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult($@"C:\fake\jail\{missionId:N}");

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) =>
            Task.CompletedTask;

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    /// <summary>Returns a caller-chosen exit code, timeout flag and streams.</summary>
    private sealed class ScriptedSensor : IProcessLauncher
    {
        private readonly int _exitCode;
        private readonly bool _timedOut;
        private readonly string _stdout;
        private readonly string _stderr;

        public ScriptedSensor(int exitCode = 0, bool timedOut = false, string stdout = "", string stderr = "")
        {
            _exitCode = exitCode;
            _timedOut = timedOut;
            _stdout = stdout;
            _stderr = stderr;
        }

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            Task.FromResult(new ProcessExecutionResult(
                _exitCode, _stdout, _stderr, _timedOut, new JobResourceMetrics(1, 10, 10, 1024, 2048)));
    }

    private sealed class RecordingMemoryIndex : ISemanticMemoryIndex
    {
        public readonly List<string> Indexed = new();

        public Task IndexMissionDocumentAsync(Guid missionId, string templateId, string content,
            CancellationToken cancellationToken = default)
        {
            lock (Indexed) Indexed.Add(content);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<SemanticSearchResult>> SearchSimilarMissionsAsync(string query, int topK = 5,
            double minScore = 0.1, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SemanticSearchResult>>(Array.Empty<SemanticSearchResult>());
    }

    /// <summary>A quality island that returns whatever verdict the test asks for.</summary>
    private sealed class VerdictIsland : IIsolatedQualityIsland
    {
        private readonly bool _accepted;

        public VerdictIsland(bool accepted) => _accepted = accepted;

        public Task<QuadrantEvaluationResult> EvaluateArtifactAsync(
            string candidateContent, string? rawTelemetry, SchemaContractType contractType,
            QualityIslandOptions options, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<QualityIslandResult> ExecuteIslandAsync(
            QualityIslandRequest request,
            IProgress<string>? tokenProgress = null,
            IProgress<MissionChunk>? chunkProgress = null,
            CancellationToken cancellationToken = default)
        {
            var artifact = new CandidateArtifact(
                CandidateId: "verdict",
                ModelId: "verdict-model",
                RawContent: "analysis",
                SanitizedContent: "analysis",
                Evaluation: null!,
                LatencyMs: 1);

            return Task.FromResult(new QualityIslandResult(
                request.MissionId,
                request.TemplateId,
                IsSuccess: _accepted,
                OutputContent: "analysis",
                WinningArtifact: artifact,
                EvaluatedCohort: new[] { artifact },
                Telemetry: new EscalationTelemetry(
                    TotalCandidatesGenerated: 1,
                    EscalationCount: 0,
                    EscalationTriggered: false,
                    InitialFailureReason: _accepted ? null : "every candidate was rejected by the oracle",
                    EscalatedModelUsed: null,
                    TotalLatencyMs: 1),
                CompletedAtUtc: DateTime.UtcNow));
        }
    }

    private sealed class FakeJobSandboxForMission : IJobSandbox
    {
        public string JobName => "mission-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(SafeProcessHandle processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(0, 0, 0, 0, 0);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    /// <summary>Exit code 0 only, so 3 is outside the contract and the timeout flag is meaningful.</summary>
    private static SingleToolTemplate MissionTemplate() => new(
        "evidence-test",
        "Evidence Probe",
        "A sensor with a declared exit contract",
        "Net",
        "gemini-2.0-flash",
        new SingleToolDefinition("tool-e1", "probe", "cmd.exe", "/c probe", new[] { 0 }),
        new EgressRule("googleapis.com"),
        "Analyze output",
        new Dictionary<string, string>());

    private static async Task<List<MissionChunk>> RunMissionAsync(MissionExecutionEngine engine)
    {
        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteMissionAsync(
            MissionTemplate(), new Dictionary<string, string>(), "operator"))
        {
            chunks.Add(chunk);
        }
        return chunks;
    }

    [Fact]
    public async Task ASensorExitingOutsideItsContract_FailsTheMissionAndIndexesNothing()
    {
        var ledger = new NullLedger();
        var memory = new RecordingMemoryIndex();
        var engine = new MissionExecutionEngine(
            new FakeJailManager(),
            new ScriptedSensor(exitCode: 3, stdout: "partial telemetry"),
            new SilentModelClient(),
            ledger,
            _ => new FakeJobSandboxForMission(),
            semanticMemoryIndex: memory,
            qualityIsland: new VerdictIsland(accepted: true));

        var chunks = await RunMissionAsync(engine);

        // The exit code was logged and then ignored, so a dead sensor's stderr went to the model as
        // telemetry and came back as a completed diagnosis.
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.Completed);
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.AiToken);
        Assert.Contains("TOOL_EXECUTION_FAILED", ledger.Actions);
        Assert.Contains("MISSION_FAILED", ledger.Actions);
        Assert.Empty(memory.Indexed);
    }

    [Fact]
    public async Task ASensorKilledAtItsTimeout_FailsTheMission()
    {
        var ledger = new NullLedger();
        var engine = new MissionExecutionEngine(
            new FakeJailManager(),
            new ScriptedSensor(exitCode: 0, timedOut: true, stdout: "truncated telemetry"),
            new SilentModelClient(),
            ledger,
            _ => new FakeJobSandboxForMission(),
            qualityIsland: new VerdictIsland(accepted: true));

        var chunks = await RunMissionAsync(engine);

        // Exit code 0 from a process the job object killed is not a clean run.
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.Completed);
        Assert.Contains("TOOL_EXECUTION_FAILED", ledger.Actions);
    }

    [Fact]
    public async Task AnAnalysisTheQualityGateRejected_IsNotIndexedAsEvidence()
    {
        var ledger = new NullLedger();
        var memory = new RecordingMemoryIndex();
        var engine = new MissionExecutionEngine(
            new FakeJailManager(),
            new ScriptedSensor(exitCode: 0, stdout: "telemetry"),
            new SilentModelClient(),
            ledger,
            _ => new FakeJobSandboxForMission(),
            semanticMemoryIndex: memory,
            qualityIsland: new VerdictIsland(accepted: false));

        var chunks = await RunMissionAsync(engine);

        // A rejected diagnosis indexed here becomes prior art every later mission inherits, with
        // nothing in the recall snippet saying it was refused.
        Assert.Empty(memory.Indexed);
        Assert.Contains("AI_ANALYSIS_REJECTED", ledger.Actions);
        Assert.Contains("MISSION_FAILED", ledger.Actions);
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.Completed);
    }

    [Fact]
    public async Task AnAcceptedMission_StillCompletesAndIndexes()
    {
        var memory = new RecordingMemoryIndex();
        var engine = new MissionExecutionEngine(
            new FakeJailManager(),
            new ScriptedSensor(exitCode: 0, stdout: "telemetry"),
            new SilentModelClient(),
            new NullLedger(),
            _ => new FakeJobSandboxForMission(),
            semanticMemoryIndex: memory,
            qualityIsland: new VerdictIsland(accepted: true));

        var chunks = await RunMissionAsync(engine);

        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.Completed);
        Assert.Single(memory.Indexed);
    }

    // ------------------------------------------------------------------ output privacy

    private sealed class MarkerSanitizer : IDataLossPreventionSanitizer
    {
        public DlpSanitizationResult Sanitize(string input)
        {
            bool hit = input.Contains("SEED-SECRET");
            return new DlpSanitizationResult(
                input.Replace("SEED-SECRET", "[REDACTED]"),
                hit ? 1 : 0,
                hit ? new List<string> { "SeedMarker" } : new List<string>());
        }
    }

    [Fact]
    public async Task ASecretInSensorOutput_IsRedactedBeforeItLeavesTheEngine()
    {
        var engine = new MissionExecutionEngine(
            new FakeJailManager(),
            new ScriptedSensor(exitCode: 0, stdout: "token=SEED-SECRET", stderr: "also SEED-SECRET here"),
            new SilentModelClient(),
            new NullLedger(),
            _ => new FakeJobSandboxForMission(),
            dlpSanitizer: new MarkerSanitizer(),
            qualityIsland: new VerdictIsland(accepted: true));

        var chunks = await RunMissionAsync(engine);

        // The scrub used to run only before the model call, while the raw stdout and stderr chunks
        // had already left the engine - and the MCP server appends those very chunks to its tool
        // result, so an external agent client received what SPLAT withheld from its own model.
        var streamed = string.Join("\n", System.Linq.Enumerable.Select(chunks, c => c.Content));
        Assert.DoesNotContain("SEED-SECRET", streamed);
        Assert.Contains("[REDACTED]", streamed);
    }
}
