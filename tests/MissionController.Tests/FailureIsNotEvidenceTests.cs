using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland;
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
        public void AssignProcess(IntPtr processHandle) { }
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
    public async Task AScriptNodeWithNoSandbox_FailsUnlessSimulationWasAskedFor()
    {
        var graph = new WorkflowGraph(
            WorkflowId: "flow-no-sandbox",
            Name: "No Sandbox",
            Description: "A script node with neither launcher nor job object wired.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("probe", "Probe", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'hello'")
            },
            Edges: new List<WorkflowEdge>());

        // Default composition wires neither, and used to answer "[SIMULATED_SANDBOX] Executed
        // script: ..." with Success=true. Containment that was never applied is not a result.
        var strict = new WorkflowExecutionEngine();
        var refused = await strict.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.False(refused.Success);
        Assert.Contains("nothing was executed", refused.FailureReason);

        // The demo still exists; it just has to be asked for, and it says so in its own output.
        var demo = new WorkflowExecutionEngine(allowSimulatedExecution: true);
        var simulated = await demo.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(simulated.Success, simulated.FailureReason);
        Assert.Contains("SIMULATED_SANDBOX", simulated.NodeOutputs["probe"]);
    }

    [Fact]
    public async Task AWorkflowWhoseAnalysisRuns_StillSucceeds()
    {
        // The refusals above must not cost the working path. Same graph shape, services present.
        var engine = new WorkflowExecutionEngine(
            modelClient: new SilentModelClient(),
            allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-wired",
            Name: "Wired",
            Description: "Script then analysis, both serviced.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("probe", "Probe", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'hello'"),
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

        // And the contract it does satisfy still passes, so this is a real gate, not a blanket no.
        var matched = await engine.ExecuteIslandAsync(new QualityIslandRequest(
            MissionId: Guid.NewGuid(),
            TemplateId: "tpl-offline",
            TargetModel: "offline",
            SystemPrompt: "Diagnose.",
            UserPayload: "disk at 94 percent",
            OperatorIdentity: "operator",
            RequiredSchema: SchemaContractType.StructuredDiagnosis));

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
            FixArguments: "/c \"echo working\"");

        var result = await engine.ExecuteFixAsync(action, "operator");

        // Exit code 0 from a process the job object killed says nothing about whether the repair
        // finished. Reading only the exit code reported a half-applied change as a completed one.
        Assert.False(result.Success);
        Assert.Contains("half-applied", result.ErrorMessage);
        Assert.Contains("REMEDIATION_FIX_FAILED", ledger.Actions);
        Assert.DoesNotContain("REMEDIATION_FIX_COMPLETED", ledger.Actions);
    }
}
