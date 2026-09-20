using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland;
using MissionController.Core.QualityIsland.Contracts;
using MissionController.Infrastructure.Network.Dlp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The mission engine seals what it observed as the mission's last ledger row, on every path it can
/// end by. A run record is assembled from that row, so a path that seals nothing is a mission no
/// record can be made for.
/// </summary>
public class MissionRunFactsTests
{
    [Fact]
    public async Task ACompletedMission_SealsItsFactsAsItsLastRow()
    {
        var ledger = new RecordingLedger();
        var engine = NewEngine(ledger, new ScriptedSensor(exitCode: 0, stdout: "telemetry"));

        await RunAsync(engine);

        Assert.Equal(MissionRunFacts.LedgerAction, ledger.Rows[^1].Action);
        var facts = ledger.Facts();
        Assert.Equal("Completed", facts.ExecutionState);
        Assert.Equal(0, facts.ExitCode);
        Assert.True(facts.ExitContractMet);
        Assert.Equal("Admitted", facts.Admission);
        Assert.Equal("cmd.exe", facts.ExecutablePath);
        Assert.StartsWith("sha256:", facts.TemplateSha256);
        Assert.True(facts.QualityAccepted);
        // No model was connected in this test, and the record says the analysis was simulated rather
        // than naming a model that never answered.
        Assert.StartsWith("none: a local simulation", facts.Model);
        Assert.NotNull(facts.EndedAtUtc);
    }

    [Fact]
    public async Task TheFacts_CarryWhatTheKernelObjectsReadBack()
    {
        var ledger = new RecordingLedger();
        var engine = NewEngine(
            ledger,
            new ScriptedSensor(exitCode: 0, controls: new[] { "job:mission-job", "token:integrity=Low", "token:appcontainer=0-capabilities" }));

        await RunAsync(engine);
        var facts = ledger.Facts();

        Assert.Equal(50, facts.LimitsReadBack!.CpuRatePercent);
        Assert.Equal(256L * 1024 * 1024, facts.LimitsReadBack!.JobMemoryLimitBytes);
        Assert.True(facts.LimitsReadBack!.KillOnJobClose);
        Assert.Contains("token:appcontainer=0-capabilities", facts.AppliedControls);
        Assert.Contains("acl-jail:read-back", facts.AppliedControls);
        Assert.Equal("mission-job", facts.JobName);
        // The teardown order is the one the engine performed, not a list of intentions.
        Assert.Equal(
            new[] { "job: no process left running", "job: closed, which kills anything left in it", "jail: drained and removed" },
            facts.TeardownOrder);
        Assert.Equal(0u, facts.ProcessesLeftAtTeardown);
        Assert.True(facts.JailRemoved);
    }

    [Fact]
    public async Task AToolOutsideItsExitContract_SealsThatItFailed()
    {
        var ledger = new RecordingLedger();
        var engine = NewEngine(ledger, new ScriptedSensor(exitCode: 3, stdout: "partial"));

        await RunAsync(engine);
        var facts = ledger.Facts();

        Assert.Equal("ToolFailed", facts.ExecutionState);
        Assert.Equal(3, facts.ExitCode);
        Assert.False(facts.ExitContractMet);
        Assert.Equal(new[] { 0 }, facts.AllowedExitCodes);
        Assert.Null(facts.QualityAccepted);
    }

    [Fact]
    public async Task ALaunchThatCouldNotBeConfined_SealsThatNothingRan()
    {
        var ledger = new RecordingLedger();
        var engine = NewEngine(ledger, new RefusingLauncher());

        await RunAsync(engine);
        var facts = ledger.Facts();

        Assert.Equal("LaunchFailed", facts.ExecutionState);
        Assert.Null(facts.ExitCode);
        Assert.Contains("could not be launched", facts.TerminalReason);
        // Provisioned before the launch, so teardown still has something to undo.
        Assert.Contains("jail: drained and removed", facts.TeardownOrder);
    }

    [Fact]
    public async Task AMissionRefusedAtTheBinder_SealsTheRefusal_WithNothingProvisioned()
    {
        var ledger = new RecordingLedger();
        var engine = NewEngine(ledger, new ScriptedSensor(exitCode: 0));

        await RunAsync(engine, new Dictionary<string, string> { ["Target"] = "no spaces & pipes | allowed" });
        var facts = ledger.Facts();

        Assert.Equal("Refused", facts.ExecutionState);
        Assert.StartsWith("Refused:", facts.Admission);
        Assert.Null(facts.WorkspacePath);
        Assert.Null(facts.JobName);
        Assert.Empty(facts.TeardownOrder);
        Assert.Contains("MISSION_BLOCKED_PARAMETER_REJECTED", ledger.Rows.Select(r => r.Action));
    }

    [Fact]
    public async Task ACancelledMission_SealsThatItWasCancelled()
    {
        var ledger = new RecordingLedger();
        var engine = NewEngine(ledger, new CancellingLauncher());
        using var cancellation = new CancellationTokenSource();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
        {
            await foreach (var _ in engine.ExecuteMissionAsync(Template(), new Dictionary<string, string>(), "windows:operator", cancellation.Token))
            {
                cancellation.Cancel();
            }
        });

        var facts = ledger.Facts();
        Assert.Equal("Cancelled", facts.ExecutionState);
        Assert.Contains("cancelled by the caller", facts.TerminalReason);
    }

    [Fact]
    public async Task TheSealedCommandLine_IsScrubbedLikeTheToolsOutput()
    {
        var ledger = new RecordingLedger();
        var engine = NewEngine(ledger, new ScriptedSensor(exitCode: 0), dlp: new RegexDataLossPreventionSanitizer());

        await RunAsync(engine, new Dictionary<string, string> { ["Target"] = "AKIAIOSFODNN7EXAMPLE" });
        var facts = ledger.Facts();

        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", facts.CommandLine);
        Assert.Contains("[REDACTED_AWS_KEY]", facts.CommandLine);
    }

    // ---------------------------------------------------------------- the engine and its stand-ins

    private static MissionExecutionEngine NewEngine(
        RecordingLedger ledger,
        IProcessLauncher launcher,
        IDataLossPreventionSanitizer? dlp = null) =>
        new(
            new ReadableJailManager(),
            launcher,
            new SimulatedModelClient(),
            ledger,
            _ => new ReadableJobSandbox(),
            dlpSanitizer: dlp,
            qualityIsland: new AcceptingIsland());

    private static SingleToolTemplate Template() => new(
        "facts-test",
        "Facts Probe",
        "A sensor whose facts are sealed",
        "Net",
        "gemini-2.0-flash",
        new SingleToolDefinition("tool-f1", "probe", "cmd.exe", "/c echo {Target}", new[] { 0 }, TimeoutSeconds: 60, MaxMemoryBytes: 256 * 1024 * 1024, MaxCpuPercent: 50),
        new EgressRule("googleapis.com"),
        "Analyze output",
        new[] { new TemplateParameterField("Target", "Target", "What to echo", "localhost") });

    private static async Task RunAsync(MissionExecutionEngine engine, IReadOnlyDictionary<string, string>? parameters = null)
    {
        await foreach (var _ in engine.ExecuteMissionAsync(
            Template(), parameters ?? new Dictionary<string, string>(), "windows:operator [S-1-5-21-1] via console"))
        {
        }
    }

    private sealed class RecordingLedger : IAuditLedger
    {
        public readonly List<(string Action, string Details)> Rows = new();

        public MissionRunFacts Facts()
        {
            var row = Rows.LastOrDefault(r => r.Action == MissionRunFacts.LedgerAction);
            Assert.True(row.Action == MissionRunFacts.LedgerAction, "the mission sealed no facts");
            return JsonSerializer.Deserialize<MissionRunFacts>(row.Details)!;
        }

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (Rows) Rows.Add((action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }

    private sealed class ReadableJailManager : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult($@"C:\fake\jail\{missionId:N}");

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) => Task.CompletedTask;

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

        public string? DescribeJail(string jailPath) => "acl-jail:read-back";
    }

    private sealed class ReadableJobSandbox : IJobSandbox
    {
        public string JobName => "mission-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(SafeProcessHandle processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(0, 0, 0, 0, ActiveProcessCount: 0);
        public JobLimitsReadback ReadBackLimits() => new(256L * 1024 * 1024, 256L * 1024 * 1024, 50, 32, true);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    private sealed class ScriptedSensor : IProcessLauncher
    {
        private readonly int _exitCode;
        private readonly string _stdout;
        private readonly IReadOnlyList<string>? _controls;

        public ScriptedSensor(int exitCode = 0, string stdout = "", IReadOnlyList<string>? controls = null)
        {
            _exitCode = exitCode;
            _stdout = stdout;
            _controls = controls;
        }

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            Task.FromResult(new ProcessExecutionResult(
                _exitCode, _stdout, string.Empty, false, JobResourceMetrics.Unavailable, AppliedControls: _controls));
    }

    private sealed class RefusingLauncher : IProcessLauncher
    {
        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            throw new System.Security.SecurityException("the privilege drop could not be applied");
    }

    private sealed class CancellingLauncher : IProcessLauncher
    {
        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            throw new OperationCanceledException();
    }

    private sealed class SimulatedModelClient : IModelStreamClient
    {
        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(false, "Simulator", "none", "no key is connected in this test"));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel, string systemPrompt, string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return "simulated analysis";
        }
    }

    private sealed class AcceptingIsland : IIsolatedQualityIsland
    {
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
                CandidateId: "facts",
                ModelId: "facts-model",
                RawContent: "analysis",
                SanitizedContent: "analysis",
                Evaluation: null!,
                LatencyMs: 1);

            return Task.FromResult(new QualityIslandResult(
                request.MissionId,
                request.TemplateId,
                IsSuccess: true,
                OutputContent: "analysis",
                WinningArtifact: artifact,
                EvaluatedCohort: new[] { artifact },
                Telemetry: new EscalationTelemetry(
                    TotalCandidatesGenerated: 1,
                    EscalationCount: 0,
                    EscalationTriggered: false,
                    InitialFailureReason: null,
                    EscalatedModelUsed: null,
                    TotalLatencyMs: 1),
                CompletedAtUtc: DateTime.UtcNow));
        }
    }
}
