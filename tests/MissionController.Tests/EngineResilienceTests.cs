using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Failure-path guarantees for the mission engine. A mission that dies must (1) never leak its
/// NT ACL jail directory, (2) seal a MISSION_FAILED row into the ledger, and (3) end the chunk
/// stream with readable operator messaging instead of an unhandled exception - including when
/// the consumer abandons the stream mid-iteration.
/// </summary>
public class EngineResilienceTests
{
    // ---------------------------------------------------------------- fakes

    private sealed class FakeJailManager : IJailManager
    {
        public int ProvisionCalls;
        public int DrainCalls;

        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default)
        {
            ProvisionCalls++;
            return Task.FromResult($@"C:\fake\jail\{missionId:N}");
        }

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200)
        {
            Interlocked.Increment(ref DrainCalls);
            return Task.CompletedTask;
        }

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class ThrowingProcessLauncher : IProcessLauncher
    {
        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            throw new InvalidOperationException("CreateProcessW failed (Win32 error 5: access denied)");
    }

    private sealed class HappyProcessLauncher : IProcessLauncher
    {
        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            Task.FromResult(new ProcessExecutionResult(
                0, "sensor output", "", false, new JobResourceMetrics(1, 10, 10, 1024, 2048)));
    }

    private sealed class FakeJobSandbox : IJobSandbox
    {
        public string JobName => "fake-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(IntPtr processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(0, 0, 0, 0, 0);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    private sealed class InMemoryAuditLedger : IAuditLedger
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

    private sealed class SimulatedModelClient : IModelStreamClient
    {
        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(false, "Fake", requestedModel, "no key"));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(string requestedModel, string systemPrompt,
            string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return "simulated analysis";
        }
    }

    private static SingleToolTemplate BuildTemplate() => new(
        "resilience-test",
        "Resilience Probe",
        "Engine failure-path test",
        "Net",
        "gemini-2.0-flash",
        new SingleToolDefinition("tool-r1", "ping", "cmd.exe", "/c ping 127.0.0.1", new[] { 0 }),
        new EgressRule("googleapis.com"),
        "Analyze output",
        new Dictionary<string, string>());

    private static MissionExecutionEngine BuildEngine(
        FakeJailManager jail, IProcessLauncher launcher, InMemoryAuditLedger ledger) =>
        new(jail, launcher, new SimulatedModelClient(), ledger, _ => new FakeJobSandbox());

    // ---------------------------------------------------------------- guarantees

    [Fact]
    public async Task LaunchFailure_SurfacesReadableChunks_SealsAudit_AndDrainsJail()
    {
        var jail = new FakeJailManager();
        var ledger = new InMemoryAuditLedger();
        var engine = BuildEngine(jail, new ThrowingProcessLauncher(), ledger);

        var chunks = new List<MissionChunk>();
        // Must complete WITHOUT an exception escaping the stream.
        await foreach (var chunk in engine.ExecuteMissionAsync(BuildTemplate(), new Dictionary<string, string>(), "op"))
            chunks.Add(chunk);

        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.Stderr && c.Content.Contains("MISSION FAILED"));
        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.StatusChange && c.Content.Contains("Mission aborted"));
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.Completed);
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.AiToken);
        Assert.Contains("MISSION_FAILED", ledger.Actions);
        Assert.Equal(1, jail.DrainCalls);
    }

    [Fact]
    public async Task AbandonedStream_StillDrainsJail()
    {
        var jail = new FakeJailManager();
        var engine = BuildEngine(jail, new HappyProcessLauncher(), new InMemoryAuditLedger());

        await foreach (var chunk in engine.ExecuteMissionAsync(BuildTemplate(), new Dictionary<string, string>(), "op"))
        {
            // Bail as soon as the jail exists - simulates the operator closing the mission view.
            if (chunk.Content.Contains("Jail established"))
                break;
        }

        Assert.Equal(1, jail.ProvisionCalls);
        Assert.Equal(1, jail.DrainCalls);
    }

    [Fact]
    public async Task HappyPath_DrainsJailExactlyOnce_AndCompletes()
    {
        var jail = new FakeJailManager();
        var engine = BuildEngine(jail, new HappyProcessLauncher(), new InMemoryAuditLedger());

        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteMissionAsync(BuildTemplate(), new Dictionary<string, string>(), "op"))
            chunks.Add(chunk);

        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.Completed);
        // No live key in the simulated client => the honesty banner must be present.
        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.SimulatedNotice);
        Assert.Equal(1, jail.DrainCalls);
    }
}
