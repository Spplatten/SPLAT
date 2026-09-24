using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Win32.SafeHandles;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Retention;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The Missions table was declared by the schema and written by nothing, while DataRetentionService
/// scrubbed three of its columns and reported the count. A sweep over an empty table returns the
/// same zeroes a sweep over fully-scrubbed data does, so the retention report said "clean" whether
/// or not retention was doing anything.
///
/// DataRetentionTests already proves the sweep erases a row that exists. What was missing is the
/// other half - that a mission produces one. These run the real engine into a real SQLite file and
/// then sweep it, so the two halves are joined by the code rather than by a hand-written INSERT.
/// </summary>
public sealed class MissionHistoryStoreTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"splat-history-{Guid.NewGuid():N}.db");
    private readonly SqliteStorageContext _context;

    public MissionHistoryStoreTests() => _context = new SqliteStorageContext(_dbPath);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var path in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { /* temp file */ }
        }
    }

    // ---------------------------------------------------------------- fakes

    private sealed class FakeJailManager : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult($@"C:\fake\jail\{missionId:N}");

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) =>
            Task.CompletedTask;

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class StubProcessLauncher : IProcessLauncher
    {
        private readonly string _stdout;
        private readonly int _exitCode;

        public StubProcessLauncher(string stdout, int exitCode = 0)
        {
            _stdout = stdout;
            _exitCode = exitCode;
        }

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            Task.FromResult(new ProcessExecutionResult(
                _exitCode, _stdout, "", false, new JobResourceMetrics(1, 10, 10, 1024, 2048)));
    }

    private sealed class FakeJobSandbox : IJobSandbox
    {
        public string JobName => "splat-history-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(SafeProcessHandle processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(0, 0, 0, 0, 0);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    /// <summary>
    /// Answers with a diagnosis the quality gate accepts, whose finding quotes the telemetry it was
    /// handed. Free prose ends every mission in AnalysisRejected, and an ungrounded finding ends it
    /// the same way - either would have made the completed-mission test assert a state other than
    /// the one it is named for.
    /// </summary>
    private sealed class FixedModelClient : IModelStreamClient
    {
        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, "Fake", requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(string requestedModel, string systemPrompt,
            string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();

            // The payload arrives boundary-delimited, so the first line inside the markers is the
            // telemetry - which is what a grounded finding has to quote.
            string quoted = userPrompt
                .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                .Select(line => line.Trim())
                .FirstOrDefault(line => line.Length > 0
                    && !line.StartsWith("[BEGIN", StringComparison.Ordinal)
                    && !line.StartsWith("[END", StringComparison.Ordinal))
                ?? "no telemetry";

            yield return $$"""
                The sensor answered and its output is quoted below.
                ```json
                {
                  "status": "Healthy",
                  "headline": "Sensor returned nominal output",
                  "findings": ["The tool reported: {{quoted.Replace("\"", "'")}}"],
                  "recommendedActions": ["No remediation required"]
                }
                ```
                """;
        }
    }

    private static SingleToolTemplate BuildTemplate() => new(
        "history-test",
        "Atlas-Net",
        "History probe",
        "Net",
        "gemini-2.0-flash",
        new SingleToolDefinition("tool-h1", "ping", "cmd.exe", "/c ping 127.0.0.1", new[] { 0 }),
        new EgressRule("googleapis.com"),
        "Analyze output",
        new Dictionary<string, string>());

    private async Task<Guid> RunMissionAsync(string stdout, int exitCode = 0)
    {
        var engine = new MissionExecutionEngine(
            new FakeJailManager(), new StubProcessLauncher(stdout, exitCode), new FixedModelClient(),
            new SqliteChainedAuditLedger(_context), _ => new FakeJobSandbox(),
            missionHistory: new SqliteMissionHistoryStore(_context));

        Guid missionId = Guid.Empty;
        await foreach (var chunk in engine.ExecuteMissionAsync(
            BuildTemplate(), new Dictionary<string, string> { ["Host"] = "WS-04" }, "operator"))
        {
            missionId = chunk.MissionId;
        }

        return missionId;
    }

    private string? ReadColumn(Guid missionId, string column)
    {
        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {column} FROM Missions WHERE MissionId = $id;";
        cmd.Parameters.AddWithValue("$id", missionId.ToString("D"));
        return cmd.ExecuteScalar()?.ToString();
    }

    // ---------------------------------------------------------------- guarantees

    [Fact]
    public async Task ACompletedMission_LeavesOneRow()
    {
        Guid missionId = await RunMissionAsync("Reply from 127.0.0.1: bytes=32 time<1ms");

        Assert.Equal("Completed", ReadColumn(missionId, "Status"));
        Assert.Equal("history-test", ReadColumn(missionId, "TemplateId"));
        Assert.Equal("operator", ReadColumn(missionId, "InitiatedBy"));
        Assert.Contains("Reply from 127.0.0.1", ReadColumn(missionId, "RawOutput"));
        Assert.Contains("WS-04", ReadColumn(missionId, "InputParametersJson"));
        Assert.Equal("0", ReadColumn(missionId, "ExitCode"));
        Assert.NotNull(ReadColumn(missionId, "CompletedAtUtc"));
    }

    /// <summary>
    /// The row is written from the finally, so the mission that failed - the one whose history an
    /// investigator actually wants - is recorded on the same path as the one that worked.
    /// </summary>
    [Fact]
    public async Task AFailedMission_LeavesOneToo()
    {
        Guid missionId = await RunMissionAsync("ping: transmit failed", exitCode: 1);

        Assert.Equal("ToolFailed", ReadColumn(missionId, "Status"));
        Assert.Equal("1", ReadColumn(missionId, "ExitCode"));
        Assert.Contains("transmit failed", ReadColumn(missionId, "RawOutput"));
    }

    /// <summary>
    /// The join the whole change is for: run a mission, sweep, and see a non-zero count. Before the
    /// store existed this assertion could only be made about a row a test had inserted itself.
    /// </summary>
    [Fact]
    public async Task TheRetentionSweep_NowHasAMissionToScrub()
    {
        Guid missionId = await RunMissionAsync("SID S-1-5-21-1004336348 jsmith stale telemetry");

        // Backdated: the sweep erases by age, and a mission that just ran is inside every window.
        using (var conn = _context.CreateConnection())
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = "UPDATE Missions SET CreatedAtUtc = $old WHERE MissionId = $id;";
            cmd.Parameters.AddWithValue("$old", DateTime.UtcNow.AddDays(-30).ToString("O"));
            cmd.Parameters.AddWithValue("$id", missionId.ToString("D"));
            cmd.ExecuteNonQuery();
        }

        var retention = new DataRetentionService(_context, new SqliteChainedAuditLedger(_context));
        var result = await retention.SweepAsync(new RetentionPolicy { VacuumAfterSweep = false });

        Assert.Equal(1, result.RawOutputsScrubbed);
        Assert.Equal(string.Empty, ReadColumn(missionId, "RawOutput"));
        // The skeleton survives, so the mission is still accountable after its payload is gone.
        Assert.Equal("history-test", ReadColumn(missionId, "TemplateId"));
    }

    /// <summary>Nothing regresses for a host that has not wired one: the store stays optional.</summary>
    [Fact]
    public async Task WithoutTheStore_TheMissionStillRuns_AndWritesNoRow()
    {
        var engine = new MissionExecutionEngine(
            new FakeJailManager(), new StubProcessLauncher("ok"), new FixedModelClient(),
            new SqliteChainedAuditLedger(_context), _ => new FakeJobSandbox());

        Guid missionId = Guid.Empty;
        await foreach (var chunk in engine.ExecuteMissionAsync(
            BuildTemplate(), new Dictionary<string, string>(), "operator"))
        {
            missionId = chunk.MissionId;
        }

        Assert.NotEqual(Guid.Empty, missionId);
        Assert.Null(ReadColumn(missionId, "Status"));
    }
}
