using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Retention;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Layer 10 retention. The property under test throughout: purged data must be genuinely gone, and
/// the audit chain must still verify afterwards. A sweep that breaks Layer 7 is worse than no sweep,
/// because a broken chain is indistinguishable from tampering.
/// </summary>
public class DataRetentionTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteStorageContext _context;
    private readonly SqliteChainedAuditLedger _ledger;
    private readonly DataRetentionService _retention;

    public DataRetentionTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"splat-retention-{Guid.NewGuid():N}.db");
        _context = new SqliteStorageContext(_dbPath);
        _ledger = new SqliteChainedAuditLedger(_context);
        _retention = new DataRetentionService(_context, _ledger);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        foreach (var path in new[] { _dbPath, _dbPath + "-wal", _dbPath + "-shm" })
        {
            try { if (File.Exists(path)) File.Delete(path); } catch { /* temp file */ }
        }
    }

    private void InsertMission(Guid missionId, DateTime createdUtc, string rawOutput)
    {
        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO Missions (MissionId, TemplateId, Status, CreatedAtUtc, JailDirectory, InitiatedBy, InputParametersJson, RawOutput, AiAnalysis)
            VALUES ($id, 'tpl-1', 'Completed', $created, 'C:\jail', 'operator', '{""host"":""WS-04""}', $raw, 'analysis text');";
        cmd.Parameters.AddWithValue("$id", missionId.ToString("D"));
        cmd.Parameters.AddWithValue("$created", createdUtc.ToString("O"));
        cmd.Parameters.AddWithValue("$raw", rawOutput);
        cmd.ExecuteNonQuery();
    }

    private string? ReadMissionColumn(Guid missionId, string column)
    {
        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT {column} FROM Missions WHERE MissionId = $id;";
        cmd.Parameters.AddWithValue("$id", missionId.ToString("D"));
        return cmd.ExecuteScalar() as string;
    }

    [Fact]
    public async Task Sweep_ScrubsRawTelemetryPastWindow_ButKeepsMissionSkeleton()
    {
        var stale = Guid.NewGuid();
        InsertMission(stale, DateTime.UtcNow.AddDays(-30), "SID S-1-5-21-1004336348 jsmith PasswordRequired False");

        var result = await _retention.SweepAsync(new RetentionPolicy { VacuumAfterSweep = false });

        Assert.Equal(1, result.RawOutputsScrubbed);
        Assert.Equal(string.Empty, ReadMissionColumn(stale, "RawOutput"));

        // Operational metadata is deliberately retained - it carries no secrets and losing it would
        // erase the record that the mission ever ran.
        Assert.Equal("tpl-1", ReadMissionColumn(stale, "TemplateId"));
        Assert.Equal("Completed", ReadMissionColumn(stale, "Status"));
    }

    [Fact]
    public async Task Sweep_LeavesRecentTelemetryIntact()
    {
        var fresh = Guid.NewGuid();
        InsertMission(fresh, DateTime.UtcNow.AddHours(-2), "recent sensor output");

        var result = await _retention.SweepAsync(new RetentionPolicy { VacuumAfterSweep = false });

        Assert.Equal(0, result.RawOutputsScrubbed);
        Assert.Equal("recent sensor output", ReadMissionColumn(fresh, "RawOutput"));
    }

    [Fact]
    public async Task Sweep_HonoursPerColumnWindows()
    {
        var mission = Guid.NewGuid();
        InsertMission(mission, DateTime.UtcNow.AddDays(-14), "raw dump");

        // 14 days old: past the 7-day raw window, inside the 30-day analysis window.
        await _retention.SweepAsync(new RetentionPolicy { VacuumAfterSweep = false });

        Assert.Equal(string.Empty, ReadMissionColumn(mission, "RawOutput"));
        Assert.Equal("analysis text", ReadMissionColumn(mission, "AiAnalysis"));
    }

    [Fact]
    public async Task Sweep_IsIdempotent_AndDoesNotInflateCounts()
    {
        InsertMission(Guid.NewGuid(), DateTime.UtcNow.AddDays(-30), "stale dump");

        var first = await _retention.SweepAsync(new RetentionPolicy { VacuumAfterSweep = false });
        var second = await _retention.SweepAsync(new RetentionPolicy { VacuumAfterSweep = false });

        Assert.Equal(1, first.RawOutputsScrubbed);
        Assert.Equal(0, second.RawOutputsScrubbed);
    }

    [Fact]
    public async Task DisabledPolicy_PurgesNothing()
    {
        var mission = Guid.NewGuid();
        InsertMission(mission, DateTime.UtcNow.AddDays(-3650), "ancient but retained");

        var result = await _retention.SweepAsync(RetentionPolicy.Disabled);

        Assert.Equal(0, result.TotalErased);
        Assert.Equal("ancient but retained", ReadMissionColumn(mission, "RawOutput"));
    }

    [Fact]
    public async Task LedgerRedaction_ErasesPayload_ButChainStillVerifies()
    {
        var missionId = Guid.NewGuid();
        await _ledger.AppendLogAsync(missionId, "tpl-1", "MISSION_STARTED", "operator jsmith on WS-04", "jsmith");
        await _ledger.AppendLogAsync(missionId, "tpl-1", "MISSION_COMPLETED", "exit code 0", "jsmith");

        Assert.True(await _ledger.VerifyLedgerIntegrityAsync());

        var redaction = await _ledger.RedactDetailsOlderThanAsync(DateTime.UtcNow.AddMinutes(1));

        Assert.Equal(2, redaction.EntriesRedacted);
        Assert.Equal(0, redaction.LegacyEntriesSkipped);

        // The whole point: payload gone, chain still provably intact.
        Assert.True(await _ledger.VerifyLedgerIntegrityAsync());

        var entries = await _ledger.GetAuditLogsAsync(missionId);
        Assert.All(entries, e => Assert.DoesNotContain("jsmith on WS-04", e.Details));
        Assert.All(entries, e => Assert.Contains("REDACTED", e.Details));
    }

    [Fact]
    public async Task LedgerRedaction_DestroysSaltSoCommitmentIsNotBruteForceable()
    {
        await _ledger.AppendLogAsync(Guid.NewGuid(), "tpl-1", "ACTION", "low entropy detail", "operator");
        await _ledger.RedactDetailsOlderThanAsync(DateTime.UtcNow.AddMinutes(1));

        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT DetailsSalt, DetailsCommitment FROM AuditLedger LIMIT 1;";
        using var reader = cmd.ExecuteReader();
        Assert.True(reader.Read());

        // Salt destroyed, commitment retained. Without the salt an attacker cannot confirm a guessed
        // plaintext against the surviving digest, which is what makes this erasure rather than hashing.
        Assert.True(reader.IsDBNull(0));
        Assert.False(reader.IsDBNull(1));
    }

    [Fact]
    public async Task LedgerRedaction_SkipsLegacyRowsRatherThanBreakingTheChain()
    {
        // Simulate a pre-migration entry: HashVersion 1, chain hash computed over plaintext.
        const string genesis = "0000000000000000000000000000000000000000000000000000000000000000";
        string ts = DateTime.UtcNow.AddDays(-200).ToString("O");
        string mid = Guid.NewGuid().ToString("D");
        string legacyHash = SqliteChainedAuditLedger.ComputeEntryHash(
            genesis, ts, mid, "tpl-legacy", "LEGACY_ACTION", "legacy plaintext detail", "operator");

        using (var conn = _context.CreateConnection())
        using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT INTO AuditLedger (TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, HashVersion)
                VALUES ($ts, $mid, 'tpl-legacy', 'LEGACY_ACTION', 'legacy plaintext detail', 'operator', $prev, $entry, 1);";
            cmd.Parameters.AddWithValue("$ts", ts);
            cmd.Parameters.AddWithValue("$mid", mid);
            cmd.Parameters.AddWithValue("$prev", genesis);
            cmd.Parameters.AddWithValue("$entry", legacyHash);
            cmd.ExecuteNonQuery();
        }

        Assert.True(await _ledger.VerifyLedgerIntegrityAsync());

        var redaction = await _ledger.RedactDetailsOlderThanAsync(DateTime.UtcNow.AddMinutes(1));

        Assert.Equal(0, redaction.EntriesRedacted);
        Assert.Equal(1, redaction.LegacyEntriesSkipped);

        // Untouched and therefore still verifiable - a broken chain reads as tampering, which is a
        // worse compliance outcome than retaining the text.
        Assert.True(await _ledger.VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task LedgerVerification_StillCatchesRealTampering_AfterRedactionSupport()
    {
        await _ledger.AppendLogAsync(Guid.NewGuid(), "tpl-1", "ACTION", "original detail", "operator");

        using (var conn = _context.CreateConnection())
        using (var cmd = conn.CreateCommand())
        {
            // Edit the payload without touching the commitment: this is forgery, not redaction.
            cmd.CommandText = "UPDATE AuditLedger SET DetailsCommitment = $bogus WHERE Id = 1;";
            cmd.Parameters.AddWithValue("$bogus", new string('a', 64));
            cmd.ExecuteNonQuery();
        }

        Assert.False(await _ledger.VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task Sweep_RecordsWhatItErased()
    {
        InsertMission(Guid.NewGuid(), DateTime.UtcNow.AddDays(-60), "stale");
        await _ledger.AppendLogAsync(Guid.NewGuid(), "tpl-1", "ACTION", "detail", "operator");

        var result = await _retention.SweepAsync(
            new RetentionPolicy { AuditDetailRetention = TimeSpan.Zero, VacuumAfterSweep = false });

        Assert.True(result.TotalErased > 0);
        Assert.Contains("Retention sweep", result.Summary);
        Assert.Contains("audit payloads redacted", result.Summary);
    }

    [Fact]
    public async Task Sweep_WithVacuum_LeavesDatabaseUsable()
    {
        var mission = Guid.NewGuid();
        InsertMission(mission, DateTime.UtcNow.AddDays(-30), new string('x', 4096));

        await _retention.SweepAsync(new RetentionPolicy { VacuumAfterSweep = true });

        // A vacuum that corrupts or locks the file would fail here.
        Assert.Equal(string.Empty, ReadMissionColumn(mission, "RawOutput"));
        Assert.Equal("tpl-1", ReadMissionColumn(mission, "TemplateId"));
    }

    [Fact]
    public void SecureDeletePragma_IsEnabledOnEveryConnection()
    {
        // Without this, "deleted" telemetry survives verbatim in SQLite free pages.
        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA secure_delete;";
        Assert.Equal(1L, Convert.ToInt64(cmd.ExecuteScalar()));
    }
}
