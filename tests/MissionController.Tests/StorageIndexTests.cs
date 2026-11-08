using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Data.Sqlite;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Retention;
using MissionController.Infrastructure.Data.Vector;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The statements that would otherwise read a whole table, planned against the schema the stores
/// create. Each is the stores' own text, not a copy, so a query rewritten into a shape its index
/// cannot serve fails here instead of slowing down as the ledger grows.
/// </summary>
public sealed class StorageIndexTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "splat-index-" + Guid.NewGuid().ToString("N"));

    public StorageIndexTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
        }
    }

    [Fact]
    public void EveryFilteredOrOrderedRead_RunsOffItsIndex_WithoutASort()
    {
        var context = new SqliteStorageContext(Path.Combine(_dir, "plans.db"));
        _ = new SqliteSemanticMemoryIndex(context);

        var expected = new (string Statement, string Index)[]
        {
            (SqliteChainedAuditLedger.MissionEntriesNewestFirst, "IDX_AuditLedger_Mission"),
            (SqliteChainedAuditLedger.MissionEntriesInChainOrder, "IDX_AuditLedger_Mission"),
            (SqliteChainedAuditLedger.LegacyUnredactedCount, "IDX_AuditLedger_Unredacted"),
            (SqliteChainedAuditLedger.RedactionStatement(apply: true), "IDX_AuditLedger_Unredacted"),
            (SqliteChainedAuditLedger.RedactionStatement(apply: false), "IDX_AuditLedger_Unredacted"),
            (DataRetentionService.ScrubStatement("RawOutput", apply: true), "IDX_Missions_Created"),
            (DataRetentionService.ScrubStatement("AiAnalysis", apply: false), "IDX_Missions_Created"),
            (DataRetentionService.SemanticDeleteStatement(apply: true), "IDX_Semantic_Timestamp"),
            (DataRetentionService.SemanticDeleteStatement(apply: false), "IDX_Semantic_Timestamp"),
            (SqliteSemanticMemoryIndex.RecentDocuments, "IDX_Semantic_Timestamp"),
        };

        using var conn = context.CreateConnection();
        var failures = expected
            .Select(e => (e.Statement, e.Index, Plan: Plan(conn, e.Statement)))
            .Where(e => !RunsOff(e.Plan, e.Index))
            .Select(e => $"expected {e.Index} and no sort or table scan:\n  {e.Statement.Trim()}\n  plan: {string.Join(" | ", e.Plan)}")
            .ToList();

        Assert.True(failures.Count == 0, string.Join("\n", failures));
    }

    [Fact]
    public void ADatabaseOlderThanTheRedactionColumns_OpensAndGainsItsIndexes()
    {
        string path = Path.Combine(_dir, "old.db");
        using (var old = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = path }.ToString()))
        {
            old.Open();
            using var cmd = old.CreateCommand();
            // The ledger before the redaction migration: the partial index's RedactedAtUtc does not
            // exist until SqliteStorageContext adds it, so indexing ahead of that fails the open.
            cmd.CommandText = @"
                CREATE TABLE AuditLedger (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT, TimestampUtc TEXT NOT NULL, MissionId TEXT NOT NULL,
                    TemplateId TEXT NOT NULL, Action TEXT NOT NULL, Details TEXT NOT NULL,
                    OperatorIdentity TEXT NOT NULL, PreviousHash TEXT NOT NULL, EntryHash TEXT NOT NULL);
                INSERT INTO AuditLedger (TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash)
                VALUES ('2026-01-01T00:00:00.0000000Z', 'm', 't', 'A', 'd', 'o', 'p', 'e');";
            cmd.ExecuteNonQuery();
        }
        SqliteConnection.ClearAllPools();

        var context = new SqliteStorageContext(path);

        using var conn = context.CreateConnection();
        Assert.Equal(
            new[] { "IDX_AuditLedger_Mission", "IDX_AuditLedger_Unredacted", "IDX_Missions_Created" },
            Strings(conn, "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'IDX%' ORDER BY name;"));
        Assert.Equal(new[] { "1" }, Strings(conn, "SELECT CAST(COUNT(*) AS TEXT) FROM AuditLedger;"));
    }

    private static IReadOnlyList<string> Plan(SqliteConnection conn, string statement)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "EXPLAIN QUERY PLAN " + statement;
        // Every parameter any of the statements names; SQLite ignores the ones a statement lacks.
        foreach (string name in new[] { "$mid", "$limit", "$cutoff", "$marker", "$now" })
        {
            cmd.Parameters.AddWithValue(name, "x");
        }

        var details = new List<string>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            details.Add(reader.GetString(reader.GetOrdinal("detail")));
        }

        return details;
    }

    // An index-order SCAN is fine (the newest-500 read stops at its LIMIT); a bare SCAN of the table
    // or a temp B-tree for the ORDER BY is what the index exists to prevent.
    private static bool RunsOff(IReadOnlyList<string> plan, string index) =>
        plan.Any(step => step.Contains($"INDEX {index}", StringComparison.Ordinal))
        && plan.All(step => !step.Contains("TEMP B-TREE", StringComparison.Ordinal))
        && plan.All(step => !step.StartsWith("SCAN ", StringComparison.Ordinal) || step.Contains(" USING ", StringComparison.Ordinal));

    private static IReadOnlyList<string> Strings(SqliteConnection conn, string query)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = query;
        var values = new List<string>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            values.Add(reader.GetString(0));
        }

        return values;
    }
}
