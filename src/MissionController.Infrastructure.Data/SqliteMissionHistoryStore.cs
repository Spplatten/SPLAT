using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Data;

/// <summary>
/// Writes the <c>Missions</c> row <see cref="SqliteStorageContext"/> has always declared.
///
/// One write, at the end, from <c>SealRunFactsAsync</c> - the same place the ledger row is sealed,
/// so a refused, cancelled or faulted mission lands here exactly like a completed one. A row
/// inserted at the start and updated at the end would need the engine to succeed twice to leave a
/// consistent record, and the mission that most needs a history entry is the one that did not.
/// </summary>
public sealed class SqliteMissionHistoryStore : IMissionHistoryStore
{
    private readonly SqliteStorageContext _context;

    public SqliteMissionHistoryStore(SqliteStorageContext context) => _context = context;

    public async Task RecordAsync(MissionHistoryRecord record, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(record);

        await using var conn = _context.CreateConnection();
        await conn.OpenAsync(cancellationToken);
        await using var cmd = conn.CreateCommand();

        // INSERT OR REPLACE, not INSERT: a mission id is a fresh Guid per run, so a collision means
        // a retry of the same run rather than a second mission, and the later facts are the true
        // ones. It also keeps this callable twice without an exception reaching a finally block.
        cmd.CommandText = @"
            INSERT OR REPLACE INTO Missions (
                MissionId, TemplateId, Status, CreatedAtUtc, StartedAtUtc, CompletedAtUtc,
                JailDirectory, JobId, InitiatedBy, InputParametersJson, RawOutput, AiAnalysis,
                ExitCode, ErrorMessage)
            VALUES (
                $missionId, $templateId, $status, $createdAt, $startedAt, $completedAt,
                $jail, $jobId, $initiatedBy, $parameters, $rawOutput, $aiAnalysis,
                $exitCode, $errorMessage);";

        cmd.Parameters.AddWithValue("$missionId", record.MissionId.ToString());
        cmd.Parameters.AddWithValue("$templateId", record.TemplateId);
        cmd.Parameters.AddWithValue("$status", record.Status);
        cmd.Parameters.AddWithValue("$createdAt", record.CreatedAtUtc.UtcDateTime.ToString("O"));
        cmd.Parameters.AddWithValue("$startedAt", Nullable(record.StartedAtUtc?.UtcDateTime.ToString("O")));
        cmd.Parameters.AddWithValue("$completedAt", Nullable(record.CompletedAtUtc?.UtcDateTime.ToString("O")));
        cmd.Parameters.AddWithValue("$jail", record.JailDirectory);
        cmd.Parameters.AddWithValue("$jobId", Nullable(record.JobId));
        cmd.Parameters.AddWithValue("$initiatedBy", record.InitiatedBy);
        cmd.Parameters.AddWithValue("$parameters", record.InputParametersJson);
        cmd.Parameters.AddWithValue("$rawOutput", record.RawOutput);
        cmd.Parameters.AddWithValue("$aiAnalysis", record.AiAnalysis);
        cmd.Parameters.AddWithValue("$exitCode", record.ExitCode.HasValue ? record.ExitCode.Value : DBNull.Value);
        cmd.Parameters.AddWithValue("$errorMessage", Nullable(record.ErrorMessage));

        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <summary>
    /// AddWithValue binds a CLR null as "no parameter supplied", which SQLite then reports as a
    /// missing binding rather than storing NULL - so the absent columns need the explicit sentinel.
    /// </summary>
    private static object Nullable(string? value) => value is null ? DBNull.Value : value;
}
