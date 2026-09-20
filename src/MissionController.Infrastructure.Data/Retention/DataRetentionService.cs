using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Audit;

namespace MissionController.Infrastructure.Data.Retention;

/// <summary>
/// Layer 10 - Retention &amp; Cryptographic Erasure.
///
/// The disposal mechanism differs per data class because the constraints do:
///
///  1. Mission payload columns (RawOutput, InputParametersJson, AiAnalysis) have no chain
///     dependency, so they are overwritten in place and the metadata skeleton is kept.
///  2. The semantic index has no chain dependency either, but its vector is derived from the text,
///     so the row goes whole - keeping an embedding of deleted content is not deletion.
///  3. AuditLedger.Details CANNOT be deleted, only cryptographically erased. Its row is load-bearing
///     for Layer 7's hash chain, so the payload is dropped while the commitment the chain was built
///     over survives. See <see cref="SqliteChainedAuditLedger.RedactDetailsOlderThanAsync"/>.
///
/// SQLite specifics that make the difference between erasure and the appearance of it:
///  - PRAGMA secure_delete=ON (set in SqliteStorageContext) zeroes freed pages. Without it, deleted
///    rows persist verbatim in the file's free list.
///  - An UPDATE does not necessarily overwrite the old page; the previous value lands in the free
///    list, which is again only zeroed because secure_delete is on.
///  - In WAL mode the pre-purge image lives in the -wal sidecar until a checkpoint, so the sweep
///    forces TRUNCATE checkpointing before it reports success.
///  - VACUUM rewrites the file, which is what finally releases the pages back to the filesystem.
/// </summary>
public sealed class DataRetentionService
{
    private readonly SqliteStorageContext _context;
    private readonly SqliteChainedAuditLedger _ledger;
    private readonly Func<CancellationToken, Task<int>>? _purgeExpiredSecrets;

    /// <summary>
    /// Secret expiry is deliberately injected rather than reached for directly. The vault stores
    /// ciphertext and knows nothing about lifetimes - only the token lifecycle manager knows what has
    /// expired - and that type lives in the Network assembly. A delegate keeps the dependency
    /// pointing the right way instead of dragging Network into Data for one call.
    /// </summary>
    public DataRetentionService(
        SqliteStorageContext context,
        SqliteChainedAuditLedger ledger,
        Func<CancellationToken, Task<int>>? purgeExpiredSecrets = null)
    {
        _context = context;
        _ledger = ledger;
        _purgeExpiredSecrets = purgeExpiredSecrets;
    }

    public async Task<RetentionSweepResult> SweepAsync(
        RetentionPolicy policy,
        DateTime? nowUtc = null,
        CancellationToken cancellationToken = default)
    {
        var now = nowUtc ?? DateTime.UtcNow;

        await using var conn = _context.CreateConnection();

        int rawScrubbed = await ScrubColumnAsync(
            conn, "RawOutput", Cutoff(now, policy.RawOutputRetention), cancellationToken);

        int paramsScrubbed = await ScrubColumnAsync(
            conn, "InputParametersJson", Cutoff(now, policy.InputParameterRetention), cancellationToken);

        int analysisScrubbed = await ScrubColumnAsync(
            conn, "AiAnalysis", Cutoff(now, policy.AiAnalysisRetention), cancellationToken);

        int semanticDeleted = await DeleteSemanticRowsAsync(
            conn, Cutoff(now, policy.SemanticIndexRetention), cancellationToken);

        var redaction = policy.AuditDetailRetention == TimeSpan.MaxValue
            ? new LedgerRedactionResult(0, 0)
            : await _ledger.RedactDetailsOlderThanAsync(
                now - policy.AuditDetailRetention, cancellationToken: cancellationToken);

        int secretsPurged = policy.PurgeExpiredVaultSecrets && _purgeExpiredSecrets is not null
            ? await _purgeExpiredSecrets(cancellationToken)
            : 0;

        // Checkpoint before vacuum: the -wal sidecar still holds pre-purge page images, and a
        // vacuum that runs ahead of the checkpoint leaves them readable on disk.
        bool walTruncated = await CheckpointWalAsync(conn, cancellationToken);

        bool vacuumed = false;
        if (policy.VacuumAfterSweep)
        {
            await using var vacuumCmd = conn.CreateCommand();
            vacuumCmd.CommandText = "VACUUM;";
            await vacuumCmd.ExecuteNonQueryAsync(cancellationToken);
            vacuumed = true;
        }

        return new RetentionSweepResult(
            rawScrubbed,
            paramsScrubbed,
            analysisScrubbed,
            semanticDeleted,
            redaction.EntriesRedacted,
            redaction.LegacyEntriesSkipped,
            secretsPurged,
            vacuumed,
            walTruncated);
    }

    /// <summary>
    /// MaxValue means "never purge"; a cutoff is only meaningful for a finite window. Computing
    /// now - TimeSpan.MaxValue would throw, so the sentinel is resolved to DateTime.MinValue, which
    /// matches nothing.
    /// </summary>
    private static DateTime Cutoff(DateTime now, TimeSpan retention) =>
        retention == TimeSpan.MaxValue ? DateTime.MinValue : now - retention;

    /// <summary>
    /// Overwrites one payload column on completed missions past its window. Rows already scrubbed
    /// are excluded so a repeated sweep does not inflate its own counts.
    /// </summary>
    private static async Task<int> ScrubColumnAsync(
        SqliteConnection conn,
        string column,
        DateTime cutoffUtc,
        CancellationToken cancellationToken)
    {
        if (cutoffUtc == DateTime.MinValue)
        {
            return 0;
        }

        await using var cmd = conn.CreateCommand();

        // Column name is not user input - it is one of three compile-time literals from SweepAsync.
        cmd.CommandText = $@"
            UPDATE Missions
            SET {column} = ''
            WHERE CreatedAtUtc < $cutoff AND {column} <> '';";
        cmd.Parameters.AddWithValue("$cutoff", cutoffUtc.ToString("O"));

        return await cmd.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<int> DeleteSemanticRowsAsync(
        SqliteConnection conn,
        DateTime cutoffUtc,
        CancellationToken cancellationToken)
    {
        if (cutoffUtc == DateTime.MinValue)
        {
            return 0;
        }

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM MissionSemanticIndex WHERE TimestampUtc < $cutoff;";
        cmd.Parameters.AddWithValue("$cutoff", cutoffUtc.ToString("O"));

        try
        {
            return await cmd.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (SqliteException)
        {
            // The semantic index is created lazily by SqliteSemanticMemoryIndex; a deployment that
            // has never indexed a mission has no table to sweep.
            return 0;
        }
    }

    private static async Task<bool> CheckpointWalAsync(SqliteConnection conn, CancellationToken cancellationToken)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        if (await reader.ReadAsync(cancellationToken))
        {
            // SQLite PRAGMA wal_checkpoint returns 3 integer columns:
            // 0: busy (0 = checkpoint succeeded, 1 = checkpoint blocked because a reader held lock)
            // 1: log (number of modified pages in WAL)
            // 2: checkpointed (number of modified pages checkpointed to database)
            int busy = reader.GetInt32(0);
            return busy == 0;
        }
        return false;
    }
}
