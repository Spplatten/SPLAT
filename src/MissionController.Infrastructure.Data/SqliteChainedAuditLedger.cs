using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Audit;

public sealed class SqliteChainedAuditLedger : IAuditLedger
{
    private readonly SqliteStorageContext _context;
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    public SqliteChainedAuditLedger(SqliteStorageContext context)
    {
        _context = context;
    }

    public async Task AppendLogAsync(
        Guid missionId,
        string templateId,
        string action,
        string details,
        string operatorIdentity,
        CancellationToken cancellationToken = default)
    {
        await using var conn = _context.CreateConnection();
        await using var tx = (SqliteTransaction)await conn.BeginTransactionAsync(cancellationToken);

        // Fetch latest entry hash
        string previousHash = GenesisHash;
        await using (var getCmd = conn.CreateCommand())
        {
            getCmd.Transaction = tx;
            getCmd.CommandText = "SELECT EntryHash FROM AuditLedger ORDER BY Id DESC LIMIT 1;";
            var result = await getCmd.ExecuteScalarAsync(cancellationToken);
            if (result != null && result != DBNull.Value)
            {
                previousHash = (string)result;
            }
        }

        string timestampUtc = DateTime.UtcNow.ToString("O");
        string entryHash = ComputeEntryHash(previousHash, timestampUtc, missionId.ToString("D"), templateId, action, details, operatorIdentity);

        await using (var insertCmd = conn.CreateCommand())
        {
            insertCmd.Transaction = tx;
            insertCmd.CommandText = @"
                INSERT INTO AuditLedger (TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash)
                VALUES ($ts, $mid, $tid, $act, $det, $op, $prev, $entry);
            ";
            insertCmd.Parameters.AddWithValue("$ts", timestampUtc);
            insertCmd.Parameters.AddWithValue("$mid", missionId.ToString("D"));
            insertCmd.Parameters.AddWithValue("$tid", templateId);
            insertCmd.Parameters.AddWithValue("$act", action);
            insertCmd.Parameters.AddWithValue("$det", details);
            insertCmd.Parameters.AddWithValue("$op", operatorIdentity);
            insertCmd.Parameters.AddWithValue("$prev", previousHash);
            insertCmd.Parameters.AddWithValue("$entry", entryHash);

            await insertCmd.ExecuteNonQueryAsync(cancellationToken);
        }

        await tx.CommitAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(
        Guid? missionId = null,
        int limit = 100,
        CancellationToken cancellationToken = default)
    {
        var list = new List<AuditLogEntry>();
        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();

        if (missionId.HasValue)
        {
            cmd.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash FROM AuditLedger WHERE MissionId = $mid ORDER BY Id DESC LIMIT $limit;";
            cmd.Parameters.AddWithValue("$mid", missionId.Value.ToString("D"));
        }
        else
        {
            cmd.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash FROM AuditLedger ORDER BY Id DESC LIMIT $limit;";
        }
        cmd.Parameters.AddWithValue("$limit", limit);

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new AuditLogEntry(
                reader.GetInt64(0),
                DateTime.Parse(reader.GetString(1)),
                Guid.Parse(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetString(7),
                reader.GetString(8)));
        }

        return list;
    }

    public async Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default)
    {
        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash FROM AuditLedger ORDER BY Id ASC;";

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        string expectedPreviousHash = GenesisHash;

        while (await reader.ReadAsync(cancellationToken))
        {
            string ts = reader.GetString(1);
            string mid = reader.GetString(2);
            string tid = reader.GetString(3);
            string act = reader.GetString(4);
            string det = reader.GetString(5);
            string op = reader.GetString(6);
            string prev = reader.GetString(7);
            string entry = reader.GetString(8);

            // 1. Verify previous hash link matches
            if (!string.Equals(prev, expectedPreviousHash, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // 2. Verify recalculated hash matches entry hash
            string calculatedHash = ComputeEntryHash(prev, ts, mid, tid, act, det, op);
            if (!string.Equals(entry, calculatedHash, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            expectedPreviousHash = entry;
        }

        return true;
    }

    public static string ComputeEntryHash(
        string previousHash,
        string timestampUtc,
        string missionId,
        string templateId,
        string action,
        string details,
        string operatorIdentity)
    {
        string raw = $"{previousHash}|{timestampUtc}|{missionId}|{templateId}|{action}|{details}|{operatorIdentity}";
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
