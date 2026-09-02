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
    private readonly ICredentialVault? _vault;
    private readonly byte[]? _explicitHmacKey;
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    public const string HmacKeyVaultSecretName = "audit-ledger-hmac-key";

    public SqliteChainedAuditLedger(
        SqliteStorageContext context,
        ICredentialVault? vault = null,
        byte[]? explicitHmacKey = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _vault = vault;
        _explicitHmacKey = explicitHmacKey;
    }

    private async Task<byte[]?> GetHmacKeyAsync(CancellationToken ct)
    {
        if (_explicitHmacKey != null && _explicitHmacKey.Length > 0)
            return _explicitHmacKey;

        if (_vault != null)
        {
            try
            {
                var storedKey = await _vault.RetrieveSecretAsync(HmacKeyVaultSecretName, ct);
                if (storedKey != null && storedKey.Length > 0)
                    return storedKey;
            }
            catch
            {
                // Non-blocking fallback if vault is locked
            }
        }

        return null;
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

        // Version 2 chaining: the chain commits to a SALTED DIGEST of Details rather than to the
        // plaintext. This is what makes retention possible at all - the payload can later be erased
        // while EntryHash still recomputes, so a purge does not forge a tamper signal.
        string detailsSalt = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        string detailsCommitment = ComputeDetailsCommitment(detailsSalt, details);

        byte[]? hmacKey = await GetHmacKeyAsync(cancellationToken);
        string entryHash = ComputeEntryHashV2(
            previousHash, timestampUtc, missionId.ToString("D"), templateId, action, detailsCommitment, operatorIdentity, hmacKey);

        await using (var insertCmd = conn.CreateCommand())
        {
            insertCmd.Transaction = tx;
            insertCmd.CommandText = @"
                INSERT INTO AuditLedger (TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, DetailsSalt, DetailsCommitment, HashVersion)
                VALUES ($ts, $mid, $tid, $act, $det, $op, $prev, $entry, $salt, $commit, 2);
            ";
            insertCmd.Parameters.AddWithValue("$ts", timestampUtc);
            insertCmd.Parameters.AddWithValue("$mid", missionId.ToString("D"));
            insertCmd.Parameters.AddWithValue("$tid", templateId);
            insertCmd.Parameters.AddWithValue("$act", action);
            insertCmd.Parameters.AddWithValue("$det", details);
            insertCmd.Parameters.AddWithValue("$op", operatorIdentity);
            insertCmd.Parameters.AddWithValue("$prev", previousHash);
            insertCmd.Parameters.AddWithValue("$entry", entryHash);
            insertCmd.Parameters.AddWithValue("$salt", detailsSalt);
            insertCmd.Parameters.AddWithValue("$commit", detailsCommitment);

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
        byte[]? hmacKey = await GetHmacKeyAsync(cancellationToken);

        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, DetailsCommitment, HashVersion FROM AuditLedger ORDER BY Id ASC;";

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
            string? commitment = reader.IsDBNull(9) ? null : reader.GetString(9);
            long hashVersion = reader.IsDBNull(10) ? 1 : reader.GetInt64(10);

            // 1. Verify previous hash link matches
            if (!string.Equals(prev, expectedPreviousHash, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // 2. Verify recalculated hash matches entry hash
            string calculatedHash;
            if (hashVersion >= 2 && commitment is not null)
            {
                calculatedHash = ComputeEntryHashV2(prev, ts, mid, tid, act, commitment, op, hmacKey);
                // If keyed check fails and hmacKey was active, try unkeyed for backward compatibility
                if (!string.Equals(entry, calculatedHash, StringComparison.OrdinalIgnoreCase) && hmacKey != null)
                {
                    calculatedHash = ComputeEntryHashV2(prev, ts, mid, tid, act, commitment, op, null);
                }
            }
            else
            {
                calculatedHash = ComputeEntryHash(prev, ts, mid, tid, act, det, op);
            }

            if (!string.Equals(entry, calculatedHash, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            expectedPreviousHash = entry;
        }

        return true;
    }

    public async Task<LedgerRedactionResult> RedactDetailsOlderThanAsync(
        DateTime olderThanUtc,
        string redactionMarker = "[REDACTED — retention policy]",
        CancellationToken cancellationToken = default)
    {
        await using var conn = _context.CreateConnection();

        int legacySkipped;
        await using (var countCmd = conn.CreateCommand())
        {
            countCmd.CommandText = @"
                SELECT COUNT(*) FROM AuditLedger
                WHERE TimestampUtc < $cutoff AND COALESCE(HashVersion, 1) < 2 AND RedactedAtUtc IS NULL;";
            countCmd.Parameters.AddWithValue("$cutoff", olderThanUtc.ToString("O"));
            legacySkipped = Convert.ToInt32(await countCmd.ExecuteScalarAsync(cancellationToken));
        }

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            UPDATE AuditLedger
            SET Details = $marker, DetailsSalt = NULL, RedactedAtUtc = $now
            WHERE TimestampUtc < $cutoff AND COALESCE(HashVersion, 1) >= 2 AND RedactedAtUtc IS NULL;";
        cmd.Parameters.AddWithValue("$marker", redactionMarker);
        cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));
        cmd.Parameters.AddWithValue("$cutoff", olderThanUtc.ToString("O"));

        int redacted = await cmd.ExecuteNonQueryAsync(cancellationToken);
        return new LedgerRedactionResult(redacted, legacySkipped);
    }

    /// <summary>Salted commitment to the audit payload. Salt first so length-extension is moot.</summary>
    public static string ComputeDetailsCommitment(string salt, string details)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{salt}|{details}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>Version 2 chain hash: commits to the details COMMITMENT, with optional HMAC key.</summary>
    public static string ComputeEntryHashV2(
        string previousHash,
        string timestampUtc,
        string missionId,
        string templateId,
        string action,
        string detailsCommitment,
        string operatorIdentity,
        byte[]? hmacKey = null)
    {
        string raw = $"{previousHash}|{timestampUtc}|{missionId}|{templateId}|{action}|{detailsCommitment}|{operatorIdentity}";
        byte[] rawBytes = Encoding.UTF8.GetBytes(raw);

        byte[] hashBytes = (hmacKey != null && hmacKey.Length > 0)
            ? HMACSHA256.HashData(hmacKey, rawBytes)
            : SHA256.HashData(rawBytes);

        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    /// <summary>
    /// Version 1 chain hash over plaintext details. Retained solely so ledgers written before the
    /// redaction migration still verify; new entries never use it.
    /// </summary>
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

/// <summary>Outcome of a ledger redaction sweep. Legacy rows are reported, never quietly ignored.</summary>
public record LedgerRedactionResult(int EntriesRedacted, int LegacyEntriesSkipped);
