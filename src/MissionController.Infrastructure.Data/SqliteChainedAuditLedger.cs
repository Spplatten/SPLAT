using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Audit;

/// <summary>
/// The hash-chained audit ledger. Every row says which kind of chain it belongs to, in HashVersion:
/// 1 is the legacy plaintext chain; 2 is SHA-256 over a salted commitment, unkeyed, so whoever can
/// write the file can rewrite it and recompute every later hash; 3 is HMAC-SHA256 under the
/// operator's key, which nobody without the key can recompute.
///
/// A chain only ever moves from unkeyed to keyed, and records where. The first keyed append to an
/// unkeyed ledger writes a <see cref="KeyedAction"/> entry that commits to the history before it.
/// From then on the ledger refuses to be extended without its key, or with another. What no chain
/// can see on its own is its newest entries being deleted; a saved audit anchor catches that.
/// </summary>
public sealed class SqliteChainedAuditLedger : IAuditLedger
{
    public const int PlaintextVersion = 1;
    public const int UnkeyedVersion = 2;
    public const int KeyedVersion = 3;
    public const string KeyedAction = "LEDGER_KEYED";

    private readonly SqliteStorageContext _context;
    private readonly byte[]? _explicitHmacKey;
    private const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <param name="explicitHmacKey">The operator's key, read from their key file by
    /// <see cref="LedgerKeyFile"/>; null for an unkeyed chain.</param>
    public SqliteChainedAuditLedger(SqliteStorageContext context, byte[]? explicitHmacKey = null)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        // An empty key would read as keyed while HMAC-ing with nothing.
        if (explicitHmacKey is { Length: 0 })
        {
            throw new ArgumentException("An empty key keys nothing.", nameof(explicitHmacKey));
        }

        _explicitHmacKey = explicitHmacKey;
    }

    /// <summary>The database this ledger writes, so a caller can confirm it shares one transaction with it.</summary>
    public string DatabasePath => _context.DatabasePath;

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
        await AppendWithinAsync(conn, tx, missionId, templateId, action, details, operatorIdentity, cancellationToken);
        await tx.CommitAsync(cancellationToken);
    }

    /// <summary>
    /// Appends inside a transaction the caller owns on this ledger's database, without committing it, so
    /// the entry commits or rolls back with the caller's own rows. A2A admission needs exactly that: an
    /// authorization row written before a task insert that then failed outlived the refusal it described
    /// (16 orphan rows in the 2026-10-20 A2A stress run). Same key checks and chaining as AppendLogAsync.
    /// </summary>
    public async Task AppendWithinAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        Guid missionId,
        string templateId,
        string action,
        string details,
        string operatorIdentity,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(conn);
        ArgumentNullException.ThrowIfNull(tx);

        // The newest entry decides everything, and it is read by primary key: an append never scans.
        LedgerRow? newest = await ReadNewestAsync(conn, tx, cancellationToken);
        bool keyed = newest is { HashVersion: KeyedVersion };

        if (keyed && _explicitHmacKey is null)
        {
            throw new InvalidOperationException(
                "This audit ledger is keyed and no key was supplied, so it was not extended: an unkeyed entry " +
                "would let anyone rewrite everything after it. Give SPLAT the operator's key file.");
        }

        if (keyed && !newest!.RecomputesUnder(_explicitHmacKey))
        {
            throw new InvalidOperationException("The supplied key did not write this audit ledger, so it was not extended.");
        }

        string previousHash = newest?.EntryHash ?? GenesisHash;
        if (_explicitHmacKey is not null && newest is not null && !keyed)
        {
            // The recorded migration. One keyed entry commits to the unkeyed history, which from here
            // on cannot be rewritten without breaking a hash only the key can recompute.
            previousHash = await InsertAsync(
                conn, tx, Guid.Empty, "splat.ledger", KeyedAction,
                "From this entry the chain is keyed: this entry and every later one are HMAC-SHA256 under the operator's key.",
                "splat", previousHash, cancellationToken);
        }

        await InsertAsync(conn, tx, missionId, templateId, action, details, operatorIdentity, previousHash, cancellationToken);
    }

    /// <summary>Writes one entry after <paramref name="previousHash"/> and returns its hash.</summary>
    private async Task<string> InsertAsync(
        SqliteConnection conn,
        SqliteTransaction tx,
        Guid missionId,
        string templateId,
        string action,
        string details,
        string operatorIdentity,
        string previousHash,
        CancellationToken cancellationToken)
    {
        string timestampUtc = DateTime.UtcNow.ToString("O");

        // Version 2 chaining: the chain commits to a SALTED DIGEST of Details rather than to the
        // plaintext. This is what makes retention possible at all - the payload can later be erased
        // while EntryHash still recomputes, so a purge does not forge a tamper signal.
        string detailsSalt = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        string detailsCommitment = ComputeDetailsCommitment(detailsSalt, details);

        string entryHash = ComputeEntryHashV2(
            previousHash, timestampUtc, missionId.ToString("D"), templateId, action, detailsCommitment, operatorIdentity, _explicitHmacKey);

        await using (var insertCmd = conn.CreateCommand())
        {
            insertCmd.Transaction = tx;
            insertCmd.CommandText = @"
                INSERT INTO AuditLedger (TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, DetailsSalt, DetailsCommitment, HashVersion)
                VALUES ($ts, $mid, $tid, $act, $det, $op, $prev, $entry, $salt, $commit, $ver);
            ";
            insertCmd.Parameters.AddWithValue("$ver", _explicitHmacKey is null ? UnkeyedVersion : KeyedVersion);
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

        return entryHash;
    }

    /// <summary>The fields an entry's hash is computed over, for the newest entry only.</summary>
    private sealed record LedgerRow(
        long HashVersion,
        string PreviousHash,
        string TimestampUtc,
        string MissionId,
        string TemplateId,
        string Action,
        string? DetailsCommitment,
        string OperatorIdentity,
        string EntryHash)
    {
        public bool RecomputesUnder(byte[]? key) =>
            DetailsCommitment is not null && string.Equals(
                ComputeEntryHashV2(PreviousHash, TimestampUtc, MissionId, TemplateId, Action, DetailsCommitment, OperatorIdentity, key),
                EntryHash,
                StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<LedgerRow?> ReadNewestAsync(SqliteConnection conn, SqliteTransaction? tx, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = "SELECT COALESCE(HashVersion, 1), PreviousHash, TimestampUtc, MissionId, TemplateId, Action, DetailsCommitment, OperatorIdentity, EntryHash FROM AuditLedger ORDER BY Id DESC LIMIT 1;";
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
        {
            return null;
        }

        return new LedgerRow(
            reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
            reader.GetString(5), reader.IsDBNull(6) ? null : reader.GetString(6), reader.GetString(7), reader.GetString(8));
    }

    /// <summary>What a ledger file holds, as `doctor` reports it.</summary>
    /// <param name="KeyMatches">Whether the given key wrote it; null when it is unkeyed or no key was given.</param>
    public sealed record ChainState(bool Exists, bool Keyed, bool? KeyMatches);

    /// <summary>
    /// Reads a ledger file's state without creating or changing it: `doctor` serves nothing and creates
    /// nothing, and a storage context would create the database and its schema just by being built.
    /// </summary>
    public static async Task<ChainState> InspectAsync(string databasePath, byte[]? key, CancellationToken ct = default)
    {
        if (!File.Exists(databasePath))
        {
            return new ChainState(false, false, null);
        }

        // Unpooled, so no handle outlives the look.
        string connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString();
        await using var conn = new SqliteConnection(connectionString);
        await conn.OpenAsync(ct);

        LedgerRow? newest;
        try
        {
            newest = await ReadNewestAsync(conn, null, ct);
        }
        catch (SqliteException)
        {
            // A database with no ledger table yet holds no chain.
            return new ChainState(true, false, null);
        }

        bool keyed = newest is { HashVersion: KeyedVersion };
        return new ChainState(true, keyed, keyed && key is not null ? newest!.RecomputesUnder(key) : null);
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
            cmd.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, COALESCE(HashVersion, 1), DetailsCommitment, DetailsSalt FROM AuditLedger WHERE MissionId = $mid ORDER BY Id DESC LIMIT $limit;";
            cmd.Parameters.AddWithValue("$mid", missionId.Value.ToString("D"));
        }
        else
        {
            cmd.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, COALESCE(HashVersion, 1), DetailsCommitment, DetailsSalt FROM AuditLedger ORDER BY Id DESC LIMIT $limit;";
        }
        cmd.Parameters.AddWithValue("$limit", limit);

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            list.Add(new AuditLogEntry(
                reader.GetInt64(0),
                // RoundtripKind keeps the stored "Z". A bare Parse converts to local time, which reached
                // MCP clients as "timestampUtc" with a -04:00 offset and made Merkle leaves timezone-dependent.
                DateTime.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                Guid.Parse(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetString(7),
                reader.GetString(8),
                // A row from before the column existed is plaintext, as VerifyLedgerIntegrityAsync reads it.
                (int)reader.GetInt64(9),
                reader.IsDBNull(10) ? null : reader.GetString(10),
                reader.IsDBNull(11) ? null : reader.GetString(11)));
        }

        return list;
    }

    /// <summary>
    /// Reads the anchor for one mission: the chain's first row, its last, and every row the chain
    /// holds for this mission. Three statements about the same table, read in one connection so a
    /// row appended between them cannot land in the head while the mission list already closed.
    ///
    /// <see cref="VerifyLedgerIntegrityAsync"/> is run here as well, and it walks the whole table.
    /// An export is rare and a bundle that cannot say whether its own chain recomputed is worth
    /// less than the scan costs.
    /// </summary>
    public async Task<LedgerAnchor?> ReadAnchorAsync(Guid missionId, CancellationToken cancellationToken = default)
    {
        await using var conn = _context.CreateConnection();

        await using var boundsCmd = conn.CreateCommand();
        boundsCmd.CommandText =
            "SELECT (SELECT EntryHash FROM AuditLedger ORDER BY Id ASC LIMIT 1), " +
            "       (SELECT Id FROM AuditLedger ORDER BY Id DESC LIMIT 1), " +
            "       (SELECT EntryHash FROM AuditLedger ORDER BY Id DESC LIMIT 1), " +
            "       (SELECT COALESCE(HashVersion, 1) FROM AuditLedger ORDER BY Id DESC LIMIT 1);";

        string genesis;
        long headId;
        string headHash;
        int hashVersion;
        await using (var boundsReader = await boundsCmd.ExecuteReaderAsync(cancellationToken))
        {
            // An empty ledger anchors nothing. It also cannot hold the mission whose bundle is being
            // built, so the caller is better served by "not anchored" than by an anchor of zeroes.
            if (!await boundsReader.ReadAsync(cancellationToken) || boundsReader.IsDBNull(0))
            {
                return null;
            }

            genesis = boundsReader.GetString(0);
            headId = boundsReader.GetInt64(1);
            headHash = boundsReader.GetString(2);
            hashVersion = (int)boundsReader.GetInt64(3);
        }

        var missionEntries = new List<LedgerAnchorEntry>();
        await using (var missionCmd = conn.CreateCommand())
        {
            // ASC, and every row: the anchor's whole purpose is to be the complete list, so it is the
            // one read in this codebase that takes no limit and no newest-first ordering.
            missionCmd.CommandText = "SELECT Id, EntryHash, Action FROM AuditLedger WHERE MissionId = $mid ORDER BY Id ASC;";
            missionCmd.Parameters.AddWithValue("$mid", missionId.ToString("D"));

            await using var missionReader = await missionCmd.ExecuteReaderAsync(cancellationToken);
            while (await missionReader.ReadAsync(cancellationToken))
            {
                missionEntries.Add(new LedgerAnchorEntry(
                    missionReader.GetInt64(0),
                    missionReader.GetString(1),
                    missionReader.GetString(2)));
            }
        }

        return new LedgerAnchor(
            GenesisEntryHash: genesis,
            HeadEntryId: headId,
            HeadEntryHash: headHash,
            MissionEntries: missionEntries,
            LedgerVerifiedAtExport: await VerifyLedgerIntegrityAsync(cancellationToken),
            ChainHashVersion: hashVersion,
            AnchoredAtUtc: DateTimeOffset.UtcNow);
    }

    public async Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default)
    {
        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, DetailsCommitment, HashVersion, DetailsSalt, RedactedAtUtc FROM AuditLedger ORDER BY Id ASC;";

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        string expectedPreviousHash = GenesisHash;
        bool anyEntry = false;
        bool keyedSeen = false;

        while (await reader.ReadAsync(cancellationToken))
        {
            anyEntry = true;
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
            string? salt = reader.IsDBNull(11) ? null : reader.GetString(11);
            bool isRedacted = !reader.IsDBNull(12);

            if (hashVersion >= KeyedVersion)
            {
                // Without the key a keyed entry cannot be checked, and an unchecked entry is no pass.
                if (_explicitHmacKey is null)
                {
                    return false;
                }

                keyedSeen = true;
            }
            else if (keyedSeen)
            {
                // An unkeyed entry after a keyed one is a downgrade: whoever wrote it lacked the key.
                return false;
            }

            // 1. Verify previous hash link matches
            if (!string.Equals(prev, expectedPreviousHash, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // 2. Verify recalculated hash matches entry hash
            string calculatedHash;
            if (hashVersion >= 2 && commitment is not null)
            {
                // The chain commits to the COMMITMENT, not to the narrative. Recomputing EntryHash
                // from the stored commitment therefore says nothing about the text an auditor
                // actually reads, and without this check `UPDATE AuditLedger SET Details = '...'`
                // left verification green while the displayed evidence was forged.
                if (!isRedacted)
                {
                    if (salt is null ||
                        !string.Equals(ComputeDetailsCommitment(salt, det), commitment, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                }
                else if (salt is not null)
                {
                    // Cryptographic erasure drops the salt. A row claiming redaction while keeping
                    // one was edited by hand rather than swept by the retention service.
                    return false;
                }

                // The row's version says which hash it carries, and never the verifier's hopes: no
                // unkeyed retry of a keyed row, and no keyed check of a row written before the key.
                calculatedHash = ComputeEntryHashV2(
                    prev, ts, mid, tid, act, commitment, op, hashVersion >= KeyedVersion ? _explicitHmacKey : null);
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

        // A host holding a key vouches only for a chain it keyed. Unkeyed history counts once a keyed
        // entry commits to it - the migration AppendLogAsync records - and not before: otherwise a
        // keyed chain rewritten wholesale as SHA-256 would verify.
        return !(anyEntry && _explicitHmacKey is not null && !keyedSeen);
    }

    /// <param name="apply">
    /// False counts the entries the redaction would rewrite and writes nothing. The count is taken
    /// from the same predicate the UPDATE carries, because this erasure is irreversible by design -
    /// the payload goes and only the chain's commitment to it survives - so an operator has to be able
    /// to see the number first, and must not be shown one that a separately written query invented.
    /// </param>
    public async Task<LedgerRedactionResult> RedactDetailsOlderThanAsync(
        DateTime olderThanUtc,
        string redactionMarker = "[REDACTED — retention policy]",
        CancellationToken cancellationToken = default,
        bool apply = true)
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

        const string redactable =
            "WHERE TimestampUtc < $cutoff AND COALESCE(HashVersion, 1) >= 2 AND RedactedAtUtc IS NULL";

        await using var cmd = conn.CreateCommand();
        cmd.CommandText = apply
            ? $@"UPDATE AuditLedger
                 SET Details = $marker, DetailsSalt = NULL, RedactedAtUtc = $now
                 {redactable};"
            : $"SELECT COUNT(*) FROM AuditLedger {redactable};";
        cmd.Parameters.AddWithValue("$cutoff", olderThanUtc.ToString("O"));
        if (apply)
        {
            cmd.Parameters.AddWithValue("$marker", redactionMarker);
            cmd.Parameters.AddWithValue("$now", DateTime.UtcNow.ToString("O"));
        }

        int redacted = apply
            ? await cmd.ExecuteNonQueryAsync(cancellationToken)
            : Convert.ToInt32(await cmd.ExecuteScalarAsync(cancellationToken));
        return new LedgerRedactionResult(redacted, legacySkipped);
    }

    /// <summary>Salted commitment to the audit payload. Salt first so length-extension is moot.</summary>
    public static string ComputeDetailsCommitment(string salt, string details)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes($"{salt}|{details}"));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>Version 2 and 3 chain hash: commits to the details COMMITMENT; SHA-256 unkeyed, HMAC-SHA256 under a key.</summary>
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
