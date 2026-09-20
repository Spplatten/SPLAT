using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data;

public sealed class SqliteRevocationStore : IRevocationStore
{
    private readonly SqliteStorageContext _context;

    public SqliteRevocationStore(SqliteStorageContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public async Task<IReadOnlyList<RevocationEntry>> LoadRevocationsAsync(CancellationToken cancellationToken = default)
    {
        var list = new List<RevocationEntry>();
        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Identifier, RevocationType, Reason, RevokedBy, RevokedAtUtc FROM Revocations ORDER BY RevokedAtUtc ASC;";

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var id = reader.GetString(0);
            var type = reader.GetString(1);
            var reason = reader.GetString(2);
            var by = reader.GetString(3);
            var at = DateTimeOffset.Parse(reader.GetString(4), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

            list.Add(new RevocationEntry(id, type, reason, by, at));
        }

        return list;
    }

    public async Task SaveRevocationAsync(RevocationEntry entry, CancellationToken cancellationToken = default)
    {
        if (entry == null) throw new ArgumentNullException(nameof(entry));

        await using var conn = _context.CreateConnection();
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            INSERT OR REPLACE INTO Revocations (Identifier, RevocationType, Reason, RevokedBy, RevokedAtUtc)
            VALUES ($id, $type, $reason, $by, $at);";
        cmd.Parameters.AddWithValue("$id", entry.Identifier);
        cmd.Parameters.AddWithValue("$type", entry.RevocationType);
        cmd.Parameters.AddWithValue("$reason", entry.Reason);
        cmd.Parameters.AddWithValue("$by", entry.RevokedBy);
        cmd.Parameters.AddWithValue("$at", entry.RevokedAtUtc.ToString("O"));

        await cmd.ExecuteNonQueryAsync(cancellationToken);
    }
}
