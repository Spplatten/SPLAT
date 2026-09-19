using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Roadmap 3.2: the ledger keyed by a file the operator keeps. Held here: a keyed chain is never
/// extended without its key or with another; the move from unkeyed to keyed is recorded, and fixes
/// the history before it; every row says which kind of chain it came from; and the key file is
/// checked before the server starts, whether it came from the command line or the environment.
/// </summary>
public sealed class LedgerKeyingTests : IDisposable
{
    private static readonly byte[] KeyA = RandomNumberGenerator.GetBytes(32);
    private static readonly byte[] KeyB = RandomNumberGenerator.GetBytes(32);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "splat-ledger-key-" + Guid.NewGuid().ToString("N"));
    private readonly string _db;
    private readonly SqliteStorageContext _context;

    public LedgerKeyingTests()
    {
        Directory.CreateDirectory(_dir);
        _db = Path.Combine(_dir, "ledger.db");
        _context = new SqliteStorageContext(_db);
    }

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
    public async Task AKeyedChain_VerifiesUnderItsKey_AndUnderNothingElse()
    {
        await Append(KeyA, "FIRST");
        await Append(KeyA, "SECOND");

        Assert.Equal(new long[] { SqliteChainedAuditLedger.KeyedVersion, SqliteChainedAuditLedger.KeyedVersion }, Versions());
        Assert.True(await Ledger(KeyA).VerifyLedgerIntegrityAsync());
        Assert.False(await Ledger(KeyB).VerifyLedgerIntegrityAsync());
        // Without the key a keyed entry cannot be checked, and an unchecked entry is not a pass.
        Assert.False(await Ledger(null).VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task AKeyedChain_IsNeverExtendedWithoutItsKey_OrWithAnother()
    {
        await Append(KeyA);

        var unkeyed = await Assert.ThrowsAsync<InvalidOperationException>(() => Append(null));
        Assert.Contains("keyed", unkeyed.Message);
        var other = await Assert.ThrowsAsync<InvalidOperationException>(() => Append(KeyB));
        Assert.Contains("did not write", other.Message);

        // Refused before anything was written, so the chain still verifies as the key left it.
        Assert.Single(Versions());
        Assert.True(await Ledger(KeyA).VerifyLedgerIntegrityAsync());
    }

    /// <summary>
    /// What `doctor` says of an unkeyed ledger - a rewrite by this user is undetectable - held true, so
    /// the sentence cannot outlive the weakness or overstate it.
    /// </summary>
    [Fact]
    public async Task AnUnkeyedChain_CanBeRewrittenUndetected()
    {
        await Append(null, "BEFORE-1");
        await Append(null, "BEFORE-2");

        RewriteFirstEntryAndRechain();

        Assert.True(await Ledger(null).VerifyLedgerIntegrityAsync());
        Assert.Contains(await Ledger(null).GetAuditLogsAsync(), e => e.Details == "a rewritten entry");
    }

    [Fact]
    public async Task KeyingAnUnkeyedChain_IsRecorded_AndFixesTheHistoryBeforeIt()
    {
        await Append(null, "BEFORE-1");
        await Append(null, "BEFORE-2");
        // Until a keyed entry commits to it, a host holding a key vouches for none of it.
        Assert.False(await Ledger(KeyA).VerifyLedgerIntegrityAsync());

        await Append(KeyA, "AFTER");

        Assert.Equal(new long[] { 2, 2, 3, 3 }, Versions());
        var entries = await Ledger(KeyA).GetAuditLogsAsync();
        Assert.Equal(SqliteChainedAuditLedger.KeyedAction, entries.Single(e => e.Id == 3).Action);
        Assert.True(await Ledger(KeyA).VerifyLedgerIntegrityAsync());

        // The rewrite that passed an unkeyed chain above now meets a hash only the key can recompute.
        RewriteFirstEntryAndRechain();
        Assert.False(await Ledger(KeyA).VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task AnUnkeyedEntryAfterAKeyedOne_FailsVerification()
    {
        await Append(KeyA);

        // What a writer without the key can add: an entry chained correctly, but unkeyed.
        using (var conn = _context.CreateConnection())
        {
            string previous;
            using (var read = conn.CreateCommand())
            {
                read.CommandText = "SELECT EntryHash FROM AuditLedger ORDER BY Id DESC LIMIT 1;";
                previous = (string)read.ExecuteScalar()!;
            }

            string ts = DateTime.UtcNow.ToString("O");
            string mid = Guid.NewGuid().ToString("D");
            string salt = new('a', 64);
            string commitment = SqliteChainedAuditLedger.ComputeDetailsCommitment(salt, "appended without the key");
            using var insert = conn.CreateCommand();
            insert.CommandText = @"
                INSERT INTO AuditLedger (TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, PreviousHash, EntryHash, DetailsSalt, DetailsCommitment, HashVersion)
                VALUES ($ts, $mid, 'tpl-1', 'ACTION', 'appended without the key', 'operator', $prev, $hash, $salt, $commit, 2);";
            insert.Parameters.AddWithValue("$ts", ts);
            insert.Parameters.AddWithValue("$mid", mid);
            insert.Parameters.AddWithValue("$prev", previous);
            insert.Parameters.AddWithValue("$hash", SqliteChainedAuditLedger.ComputeEntryHashV2(previous, ts, mid, "tpl-1", "ACTION", commitment, "operator"));
            insert.Parameters.AddWithValue("$salt", salt);
            insert.Parameters.AddWithValue("$commit", commitment);
            insert.ExecuteNonQuery();
        }

        Assert.False(await Ledger(KeyA).VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task EntriesComeBackInUtc_AsTheirNameSays()
    {
        await Append(null);

        var entry = (await Ledger(null).GetAuditLogsAsync()).Single();
        Assert.Equal(DateTimeKind.Utc, entry.TimestampUtc.Kind);
    }

    [Fact]
    public void TheKeyFile_IsCheckedBeforeTheServerStarts()
    {
        string good = WriteKeyFile("good.key", RandomNumberGenerator.GetBytes(32));
        string tooShort = WriteKeyFile("short.key", RandomNumberGenerator.GetBytes(31));

        var serve = Assert.IsType<McpServerCommand.Serve>(McpServerCommand.Parse(new[] { "--ledger-key", good }));
        Assert.Equal(good, serve.LedgerKeyPath);
        var doctor = Assert.IsType<McpServerCommand.Doctor>(McpServerCommand.Parse(new[] { "doctor", $"--ledger-key={good}" }));
        Assert.Equal(good, doctor.LedgerKeyPath);

        Assert.Contains("at least 32", Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "--ledger-key", tooShort })).Message);
        Assert.Contains("never creates", Assert.IsType<McpServerCommand.UsageError>(
            McpServerCommand.Parse(new[] { "--ledger-key", Path.Combine(_dir, "missing.key") })).Message);
        Assert.Contains("folder", Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "--ledger-key", _dir })).Message);
        Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "provision", "--ledger-key", good }));
    }

    [Fact]
    public void TheEnvironment_SuppliesTheKeyFile_OnlyWhenTheCommandLineDoesNot()
    {
        string fromEnvironment = WriteKeyFile("env.key", RandomNumberGenerator.GetBytes(32));
        string fromArgument = WriteKeyFile("arg.key", RandomNumberGenerator.GetBytes(32));
        string? Environment(string name) => name == LedgerKeyFile.EnvironmentVariable ? fromEnvironment : null;

        var filled = McpServerCommand.WithLedgerKeyFromEnvironment(McpServerCommand.Parse(Array.Empty<string>()), Environment);
        Assert.Equal(fromEnvironment, Assert.IsType<McpServerCommand.Serve>(filled).LedgerKeyPath);
        var kept = McpServerCommand.WithLedgerKeyFromEnvironment(McpServerCommand.Parse(new[] { "--ledger-key", fromArgument }), Environment);
        Assert.Equal(fromArgument, Assert.IsType<McpServerCommand.Serve>(kept).LedgerKeyPath);

        var refused = McpServerCommand.WithLedgerKeyFromEnvironment(
            McpServerCommand.Parse(new[] { "doctor" }), _ => Path.Combine(_dir, "missing.key"));
        Assert.Contains(LedgerKeyFile.EnvironmentVariable, Assert.IsType<McpServerCommand.UsageError>(refused).Message);
    }

    [Fact]
    public async Task TheDoctor_ReadsWhetherTheLedgerIsKeyed_FromTheLedgerItself()
    {
        string absent = Path.Combine(_dir, "never-served.db");
        string keyA = WriteKeyFile("a.key", KeyA);
        Assert.Contains("its first entry will be keyed", await DoctorLedgerLine(keyA, absent));
        Assert.False(File.Exists(absent));

        await Append(KeyA);

        string keyed = await DoctorLedgerLine(keyA, _db);
        Assert.StartsWith("  ok", keyed);
        Assert.Contains("keyed by", keyed);
        string noKey = await DoctorLedgerLine(null, _db);
        Assert.StartsWith("  FAIL", noKey);
        Assert.Contains("no key file", noKey);
        string other = await DoctorLedgerLine(WriteKeyFile("b.key", KeyB), _db);
        Assert.StartsWith("  FAIL", other);
        Assert.Contains("not by", other);
    }

    private SqliteChainedAuditLedger Ledger(byte[]? key) => new(_context, key);

    private Task Append(byte[]? key, string action = "ACTION") =>
        Ledger(key).AppendLogAsync(Guid.NewGuid(), "tpl-1", action, "details of " + action, "operator");

    private long[] Versions()
    {
        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT HashVersion FROM AuditLedger ORDER BY Id;";
        using var reader = cmd.ExecuteReader();
        var versions = new List<long>();
        while (reader.Read())
        {
            versions.Add(reader.GetInt64(0));
        }

        return versions.ToArray();
    }

    /// <summary>
    /// Rewrites entry 1 the way anyone who can write the file can: new details, a fresh commitment,
    /// and every unkeyed hash after it recomputed. A keyed entry can only be re-pointed at the result;
    /// its own hash cannot follow without the key.
    /// </summary>
    private void RewriteFirstEntryAndRechain()
    {
        using var conn = _context.CreateConnection();
        var rows = new List<(long Id, string Ts, string Mid, string Tid, string Act, string Det, string Op, string Salt, long Version)>();
        using (var read = conn.CreateCommand())
        {
            read.CommandText = "SELECT Id, TimestampUtc, MissionId, TemplateId, Action, Details, OperatorIdentity, DetailsSalt, HashVersion FROM AuditLedger ORDER BY Id;";
            using var reader = read.ExecuteReader();
            while (reader.Read())
            {
                rows.Add((reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3), reader.GetString(4),
                    reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetInt64(8)));
            }
        }

        string previous = new('0', 64);
        foreach (var row in rows)
        {
            using var update = conn.CreateCommand();
            update.Parameters.AddWithValue("$id", row.Id);
            update.Parameters.AddWithValue("$p", previous);
            if (row.Version >= SqliteChainedAuditLedger.KeyedVersion)
            {
                update.CommandText = "UPDATE AuditLedger SET PreviousHash = $p WHERE Id = $id;";
                update.ExecuteNonQuery();
                return;
            }

            string details = row.Id == 1 ? "a rewritten entry" : row.Det;
            string commitment = SqliteChainedAuditLedger.ComputeDetailsCommitment(row.Salt, details);
            previous = SqliteChainedAuditLedger.ComputeEntryHashV2(previous, row.Ts, row.Mid, row.Tid, row.Act, commitment, row.Op);
            update.CommandText = "UPDATE AuditLedger SET Details = $d, DetailsCommitment = $c, PreviousHash = $p, EntryHash = $h WHERE Id = $id;";
            update.Parameters.AddWithValue("$d", details);
            update.Parameters.AddWithValue("$c", commitment);
            update.Parameters.AddWithValue("$h", previous);
            update.ExecuteNonQuery();
        }
    }

    private string WriteKeyFile(string name, byte[] bytes)
    {
        string path = Path.Combine(_dir, name);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static async Task<string> DoctorLedgerLine(string? keyPath, string ledgerPath)
    {
        var report = new StringWriter();
        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None, keyPath),
            report,
            wsl: (_, _) => Task.FromResult((-1, "wsl.exe not found")),
            health: new WslSubstrateHealthChecker("127.0.0.1", 1, new WslAgentToken(authToken: "0123456789abcdef")),
            ledgerPath: ledgerPath);
        return report.ToString().Split('\n').Single(l => l.Contains("audit ledger"));
    }
}
