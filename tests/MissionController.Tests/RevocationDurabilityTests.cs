using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Network.Identity;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A revocation is a circuit breaker: the only failure worth designing against is the one where it
/// says "not revoked" about a principal it never actually checked. These hold the two ways that
/// happens - a check that arrives while the list is still loading, and a list that cannot be read
/// at all - and the third thing a durable store owes, which is surviving a restart.
/// </summary>
public class RevocationDurabilityTests
{
    /// <summary>A store whose load blocks until released, so a check can be raced against it.</summary>
    private sealed class SlowStore : IRevocationStore
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly List<RevocationEntry> _entries;
        public readonly TaskCompletionSource LoadStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int Loads;

        public SlowStore(params RevocationEntry[] entries) => _entries = entries.ToList();

        public void Release() => _release.TrySetResult();

        public async Task<IReadOnlyList<RevocationEntry>> LoadRevocationsAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Loads);
            LoadStarted.TrySetResult();
            await _release.Task.WaitAsync(cancellationToken);
            return _entries;
        }

        public Task SaveRevocationAsync(RevocationEntry entry, CancellationToken cancellationToken = default)
            => Task.CompletedTask;
    }

    /// <summary>A store that refuses a given number of loads before working, and counts its writes.</summary>
    private sealed class FailingStore : IRevocationStore
    {
        private int _failuresLeft;
        public int Loads;
        public readonly List<RevocationEntry> Saved = new();
        public bool RefuseWrites;

        public FailingStore(int failures) => _failuresLeft = failures;

        public Task<IReadOnlyList<RevocationEntry>> LoadRevocationsAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Loads);
            if (Interlocked.Decrement(ref _failuresLeft) >= 0)
            {
                throw new SqliteException("database disk image is malformed", 11);
            }

            return Task.FromResult<IReadOnlyList<RevocationEntry>>(Saved.ToList());
        }

        public Task SaveRevocationAsync(RevocationEntry entry, CancellationToken cancellationToken = default)
        {
            if (RefuseWrites)
            {
                throw new SqliteException("attempt to write a readonly database", 8);
            }

            Saved.Add(entry);
            return Task.CompletedTask;
        }
    }

    private static (SqliteStorageContext Context, SqliteChainedAuditLedger Ledger, string DbPath) NewLedger()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"revocation_{Guid.NewGuid():N}.db");
        var context = new SqliteStorageContext(dbPath);
        return (context, new SqliteChainedAuditLedger(context), dbPath);
    }

    private static void Delete(string dbPath)
    {
        SqliteConnection.ClearAllPools();
        try { File.Delete(dbPath); } catch { /* the pool may still hold it; the temp folder is swept anyway */ }
    }

    [Fact]
    public async Task ACheckThatArrivesDuringTheColdStartLoad_WaitsForIt_RatherThanReadingAnEmptyIndex()
    {
        var (_, ledger, dbPath) = NewLedger();
        try
        {
            var revoked = new RevocationEntry("burned-key", "API_KEY", "Leaked in a paste", "SecOps", DateTimeOffset.UtcNow);
            var store = new SlowStore(revoked);
            var manager = new IncidentRevocationManager(ledger, store);

            // First caller enters the load and blocks inside it.
            var first = Task.Run(() => manager.CheckRevocationAsync("someone-else"));
            await store.LoadStarted.Task.WaitAsync(TimeSpan.FromSeconds(10));

            // Second caller arrives while the list is still being read. Before the load gate, it saw
            // the "initialized" flag the first caller had already set and read an empty index, so
            // this returned "not revoked" about a key that is in the list it had not read yet.
            var second = Task.Run(() => manager.CheckRevocationAsync("burned-key"));

            store.Release();

            Assert.True((await second.WaitAsync(TimeSpan.FromSeconds(10))).IsRevoked);
            Assert.False((await first.WaitAsync(TimeSpan.FromSeconds(10))).IsRevoked);
            Assert.Equal(1, store.Loads);
        }
        finally
        {
            Delete(dbPath);
        }
    }

    [Fact]
    public async Task AListThatCannotBeRead_RefusesToClearAnyone()
    {
        var (_, ledger, dbPath) = NewLedger();
        try
        {
            var manager = new IncidentRevocationManager(ledger, new FailingStore(failures: 99));

            var refused = await Assert.ThrowsAsync<RevocationUnavailableException>(
                () => manager.CheckRevocationAsync("anyone"));
            Assert.Contains("could not be read", refused.Message);

            // IsRevokedAsync is the same question with a narrower answer type; it must not smooth
            // the failure into false.
            await Assert.ThrowsAsync<RevocationUnavailableException>(() => manager.IsRevokedAsync("anyone"));
        }
        finally
        {
            Delete(dbPath);
        }
    }

    [Fact]
    public async Task AFailedLoad_IsRetriedOnTheNextCheck_RatherThanLatchedForTheProcessLifetime()
    {
        var (_, ledger, dbPath) = NewLedger();
        try
        {
            var store = new FailingStore(failures: 1);
            store.Saved.Add(new RevocationEntry("burned-key", "API_KEY", "Leaked", "SecOps", DateTimeOffset.UtcNow));
            var manager = new IncidentRevocationManager(ledger, store);

            await Assert.ThrowsAsync<RevocationUnavailableException>(() => manager.CheckRevocationAsync("burned-key"));

            Assert.True((await manager.CheckRevocationAsync("burned-key")).IsRevoked);
            Assert.Equal(2, store.Loads);

            // And once it has loaded, it is not read again.
            await manager.CheckRevocationAsync("burned-key");
            Assert.Equal(2, store.Loads);
        }
        finally
        {
            Delete(dbPath);
        }
    }

    [Fact]
    public async Task ARevocationTheStoreRefusesToWrite_StillTakesEffect_AndSaysSoInTheLedger()
    {
        var (_, ledger, dbPath) = NewLedger();
        try
        {
            var store = new FailingStore(failures: 0) { RefuseWrites = true };
            var manager = new IncidentRevocationManager(ledger, store);

            await Assert.ThrowsAsync<SqliteException>(
                () => manager.RevokeAsync("burned-key", "API_KEY", "Leaked", "SecOps"));

            // The caller was told, and the credential is dead for this process all the same.
            Assert.True((await manager.CheckRevocationAsync("burned-key")).IsRevoked);

            var rows = await ledger.GetAuditLogsAsync(Guid.Empty);
            var row = Assert.Single(rows, r => r.Action == "EMERGENCY_REVOCATION_NOT_PERSISTED");
            Assert.Contains("this process only", row.Details);
            Assert.DoesNotContain(rows, r => r.Action == "EMERGENCY_REVOCATION");
        }
        finally
        {
            Delete(dbPath);
        }
    }

    [Fact]
    public async Task ARevocationSurvivesARestart_ThroughTheSqliteStore()
    {
        var (context, ledger, dbPath) = NewLedger();
        try
        {
            var before = new IncidentRevocationManager(ledger, new SqliteRevocationStore(context));
            await before.RevokeAsync("burned", "API_KEY", "Leaked in a paste", "SecOps");

            // A new manager over a new context on the same file is what a restart looks like.
            var reopened = new SqliteStorageContext(dbPath);
            var after = new IncidentRevocationManager(
                new SqliteChainedAuditLedger(reopened), new SqliteRevocationStore(reopened));

            var status = await after.CheckRevocationAsync("burned");
            Assert.True(status.IsRevoked);
            Assert.Equal("Leaked in a paste", status.Entry?.Reason);
            Assert.Equal("SecOps", status.Entry?.RevokedBy);

            // An operator revokes the bare key; the ledger identity the gate checks carries its
            // provenance ("apikey:<key>"), and the suffix lookup is what joins the two.
            Assert.True(await after.IsRevokedAsync("apikey:burned"));
        }
        finally
        {
            Delete(dbPath);
        }
    }

}
