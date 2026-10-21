using System.Text.Json;
using Microsoft.Data.Sqlite;
using MissionController.Infrastructure.Data;
using MissionController.Core.Interfaces;

namespace SplatMcp;

internal sealed record A2aTaskRecord(string Id, string ContextId, string TenantId, string CallerId,
    string MessageId, string RequestSha256, string Skill, string? CallerSuppliedParentTaskId,
    string State, DateTimeOffset UpdatedUtc, JsonElement? Result = null,
    bool CancellationRequested = false, string? Failure = null, LeaseSpec? AdmittedLease = null,
    DateTimeOffset? AuthorityExpiresUtc = null, string? DelegationNonce = null, int DelegationDepth = 0,
    bool WorkloadTerminationConfirmed = false,
    // Saved before the request reaches the lease executor, under the same lock that records a
    // cancellation, so "never started" is a fact rather than a guess. Null on a record written before
    // the field existed: unknown, never read as "not dispatched".
    bool? Dispatched = null,
    // For a canceled or interrupted task: not-started (never dispatched), termination-verified (a
    // signed drain receipt), or unresolved (dispatched, and nothing proves how it ended).
    string? CancellationEvidence = null, bool ReceiptRecovered = false);

internal sealed class A2aTaskStore
{
    private readonly SqliteStorageContext _context;
    private readonly string _receiver;
    private readonly string _version;

    internal A2aTaskStore(SqliteStorageContext context, string receiver, string version)
    {
        _context = context; _receiver = receiver; _version = version;
        using var connection = context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS A2aTasks (
                Receiver TEXT NOT NULL, Version TEXT NOT NULL, TaskId TEXT NOT NULL,
                TenantId TEXT NOT NULL, CallerId TEXT NOT NULL, MessageId TEXT NOT NULL,
                RecordJson TEXT NOT NULL, PRIMARY KEY (Receiver, Version, TaskId),
                UNIQUE (Receiver, Version, TenantId, CallerId, MessageId));
            CREATE TABLE IF NOT EXISTS A2aDelegationUses (
                Issuer TEXT NOT NULL, Nonce TEXT NOT NULL, TaskId TEXT NOT NULL,
                PRIMARY KEY (Issuer, Nonce));
            -- Finished tasks moved out of active capacity. Rows are never deleted: a messageId is
            -- recognised forever, so a retry can return its task but never execute again, and spent
            -- delegation nonces stay in A2aDelegationUses.
            CREATE TABLE IF NOT EXISTS A2aTaskArchive (
                Receiver TEXT NOT NULL, Version TEXT NOT NULL, TaskId TEXT NOT NULL,
                TenantId TEXT NOT NULL, CallerId TEXT NOT NULL, MessageId TEXT NOT NULL,
                RequestSha256 TEXT NOT NULL, ArchivedUtc TEXT NOT NULL, RecordJson TEXT NOT NULL,
                PRIMARY KEY (Receiver, Version, TaskId),
                UNIQUE (Receiver, Version, TenantId, CallerId, MessageId));
            """;
        command.ExecuteNonQuery();
    }

    internal IReadOnlyList<A2aTaskRecord> Load(int maximum)
    {
        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT RecordJson FROM A2aTasks WHERE Receiver=@receiver AND Version=@version LIMIT @limit";
        command.Parameters.AddWithValue("@receiver", _receiver);
        command.Parameters.AddWithValue("@version", _version);
        command.Parameters.AddWithValue("@limit", maximum + 1);
        using var reader = command.ExecuteReader();
        var records = new List<A2aTaskRecord>();
        while (reader.Read()) records.Add(JsonSerializer.Deserialize<A2aTaskRecord>(reader.GetString(0), A2aConfiguration.Json)
            ?? throw new InvalidOperationException("Invalid persisted A2A task."));
        if (records.Count > maximum) throw new InvalidOperationException("Stored A2A tasks exceed the configured capacity.");
        return records;
    }

    /// <summary>
    /// Admits a new task in ONE transaction: consume its delegation nonce, insert the task, then let
    /// <paramref name="authorize"/> append the authorization row on the same connection. Execution may
    /// start only after this returns. A consumed nonce or a reused messageId rolls back everything,
    /// authorization included - the order audit-then-save left an A2A_TASK_AUTHORIZED row for every
    /// refused delegation replay.
    /// </summary>
    internal async Task AdmitAsync(A2aTaskRecord task, string? delegationIssuer,
        Func<SqliteConnection, SqliteTransaction, Task> authorize, CancellationToken ct)
    {
        using var connection = _context.CreateConnection();
        using var transaction = connection.BeginTransaction();
        if (FindArchived(connection, transaction, task.TenantId, task.CallerId, task.MessageId) is not null)
            throw new A2aException(-32602, "messageId already names a different request.");
        try
        {
            Write(connection, transaction, task, insert: true, delegationIssuer);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            // UNIQUE(Receiver, Version, Tenant, Caller, MessageId): a retained task already holds this
            // messageId - e.g. one whose skill this caller is no longer granted, so the replay lookup
            // could not see it. A refusal, not a server fault, and nothing is written.
            throw new A2aException(-32602, "messageId already names a different request.");
        }
        await authorize(connection, transaction);
        ct.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    /// <summary>
    /// Moves a finished task out of A2aTasks into the archive, and appends its archival entry, in one
    /// transaction. Its result stays readable through <see cref="ReadArchived"/>.
    /// </summary>
    internal async Task ArchiveAsync(A2aTaskRecord task, Func<SqliteConnection, SqliteTransaction, Task> audit,
        CancellationToken ct)
    {
        using var connection = _context.CreateConnection();
        using var transaction = connection.BeginTransaction();
        using (var insert = connection.CreateCommand())
        {
            insert.Transaction = transaction;
            insert.CommandText = "INSERT INTO A2aTaskArchive VALUES (@receiver,@version,@id,@tenant,@caller,@message,@sha,@at,@json)";
            insert.Parameters.AddWithValue("@receiver", _receiver);
            insert.Parameters.AddWithValue("@version", _version);
            insert.Parameters.AddWithValue("@id", task.Id);
            insert.Parameters.AddWithValue("@tenant", task.TenantId);
            insert.Parameters.AddWithValue("@caller", task.CallerId);
            insert.Parameters.AddWithValue("@message", task.MessageId);
            insert.Parameters.AddWithValue("@sha", task.RequestSha256);
            insert.Parameters.AddWithValue("@at", DateTimeOffset.UtcNow.ToString("O"));
            insert.Parameters.AddWithValue("@json", JsonSerializer.Serialize(task, A2aConfiguration.Json));
            insert.ExecuteNonQuery();
        }
        using (var delete = connection.CreateCommand())
        {
            delete.Transaction = transaction;
            delete.CommandText = "DELETE FROM A2aTasks WHERE Receiver=@receiver AND Version=@version AND TaskId=@id";
            delete.Parameters.AddWithValue("@receiver", _receiver);
            delete.Parameters.AddWithValue("@version", _version);
            delete.Parameters.AddWithValue("@id", task.Id);
            if (delete.ExecuteNonQuery() != 1) throw new InvalidOperationException("A2A task to archive was not retained.");
        }
        await audit(connection, transaction);
        ct.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    /// <summary>An archived task's id and request fingerprint for a caller's messageId, or null.</summary>
    internal (string TaskId, string RequestSha256)? FindArchived(string tenant, string caller, string messageId)
    {
        using var connection = _context.CreateConnection();
        return FindArchived(connection, null, tenant, caller, messageId);
    }

    private (string TaskId, string RequestSha256)? FindArchived(SqliteConnection connection, SqliteTransaction? transaction,
        string tenant, string caller, string messageId)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT TaskId, RequestSha256 FROM A2aTaskArchive WHERE Receiver=@receiver AND Version=@version AND TenantId=@tenant AND CallerId=@caller AND MessageId=@message";
        command.Parameters.AddWithValue("@receiver", _receiver);
        command.Parameters.AddWithValue("@version", _version);
        command.Parameters.AddWithValue("@tenant", tenant);
        command.Parameters.AddWithValue("@caller", caller);
        command.Parameters.AddWithValue("@message", messageId);
        using var reader = command.ExecuteReader();
        return reader.Read() ? (reader.GetString(0), reader.GetString(1)) : null;
    }

    /// <summary>An archived task owned by this tenant and caller, or null.</summary>
    internal A2aTaskRecord? ReadArchived(string taskId, string tenant, string caller)
    {
        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT RecordJson FROM A2aTaskArchive WHERE Receiver=@receiver AND Version=@version AND TaskId=@id AND TenantId=@tenant AND CallerId=@caller";
        command.Parameters.AddWithValue("@receiver", _receiver);
        command.Parameters.AddWithValue("@version", _version);
        command.Parameters.AddWithValue("@id", taskId);
        command.Parameters.AddWithValue("@tenant", tenant);
        command.Parameters.AddWithValue("@caller", caller);
        return command.ExecuteScalar() is string json ? JsonSerializer.Deserialize<A2aTaskRecord>(json, A2aConfiguration.Json) : null;
    }

    internal async Task RecoverAsync(A2aTaskRecord task,
        Func<SqliteConnection, SqliteTransaction, Task> audit, CancellationToken ct)
    {
        using var connection = _context.CreateConnection();
        using var transaction = connection.BeginTransaction();
        int updated = 0;
        // Archival can finish while lookup is in flight. Update whichever table owns the task;
        // never recreate an active row or give a consumed message/nonce another admission.
        foreach (string table in new[] { "A2aTasks", "A2aTaskArchive" })
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = $"UPDATE {table} SET RecordJson=@json WHERE Receiver=@receiver AND Version=@version AND TaskId=@id AND TenantId=@tenant AND CallerId=@caller";
            command.Parameters.AddWithValue("@receiver", _receiver);
            command.Parameters.AddWithValue("@version", _version);
            command.Parameters.AddWithValue("@id", task.Id);
            command.Parameters.AddWithValue("@tenant", task.TenantId);
            command.Parameters.AddWithValue("@caller", task.CallerId);
            command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(task, A2aConfiguration.Json));
            updated += command.ExecuteNonQuery();
        }
        if (updated != 1) throw new InvalidOperationException("Receipt recovery requires exactly one persisted task.");
        await audit(connection, transaction);
        ct.ThrowIfCancellationRequested();
        transaction.Commit();
    }

    internal void Save(A2aTaskRecord task, bool insert = false, string? delegationIssuer = null)
    {
        using var connection = _context.CreateConnection();
        using var transaction = connection.BeginTransaction();
        Write(connection, transaction, task, insert, delegationIssuer);
        transaction.Commit();
    }

    private void Write(SqliteConnection connection, SqliteTransaction transaction, A2aTaskRecord task, bool insert,
        string? delegationIssuer)
    {
        if (insert && task.DelegationNonce is not null)
        {
            using var consume = connection.CreateCommand();
            consume.Transaction = transaction;
            consume.CommandText = "INSERT OR IGNORE INTO A2aDelegationUses VALUES (@issuer,@nonce,@task)";
            consume.Parameters.AddWithValue("@issuer", delegationIssuer ?? throw new InvalidOperationException("Delegation issuer required."));
            consume.Parameters.AddWithValue("@nonce", task.DelegationNonce);
            consume.Parameters.AddWithValue("@task", task.Id);
            if (consume.ExecuteNonQuery() != 1)
                throw new A2aException(-32000, "Delegation was already consumed; retry the original messageId.", 403);
        }
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = insert
            ? "INSERT INTO A2aTasks VALUES (@receiver,@version,@id,@tenant,@caller,@message,@json)"
            : "UPDATE A2aTasks SET RecordJson=@json WHERE Receiver=@receiver AND Version=@version AND TaskId=@id AND TenantId=@tenant AND CallerId=@caller AND MessageId=@message";
        command.Parameters.AddWithValue("@receiver", _receiver);
        command.Parameters.AddWithValue("@version", _version);
        command.Parameters.AddWithValue("@id", task.Id);
        command.Parameters.AddWithValue("@tenant", task.TenantId);
        command.Parameters.AddWithValue("@caller", task.CallerId);
        command.Parameters.AddWithValue("@message", task.MessageId);
        command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(task, A2aConfiguration.Json));
        if (command.ExecuteNonQuery() != 1) throw new InvalidOperationException("A2A task persistence failed.");
    }
}
