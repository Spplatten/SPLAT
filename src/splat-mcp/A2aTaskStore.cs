using System.Text.Json;
using MissionController.Infrastructure.Data;
using MissionController.Core.Interfaces;

namespace SplatMcp;

internal sealed record A2aTaskRecord(string Id, string ContextId, string TenantId, string CallerId,
    string MessageId, string RequestSha256, string Skill, string? CallerSuppliedParentTaskId,
    string State, DateTimeOffset UpdatedUtc, JsonElement? Result = null,
    bool CancellationRequested = false, string? Failure = null, LeaseSpec? AdmittedLease = null,
    DateTimeOffset? AuthorityExpiresUtc = null, string? DelegationNonce = null, int DelegationDepth = 0,
    bool WorkloadTerminationConfirmed = false);

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

    internal void Save(A2aTaskRecord task, bool insert = false, string? delegationIssuer = null)
    {
        using var connection = _context.CreateConnection();
        using var transaction = connection.BeginTransaction();
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
        transaction.Commit();
    }
}
