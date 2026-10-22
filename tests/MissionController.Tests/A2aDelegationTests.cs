using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using SplatMcp;

namespace MissionController.Tests;

public sealed class A2aDelegationTests : IAsyncLifetime
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splat-delegation-" + Guid.NewGuid().ToString("N"));
    private readonly Capture _capture = new();
    private readonly string _token = new('t', 64);
    private A2aBridge _parent = null!, _worker = null!;
    private AgentManifestApproval _parentApproval = null!, _workerApproval = null!;
    private SqliteStorageContext _parentDb = null!, _workerDb = null!;
    private A2aConfiguration _workerConfig = null!;
    private SqliteChainedAuditLedger _workerLedger = null!;

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(_root);
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        string keyFile = Path.Combine(_root, "delegation.pem");
        File.WriteAllText(keyFile, key.ExportECPrivateKeyPem());
        string certFile = Path.Combine(_root, "server.pfx");
        using (var cert = A2aBridgeTests.Certificate()) File.WriteAllBytes(certFile, cert.Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12));
        _parentDb = new(Path.Combine(_root, "parent.db")); _workerDb = new(Path.Combine(_root, "worker.db"));
        _parentApproval = await Import(_parentDb, "parent-agent", restricted: true);
        _workerApproval = await Import(_workerDb, "worker-agent", restricted: false);
        var caller = new A2aCaller("tenant", "caller", A2aDelegation.Digest(_token), ["read"], DateTimeOffset.UtcNow.AddHours(1));
        var parentConfig = new A2aConfiguration(1, _parentApproval.AgentId, _parentApproval.Sha256,
            28001, certFile, [caller], DelegationKeyFile: keyFile);
        _workerConfig = new(1, _workerApproval.AgentId, _workerApproval.Sha256, 28002, certFile,
            [caller with { RequireDelegation = true }], DelegationIssuers:
            [new(_parentApproval.AgentId, _parentApproval.Sha256, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()))]);
        var ledger = new SqliteChainedAuditLedger(_parentDb);
        _workerLedger = new(_workerDb);
        _parent = Bridge(parentConfig, _parentApproval, _parentDb, ledger);
        _worker = Bridge(_workerConfig, _workerApproval, _workerDb, _workerLedger);
    }

    private static async Task<AgentManifestApproval> Import(SqliteStorageContext db, string id, bool restricted)
    {
        var policy = new ExecutionPolicy(1, "x86_64", ["execve", "exit_group", "write", "close", "read", "openat"],
            [new("/proc/version", ["read"]), new("/usr/bin/cat", ["read", "execute"])]);
        var manifest = new AgentManifest(1, id, id, "Synthetic delegation", "Read public guest evidence", "local", [
            new("read", "linux-guest-identity", ExecutionPolicy: restricted ? policy : null)]);
        var importer = new AgentManifestImporter(db);
        var imported = await importer.ImportAsync(JsonSerializer.Serialize(manifest, A2aConfiguration.Json));
        return await importer.LoadApprovedAsync(id, AgentManifestApproval.Hash(imported));
    }

    private A2aBridge Bridge(A2aConfiguration config, AgentManifestApproval approval, SqliteStorageContext db, SqliteChainedAuditLedger ledger) =>
        new(config, approval, db, ledger, caller => new McpServerHandler(_capture, new TemplatePolicyCompiler(), ledger,
            agent: approval, identityProvider: new StaticOperatorIdentityProvider(caller.Identity)));

    private async Task<JsonElement> Call(A2aBridge bridge, string method, object parameters) => JsonSerializer.SerializeToElement(
        await bridge.DispatchAsync(bridge.Authenticate("Bearer " + _token)!, method,
            JsonSerializer.SerializeToElement(parameters, A2aConfiguration.Json), CancellationToken.None), A2aConfiguration.Json);

    private static object Message(string id, string? token = null, string? parent = null) => new
    {
        message = new { messageId = id, role = "ROLE_USER", parts = new[] { new { data = new {
            skill = "read", parameters = new { }, delegationToken = token, parentTaskId = parent } } } }
    };

    private async Task<(string Token, string Parent)> Grant()
    {
        string parent = (await Call(_parent, "SendMessage", Message(Guid.NewGuid().ToString("N"))))
            .GetProperty("task").GetProperty("id").GetString()!;
        var grant = await Call(_parent, "splat/DelegateTask", new { parentTaskId = parent, audience = _workerApproval.AgentId,
            audienceVersion = _workerApproval.Sha256, callerId = "caller", skill = "read" });
        return (grant.GetProperty("delegationToken").GetString()!, parent);
    }

    [Fact]
    public async Task TwoAgentDelegationCarriesOnlyTheParentTaskAuthorityAndSurvivesReceiverRestart()
    {
        var grant = await Grant();
        var message = Message("delegated", grant.Token, grant.Parent);
        var result = await Call(_worker, "SendMessage", message);
        Assert.Equal("TASK_STATE_COMPLETED", result.GetProperty("task").GetProperty("status").GetProperty("state").GetString());
        Assert.Equal(2, _capture.Leases.Count);
        var parent = _capture.Leases[0]; var worker = _capture.Leases[1];
        Assert.NotNull(worker.ExecutionPolicy);
        Assert.Equal(JsonSerializer.Serialize(parent.ExecutionPolicy), JsonSerializer.Serialize(worker.ExecutionPolicy));
        Assert.True(worker.LeaseDurationSeconds <= parent.LeaseDurationSeconds);
        Assert.Equal("parent-agent", worker.ExecutionContext!.RequestingAgentId);
        Assert.Equal(grant.Parent, worker.ExecutionContext.ParentTaskId);
        Assert.Equal(A2aDelegation.Digest(grant.Token), worker.ExecutionContext.DelegationSha256);
        await _worker.DisposeAsync();
        _worker = Bridge(_workerConfig, _workerApproval, _workerDb, _workerLedger);
        await Call(_worker, "SendMessage", message);
        Assert.Equal(2, _capture.Leases.Count);
        await Assert.ThrowsAsync<A2aException>(() => Call(_worker, "SendMessage", Message("replayed", grant.Token)));
        Assert.Equal(2, _capture.Leases.Count);

        // A refused replay leaves no authorization behind. Admission wrote A2A_TASK_AUTHORIZED before
        // the store rejected the spent nonce, so the 2026-10-20 A2A stress run found 16 authorization
        // rows with no task; nonce, task and authorization now commit in one transaction.
        await Task.WhenAll(Enumerable.Range(0, 8).Select(i =>
            Assert.ThrowsAsync<A2aException>(() => Call(_worker, "SendMessage", Message($"replayed-{i}", grant.Token)))));
        Assert.Equal(2, _capture.Leases.Count);
        var authorized = (await _workerLedger.GetAuditLogsAsync(null, 500)).Count(r => r.Action == "A2A_TASK_AUTHORIZED");
        Assert.Equal(1, authorized);

        // An authorization that cannot be written admits nothing. Keying the worker's ledger makes the
        // unkeyed bridge's append fail mid-admission; a fresh, valid grant must then leave no task row,
        // no authorization row and no execution behind.
        await new SqliteChainedAuditLedger(_workerDb, new byte[32]).AppendLogAsync(Guid.Empty, "test", "KEYED", "", "test");
        var fresh = await Grant();
        await Assert.ThrowsAnyAsync<Exception>(() => Call(_worker, "SendMessage", Message("unauditable", fresh.Token, fresh.Parent)));
        Assert.Equal(3, _capture.Leases.Count); // the parent's lease for the fresh grant; the worker ran nothing
        using var connection = _workerDb.CreateConnection();
        using var tasks = connection.CreateCommand();
        tasks.CommandText = "SELECT COUNT(*) FROM A2aTasks WHERE MessageId = 'unauditable'";
        Assert.Equal(0L, (long)tasks.ExecuteScalar()!);
        using var uses = connection.CreateCommand();
        uses.CommandText = "SELECT COUNT(*) FROM A2aDelegationUses";
        Assert.Equal(1L, (long)uses.ExecuteScalar()!); // only the first grant's nonce was ever consumed
    }

    [Fact]
    public async Task MissingForgedAndMismatchedParentDelegationsCannotReachTheWorker()
    {
        var grant = await Grant();
        await Assert.ThrowsAsync<A2aException>(() => Call(_worker, "SendMessage", Message("missing")));
        await Assert.ThrowsAsync<A2aException>(() => Call(_worker, "SendMessage", Message("forged", "A" + grant.Token[1..])));
        await Assert.ThrowsAsync<A2aException>(() => Call(_worker, "SendMessage", Message("wrong-parent", grant.Token, "another-task")));
        var stranger = new A2aCaller("other-tenant", "caller", "", ["read"], DateTimeOffset.UtcNow.AddHours(1));
        using var verifier = new A2aDelegation(_workerConfig);
        Assert.Throws<A2aException>(() => verifier.Verify(grant.Token, stranger, "read"));
        Assert.Throws<A2aException>(() => verifier.Verify(grant.Token, _workerConfig.Callers[0], "another-skill"));
        Assert.Single(_capture.Leases);
    }

    [Theory]
    [InlineData("audience")]
    [InlineData("audience-version")]
    [InlineData("issuer-version")]
    [InlineData("caller")]
    [InlineData("expired")]
    [InlineData("overlong")]
    [InlineData("depth")]
    public async Task AuthenticSignaturesCannotAuthorizeOutOfScopeClaims(string mutation)
    {
        var grant = await Grant();
        static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string encoded = grant.Token.Split('.')[0].Replace('-', '+').Replace('_', '/');
        var claim = JsonSerializer.Deserialize<A2aDelegationGrant>(Convert.FromBase64String(encoded
            + new string('=', (4 - encoded.Length % 4) % 4)), A2aConfiguration.Json)!;
        claim = mutation switch
        {
            "audience" => claim with { Audience = "another-worker" },
            "audience-version" => claim with { AudienceVersion = new string('0', 64) },
            "issuer-version" => claim with { IssuerVersion = new string('0', 64) },
            "caller" => claim with { CallerId = "another-caller" },
            "expired" => claim with { ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1) },
            "overlong" => claim with { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10) },
            "depth" => claim with { Depth = 5 },
            _ => throw new InvalidOperationException()
        };
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(claim, A2aConfiguration.Json);
        using var key = ECDsa.Create();
        key.ImportFromPem(await File.ReadAllTextAsync(Path.Combine(_root, "delegation.pem")));
        string signed = Encode(payload) + "." + Encode(key.SignData(payload, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        using var verifier = new A2aDelegation(_workerConfig);
        Assert.Throws<A2aException>(() => verifier.Verify(signed, _workerConfig.Callers[0], "read"));
        Assert.Single(_capture.Leases);
    }

    public async Task DisposeAsync()
    {
        if (_worker is not null) await _worker.DisposeAsync();
        if (_parent is not null) await _parent.DisposeAsync();
        foreach (var db in new[] { _workerDb, _parentDb }) if (db is not null)
        { using var connection = db.CreateConnection(); SqliteConnection.ClearPool(connection); }
        if (Directory.Exists(_root)) Directory.Delete(_root, true);
    }

    private sealed class Capture : ILeasedExecutor
    {
        internal readonly List<LeaseSpec> Leases = [];
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null, IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default)
        {
            Leases.Add(lease);
            return Task.FromResult(new ProcessExecutionResult(0, "synthetic", "", false, JobResourceMetrics.Unavailable));
        }
    }
}
