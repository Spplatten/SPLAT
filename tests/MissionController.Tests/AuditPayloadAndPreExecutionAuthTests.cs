using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Identity;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Two audit P1s, each asserted at the place the previous test only described.
///
/// The ledger suite already had a test named for payload tampering that edited the COMMITMENT
/// column instead of the payload, and the MCP suite already had one asserting a rejected credential
/// returns an error and writes no ledger row - neither of which touched the actual defect, which was
/// that the displayed narrative was never verified and that execution happened before the check.
/// </summary>
public class AuditPayloadAndPreExecutionAuthTests : IDisposable
{
    private readonly string _dbPath;
    private readonly SqliteStorageContext _context;

    public AuditPayloadAndPreExecutionAuthTests()
    {
        _dbPath = Path.Combine(Path.GetTempPath(), $"splat_payload_{Guid.NewGuid():N}.db");
        _context = new SqliteStorageContext(_dbPath);
    }

    public void Dispose()
    {
        if (File.Exists(_dbPath))
        {
            try { File.Delete(_dbPath); } catch { }
        }
    }

    private void ExecuteSql(string sql, params (string Name, object Value)[] parameters)
    {
        using var conn = _context.CreateConnection();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            cmd.Parameters.AddWithValue(name, value);
        }
        cmd.ExecuteNonQuery();
    }

    // ------------------------------------------------------------------ ledger payload integrity

    [Fact]
    public async Task EditingOnlyTheDisplayedDetails_FailsVerification()
    {
        var ledger = new SqliteChainedAuditLedger(_context);
        await ledger.AppendLogAsync(Guid.NewGuid(), "tpl-1", "MISSION_COMPLETED", "exit code 3, probe refused", "jsmith");

        Assert.True(await ledger.VerifyLedgerIntegrityAsync());

        // The exact attack the audit describes: the narrative an auditor reads is rewritten, and
        // every column the chain hash consumes is left untouched.
        ExecuteSql(
            "UPDATE AuditLedger SET Details = $forged WHERE Id = 1;",
            ("$forged", "Operator approved all security overrides. All systems healthy."));

        Assert.False(await ledger.VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task ARowForgedToLookRedacted_FailsVerification()
    {
        var ledger = new SqliteChainedAuditLedger(_context);
        await ledger.AppendLogAsync(Guid.NewGuid(), "tpl-1", "ACTION", "original detail", "operator");

        // Marking a row redacted is how a payload legitimately becomes unverifiable, so it must not
        // be a way to smuggle text past the commitment check. A genuine sweep destroys the salt.
        ExecuteSql(
            "UPDATE AuditLedger SET Details = $forged, RedactedAtUtc = $now WHERE Id = 1;",
            ("$forged", "nothing to see here"),
            ("$now", DateTime.UtcNow.ToString("O")));

        Assert.False(await ledger.VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task AGenuineRedaction_StillVerifies()
    {
        var ledger = new SqliteChainedAuditLedger(_context);
        await ledger.AppendLogAsync(Guid.NewGuid(), "tpl-1", "ACTION", "operator jsmith on WS-04", "jsmith");

        await ledger.RedactDetailsOlderThanAsync(DateTime.UtcNow.AddMinutes(1));

        // Cryptographic erasure must stay distinguishable from tampering, or retention breaks the
        // very evidence it exists to preserve.
        Assert.True(await ledger.VerifyLedgerIntegrityAsync());
    }

    [Fact]
    public async Task AnUnkeyedChain_DoesNotVerifyOnceAKeyIsConfigured()
    {
        var unkeyed = new SqliteChainedAuditLedger(_context);
        await unkeyed.AppendLogAsync(Guid.NewGuid(), "tpl-1", "ACTION", "written before a key existed", "operator");
        Assert.True(await unkeyed.VerifyLedgerIntegrityAsync());

        var keyed = new SqliteChainedAuditLedger(_context, explicitHmacKey: RandomNumberGenerator.GetBytes(32));

        // The verifier used to retry without the key when the keyed check failed, so a writer who
        // could rewrite the database could replace a keyed chain with plain SHA-256 and still pass.
        // Recovering a genuinely pre-key ledger is a recorded migration, not a silent downgrade.
        Assert.False(await keyed.VerifyLedgerIntegrityAsync());
    }

    // -------------------------------------------------------------- MCP identity before effects

    /// <summary>Counts invocations so a test can assert an executor was never reached at all.</summary>
    private sealed class CountingLeasedExecutor : ILeasedExecutor
    {
        public int Invocations;

        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Invocations);
            return Task.FromResult(new ProcessExecutionResult(0, "ok", "", false, JobResourceMetrics.Unavailable));
        }
    }

    private sealed class NullLedger : IAuditLedger
    {
        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private static McpServerHandler HandlerWithRejectedCredential(
        CountingLeasedExecutor executor, string workspaceRoot) =>
        new(
            executor,
            new TemplatePolicyCompiler(),
            new NullLedger(),
            identityProvider: new McpOperatorIdentityProvider(
                new StaticOperatorIdentityProvider(OperatorIdentity.Unknown()),
                apiKeyValidator: new ApiKeyValidator(),
                presentedCredential: "k-forged"),
            workspaceRoot: workspaceRoot);

    private static McpJsonRpcMessage ToolCall(string tool, object arguments) =>
        new()
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new { name = tool, arguments })
        };

    [Fact]
    public async Task ARejectedCredential_ReachesNoExecutor()
    {
        string workspace = Path.Combine(Path.GetTempPath(), $"splat_ws_{Guid.NewGuid():N}");
        var executor = new CountingLeasedExecutor();
        var handler = HandlerWithRejectedCredential(executor, workspace);

        var response = await handler.ProcessMessageAsync(ToolCall("run_command", new { command = "/bin/true" }));

        Assert.NotNull(response.Error);
        Assert.Contains("Authentication failed", response.Error!.Message);

        // The assertion the previous test was missing. An error response after the command already
        // ran is not a refusal, it is a receipt.
        Assert.Equal(0, executor.Invocations);
    }

    [Fact]
    public async Task ARejectedCredential_WritesNoFile()
    {
        string workspace = Path.Combine(Path.GetTempPath(), $"splat_ws_{Guid.NewGuid():N}");
        Directory.CreateDirectory(workspace);
        try
        {
            var handler = HandlerWithRejectedCredential(new CountingLeasedExecutor(), workspace);
            string target = Path.Combine(workspace, "written-by-a-rejected-caller.txt");

            var response = await handler.ProcessMessageAsync(
                ToolCall("fs_write", new { path = target, content = "payload" }));

            Assert.NotNull(response.Error);
            Assert.False(File.Exists(target), "fs_write must not touch disk before the caller is authenticated.");
        }
        finally
        {
            try { Directory.Delete(workspace, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task AnAcceptedCredential_StillReachesTheExecutor()
    {
        // The gate must refuse the rejected caller without also refusing the legitimate one.
        var executor = new CountingLeasedExecutor();
        var handler = new McpServerHandler(
            executor,
            new TemplatePolicyCompiler(),
            new NullLedger(),
            identityProvider: new McpOperatorIdentityProvider(
                new StaticOperatorIdentityProvider(new OperatorIdentity(
                    @"CONTOSO\sean", "S-1-5-21-42", OperatorAuthenticationMethod.WindowsAuthenticated))));

        var response = await handler.ProcessMessageAsync(ToolCall("run_command", new { command = "/bin/true" }));

        Assert.Null(response.Error);
        Assert.Equal(1, executor.Invocations);
    }
}
