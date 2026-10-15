using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Linux;
using SplatMcp;

namespace MissionController.Tests;

/// <summary>
/// The ledger half of the 2.4 gate, run against a real keyed chain: the bridge probe cannot read the
/// service's ledger, so the audit is the only thing that scores whose name each admission row carries.
/// </summary>
public sealed class ManagedLedgerAuditTests : IDisposable
{
    private const string ServiceSid = "S-1-5-21-1-2-3-1500";
    private static readonly OperatorIdentity Caller = new(@"HOST\operator", "S-1-5-21-1-2-3-1001",
        OperatorAuthenticationMethod.WindowsAuthenticated, ManagedBridgeHost.Transport);
    private readonly string _state = Path.Combine(Path.GetTempPath(), "splat-ledger-audit-test-" + Guid.NewGuid().ToString("N"));
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(64);

    public ManagedLedgerAuditTests()
    {
        Directory.CreateDirectory(_state);
        File.WriteAllBytes(Path.Combine(_state, "ledger.key"), _key);
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        try { Directory.Delete(_state, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }

    private SqliteChainedAuditLedger Ledger(byte[]? key = null) =>
        new(new SqliteStorageContext(Path.Combine(_state, "ledger.db")), key ?? _key);

    private static JsonElement Probe(DateTimeOffset started, string digest) => JsonSerializer.SerializeToElement(new
    {
        Verdict = "PASS", ServiceSid, CallerSid = Caller.PrincipalId, CallerName = Caller.DisplayName,
        At = started.ToString("o"), FinishedAt = DateTimeOffset.UtcNow.ToString("o"),
        Admissions = new[] { new { Id = 2, Tool = "run_command", RequestSha256 = digest, ClaimedPrincipal = "S-1-5-18" } }
    });

    private Task<ManagedLedgerAudit.Report> Audit(JsonElement probe) =>
        ManagedLedgerAudit.AuditAsync(ServiceSid, new[] { Caller.PrincipalId! }, _state, probe, default);

    [Fact]
    public async Task TheAudit_FindsTheAdmissionUnderThePipeCaller_NotThePrincipalTheRequestClaimed()
    {
        var started = DateTimeOffset.UtcNow;
        var request = new McpJsonRpcMessage
        {
            JsonRpc = "2.0", Id = JsonSerializer.SerializeToElement(2), Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "run_command",
                arguments = new { command = "/bin/echo", args = new[] { "hi" }, operatorIdentity = "SYSTEM", principalId = "S-1-5-18" }
            })
        };
        var identity = new ManagedPipeIdentity();
        identity.Set(Caller);
        var ledger = Ledger();
        var handler = new McpServerHandler(new Executor(), new TemplatePolicyCompiler(), ledger, identityProvider: identity);
        Assert.Null((await ManagedBridgeHost.DispatchAsync(request, handler, ledger, identity, default)).Error);

        var report = await Audit(Probe(started, ManagedBridgeHost.RequestSha256(request.Params)));

        Assert.True(report.Verdict == "PASS", string.Join(", ", report.Checks.Where(check => !check.Value).Select(check => check.Key)));
    }

    [Fact]
    public async Task TheAudit_FailsAnAdmissionRowThatNamesTheClaimedPrincipal()
    {
        var started = DateTimeOffset.UtcNow;
        string digest = new('a', 64);
        var system = new OperatorIdentity("SYSTEM", "S-1-5-18", OperatorAuthenticationMethod.WindowsAuthenticated, ManagedBridgeHost.Transport);
        await Ledger().AppendLogAsync(Guid.NewGuid(), "mcp-tool-run_command", ManagedBridgeHost.AdmissionAction,
            ManagedBridgeHost.AdmissionDetails("run_command", digest), system.ToLedgerIdentity());

        var report = await Audit(Probe(started, digest));

        Assert.Equal("FAIL", report.Verdict);
        Assert.False(report.Checks["Admitted:2:run_command"]);
        Assert.False(report.Checks["ClaimedIdentityIgnored"]);
    }

    [Fact]
    public async Task TheAudit_FailsAChainTheServiceKeyDidNotWrite()
    {
        var started = DateTimeOffset.UtcNow;
        string digest = new('b', 64);
        await Ledger(RandomNumberGenerator.GetBytes(64)).AppendLogAsync(Guid.NewGuid(), "mcp-tool-run_command",
            ManagedBridgeHost.AdmissionAction, ManagedBridgeHost.AdmissionDetails("run_command", digest), Caller.ToLedgerIdentity());

        var report = await Audit(Probe(started, digest));

        Assert.Equal("FAIL", report.Verdict);
        Assert.False(report.Checks["LedgerKeyedByTheServiceKey"]);
        Assert.False(report.Checks["ChainVerifies"]);
    }

    [Fact]
    public void TheServiceDigest_IsThePowerShellDigestOfTheParamsTextTheProbeSent()
    {
        // A line exactly as probe-managed-bridge.ps1 builds it under Windows PowerShell 5.1, which
        // escapes quotes as \u0027, beside the SHA-256 that PowerShell computed over its params text.
        // The audit finds rows by this value, so the service must hash the text as sent, not re-encoded.
        const string line = """{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"arguments":{"code":"import socket\ns=socket.socket()\ntry:\n s.connect((\u0027127.0.0.1\u0027,9))\n print(\u0027UNEXPECTED_CONNECT\u0027)\nexcept OSError as e:\n print(\u0027DENIED_ERRNO\u0027,e.errno)","language":"python"},"name":"run_code"}}""";

        var message = JsonSerializer.Deserialize<McpJsonRpcMessage>(line)!;

        Assert.Equal("171d364a34da0d0a18192f486d28492aef3f04b07da349dc989fecdb6232db25", ManagedBridgeHost.RequestSha256(message.Params));
    }

    private sealed class Executor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null, IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default) =>
            Task.FromResult(new ProcessExecutionResult(0, "hi", "", false, JobResourceMetrics.Unavailable));
    }
}
