using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;
using SplatMcp;

namespace MissionController.Tests;

public sealed class ManagedBridgeTests
{
    private static readonly OperatorIdentity Caller = new("test-caller", "S-1-5-21-1-2-3-1001",
        OperatorAuthenticationMethod.WindowsAuthenticated, "mcp-managed-pipe");
    private static McpJsonRpcMessage Request(string tool, object arguments) => new()
    {
        JsonRpc = "2.0", Id = JsonSerializer.SerializeToElement(1), Method = "tools/call",
        Params = JsonSerializer.SerializeToElement(new { name = tool, arguments })
    };
    private static (McpServerHandler Handler, ManagedPipeIdentity Identity, Executor Executor, Ledger Ledger) Host()
    {
        var identity = new ManagedPipeIdentity();
        var ledger = new Ledger();
        var executor = new Executor(ledger);
        return (new McpServerHandler(executor, new TemplatePolicyCompiler(), ledger, identityProvider: identity), identity, executor, ledger);
    }

    [Fact]
    public async Task AdmissionFailurePreventsExecutionAndDoesNotDisclosePrivatePath()
    {
        var host = Host(); host.Identity.Set(Caller); host.Ledger.Fail = true;
        var response = await ManagedBridgeHost.DispatchAsync(Request("run_command", new { command = "/bin/echo", args = new[] { "hi" } }),
            host.Handler, host.Ledger, host.Identity, default);
        Assert.Equal(-32001, response.Error?.Code);
        Assert.DoesNotContain("private-path", response.Error!.Message);
        Assert.Equal(0, host.Executor.Calls);
    }

    [Theory]
    [InlineData("fs_read")]
    [InlineData("execute_mission")]
    [InlineData("revoke_operator")]
    public async Task PrivilegedHostToolsCannotBeCalledThroughManagedPipe(string tool)
    {
        var host = Host(); host.Identity.Set(Caller);
        var response = await ManagedBridgeHost.DispatchAsync(Request(tool, new { path = "C:\\Windows" }), host.Handler, host.Ledger, host.Identity, default);
        Assert.Equal(-32601, response.Error?.Code);
        Assert.Empty(host.Ledger.Entries);
        Assert.Equal(0, host.Executor.Calls);
    }

    [Fact]
    public async Task ExecutionFollowsAdmissionAndUsesTokenIdentityInsteadOfCallerArguments()
    {
        var host = Host(); host.Identity.Set(Caller);
        var response = await ManagedBridgeHost.DispatchAsync(Request("run_command", new
        {
            command = "/bin/echo", args = new[] { "hi" }, operatorIdentity = "administrator", principalId = "S-1-5-18"
        }), host.Handler, host.Ledger, host.Identity, default);
        Assert.Null(response.Error);
        Assert.Equal(1, host.Executor.Calls);
        Assert.Equal("MANAGED_CALL_ADMITTED", host.Ledger.Entries[0].Action);
        Assert.Contains("request_sha256=", host.Ledger.Entries[0].Details);
        Assert.All(host.Ledger.Entries, entry => Assert.Equal(Caller.ToLedgerIdentity(), entry.OperatorIdentity));
    }

    [Fact]
    public async Task ToolListContainsOnlyServiceAuthorizedLinuxTools()
    {
        var host = Host(); host.Identity.Set(Caller);
        var response = await ManagedBridgeHost.DispatchAsync(new McpJsonRpcMessage { Method = "tools/list" }, host.Handler, host.Ledger, host.Identity, default);
        var names = response.Result!.Value.GetProperty("tools").EnumerateArray().Select(x => x.GetProperty("name").GetString()).ToArray();
        Assert.Equal(ManagedBridgeHost.AllowedTools.Order(), names.Order());
    }

    [Fact]
    public async Task UntrustedTransportAndMissingTokenIdentityCannotReachExecutor()
    {
        var host = Host();
        await Assert.ThrowsAsync<McpAuthenticationException>(() => ManagedBridgeHost.DispatchAsync(Request("run_command", new { command = "/bin/echo" }), host.Handler, host.Ledger, host.Identity, default));
        host.Identity.Set(Caller with { Transport = "mcp-stdio" });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => ManagedBridgeHost.DispatchAsync(Request("run_command", new { command = "/bin/echo" }), host.Handler, host.Ledger, host.Identity, default));
        Assert.Equal(0, host.Executor.Calls);
    }

    [Fact]
    public async Task CallerIdentityDoesNotLeakBetweenConcurrentConnections()
    {
        var provider = new ManagedPipeIdentity();
        async Task<string> Resolve(string sid)
        {
            provider.Set(Caller with { PrincipalId = sid });
            await Task.Yield();
            return (await provider.ResolveAsync()).PrincipalId!;
        }
        var identities = await Task.WhenAll(Enumerable.Range(0, 32).Select(i => Resolve(i.ToString())));
        Assert.Equal(Enumerable.Range(0, 32).Select(i => i.ToString()), identities);
        await Assert.ThrowsAsync<McpAuthenticationException>(async () => await provider.ResolveAsync());
    }

    [Fact]
    public void OperatorAccessDoesNotPermitCounterfeitPipeInstances()
    {
        var config = new ManagedBridgeConfiguration(1, "SplatTest", "S-1-5-21-1-2-3-1002", "pipe", "distro", 55555,
            "C:\\private", "C:\\work", new[] { Caller.PrincipalId! });
        var rules = ManagedBridgeHost.Security(config).GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<PipeAccessRule>();
        var admitted = Assert.Single(rules, x => x.IdentityReference.Value == Caller.PrincipalId);
        Assert.Equal((PipeAccessRights)0, admitted.PipeAccessRights & PipeAccessRights.CreateNewInstance);
        Assert.Equal((PipeAccessRights)0, admitted.PipeAccessRights & PipeAccessRights.ChangePermissions);
    }

    [Fact]
    public async Task CounterfeitServerReceivesNoRequestOrHandshakeBytes()
    {
        string name = "splat-test-" + Guid.NewGuid().ToString("N");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var counterfeit = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        var accept = counterfeit.WaitForConnectionAsync(cancellation.Token);
        var connect = ManagedBridgeHost.ConnectAsync(name, "S-1-5-21-1-2-3-9999", cancellation.Token);
        await accept;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => connect);
        // The owner check occurs before even the one-byte identity bootstrap is transmitted.
        Assert.Equal(0, await counterfeit.ReadAsync(new byte[1], cancellation.Token));
    }

    private sealed class Ledger : IAuditLedger
    {
        internal bool Fail;
        internal List<AuditLogEntry> Entries { get; } = new();
        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            if (Fail) throw new IOException("private-path");
            Entries.Add(new AuditLogEntry(Entries.Count + 1, DateTime.UtcNow, missionId, templateId, action, details, operatorIdentity, "hash", "previous"));
            return Task.CompletedTask;
        }
        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Entries.Where(x => missionId is null || x.MissionId == missionId).Reverse().Take(limit).ToArray());
        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }
    private sealed class Executor(Ledger ledger) : ILeasedExecutor
    {
        internal int Calls;
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null, IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
        {
            Assert.Contains(ledger.Entries, x => x.Action == "MANAGED_CALL_ADMITTED");
            Calls++;
            return Task.FromResult(new ProcessExecutionResult(0, "hi", "", false, JobResourceMetrics.Unavailable));
        }
    }
}
