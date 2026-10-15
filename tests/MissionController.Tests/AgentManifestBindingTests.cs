using System.Text.Json;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using MissionController.Host;
using SplatMcp;

namespace MissionController.Tests;

public sealed class AgentManifestBindingTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("splat-bound-agent-").FullName;
    private readonly SqliteStorageContext _context;
    private readonly Capture _executor = new();

    public AgentManifestBindingTests() => _context = new(Path.Combine(_root, "test.db"));

    private async Task<(McpServerHandler Handler, AgentManifestApproval Approval)> Host(IOperatorIdentityProvider? identity = null)
    {
        var importer = new AgentManifestImporter(_context);
        var compiled = await importer.ImportAsync(AgentManifestCompiler.ExampleJson);
        var approval = await importer.LoadApprovedAsync(AgentManifestApproval.AgentIdOf(compiled), AgentManifestApproval.Hash(compiled));
        return (new McpServerHandler(_executor, new TemplatePolicyCompiler(), new SqliteChainedAuditLedger(_context),
            workspaceRoot: _root, agent: approval, identityProvider: identity), approval);
    }

    private static McpJsonRpcMessage Call(string tool, object arguments) => new()
    {
        Id = JsonSerializer.SerializeToElement(1), Method = "tools/call",
        Params = JsonSerializer.SerializeToElement(new { name = tool, arguments })
    };

    [Fact]
    public async Task SavedVersionAdvertisesOnlyItsToolsAndCompilesEachCallIntoItsOwnLease()
    {
        var (handler, approval) = await Host();
        var list = await handler.ProcessMessageAsync(new() { Method = "tools/list" });
        Assert.Equal(new[] { "inspect_disk", "inspect_memory" }, list.Result!.Value.GetProperty("tools")
            .EnumerateArray().Select(t => t.GetProperty("name").GetString()));
        Assert.Equal(approval.Sha256, list.Result.Value.GetProperty("agent").GetProperty("version").GetString());
        foreach (var stage in approval.Manifest.Project.Stages)
        {
            var result = await handler.ProcessMessageAsync(Call(stage.StageId, new { }));
            Assert.Null(result.Error);
            Assert.False(result.Result!.Value.GetProperty("isError").GetBoolean());
            Assert.Contains(approval.Sha256, result.Result.Value.GetRawText());
        }
        Assert.Equal(2, _executor.Leases.Select(l => l.MissionId).Distinct().Count());
        Assert.Equal(new[] { "/bin/df", "/bin/cat" }, _executor.Commands);
        Assert.All(_executor.Leases, lease =>
        {
            Assert.True(lease.RequireEnforcing);
            Assert.True(lease.EphemeralWorkspace);
            Assert.False(lease.AllowNetwork);
            Assert.Empty(lease.AllowedEgressIps);
            Assert.StartsWith(LinuxLeaseSubstrate.DefaultMissionsRoot, lease.WorkingDirectory);
        });
    }

    [Theory]
    [InlineData("run_command")]
    [InlineData("run_code")]
    [InlineData("fs_read")]
    [InlineData("fs_write")]
    [InlineData("diagnose_system")]
    [InlineData("investigate_system")]
    [InlineData("run_agent_brain")]
    [InlineData("run_governed_crew")]
    [InlineData("inspect_unapproved")]
    public async Task GenericAndNestedRoutesCannotBypassTheSameBoundEndpoint(string tool)
    {
        var (handler, _) = await Host();
        var result = await handler.ProcessMessageAsync(Call(tool, new { command = "/bin/sh", code = "print(1)" }));
        Assert.True(result.Result!.Value.GetProperty("isError").GetBoolean());
        Assert.Empty(_executor.Leases);
        var direct = await handler.ExecuteManagedLeaseAsync(new() { Method = "splat/execute_lease" }, "same-actor", default);
        Assert.NotNull(direct.Error);
        Assert.Empty(_executor.Leases);
    }

    [Theory]
    [InlineData("{\"command\":\"/bin/sh\"}")]
    [InlineData("{\"executionPolicy\":null}")]
    [InlineData("{\"agentId\":\"different\"}")]
    [InlineData("{\"parameters\":{\"command\":\"/bin/sh\"}}")]
    [InlineData("{\"parameters\":{},\"parameters\":{}}")]
    [InlineData("{\"parameters\":null}")]
    [InlineData("{\"allowNetwork\":true}")]
    public async Task CallersCannotRewriteAuthorityOrSupplyUndeclaredInputs(string arguments)
    {
        var (handler, _) = await Host();
        var result = await handler.ProcessMessageAsync(Call("inspect_disk", JsonSerializer.Deserialize<JsonElement>(arguments)));
        Assert.True(result.Result!.Value.GetProperty("isError").GetBoolean());
        Assert.Empty(_executor.Leases);
    }

    [Fact]
    public async Task ManagedServicePreservesBoundToolsAndRefusesRawLeaseBypassForTheSameCaller()
    {
        var identity = new ManagedPipeIdentity();
        identity.Set(new OperatorIdentity("test-caller", "S-1-5-21-1-2-3-1001",
            OperatorAuthenticationMethod.WindowsAuthenticated, "mcp-managed-pipe"));
        var (handler, approval) = await Host(identity);
        var ledger = new SqliteChainedAuditLedger(_context);
        var list = await ManagedBridgeHost.DispatchAsync(new() { Method = "tools/list" }, handler, ledger, identity, default);
        Assert.Equal(2, list.Result!.Value.GetProperty("tools").GetArrayLength());
        Assert.Equal(approval.Sha256, list.Result.Value.GetProperty("agent").GetProperty("version").GetString());
        var allowed = await ManagedBridgeHost.DispatchAsync(Call("inspect_disk", new { }), handler, ledger, identity, default);
        Assert.False(allowed.Result!.Value.GetProperty("isError").GetBoolean());
        var bypass = await ManagedBridgeHost.DispatchAsync(new() { Method = ManagedLeaseRequest.ExecuteMethod }, handler, ledger, identity, default);
        Assert.Equal(-32003, bypass.Error?.Code);
        Assert.Single(_executor.Leases);
    }

    [Fact]
    public async Task RegistryTamperingAndWrongVersionsRefuseButCannotMutateAnAlreadyPinnedSession()
    {
        var (handler, approval) = await Host();
        var importer = new AgentManifestImporter(_context);
        await Assert.ThrowsAsync<InvalidOperationException>(() => importer.LoadApprovedAsync(approval.AgentId, new string('0', 64)));
        using (var connection = _context.CreateConnection())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "UPDATE Templates SET TemplateJson = '{}' WHERE TemplateId = @id";
            command.Parameters.AddWithValue("@id", approval.Manifest.Templates[0].TemplateId);
            command.ExecuteNonQuery();
        }
        await Assert.ThrowsAsync<InvalidOperationException>(() => importer.LoadApprovedAsync(approval.AgentId, approval.Sha256));
        await handler.ProcessMessageAsync(Call("inspect_disk", new { }));
        Assert.Equal("/bin/df", Assert.Single(_executor.Commands));
    }

    [Fact]
    public void StartupBindingMustIncludeAnImmutableVersionAndCannotApplyToAdministrativeCommands()
    {
        var hash = new string('a', 64);
        var parsed = Assert.IsType<McpServerCommand.Serve>(McpServerCommand.Parse(new[] { "--agent", "reader", "--agent-version", hash }));
        Assert.Equal("reader", parsed.AgentId);
        Assert.Equal(hash, parsed.AgentVersion);
        foreach (var args in new[]
        {
            new[] { "--agent", "reader" }, new[] { "--agent-version", hash },
            new[] { "--agent", "reader", "--agent-version", "latest" },
            new[] { "doctor", "--agent", "reader", "--agent-version", hash },
            new[] { "provision", "--agent", "reader", "--agent-version", hash }
        }) Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(args));
    }

    public void Dispose()
    {
        using (var connection = _context.CreateConnection()) SqliteConnection.ClearPool(connection);
        Directory.Delete(_root, recursive: true);
    }

    private sealed class Capture : ILeasedExecutor
    {
        public List<LeaseSpec> Leases { get; } = new();
        public List<string> Commands { get; } = new();
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
        {
            Leases.Add(lease); Commands.Add(command);
            return Task.FromResult(new ProcessExecutionResult(0, "test reading", "", false, JobResourceMetrics.Unavailable));
        }
    }
}
