using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Linux;

namespace MissionController.Tests;

public sealed class AgentManifestCompilerTests
{
    private static string Manifest(Action<JsonNode> change)
    {
        var node = JsonNode.Parse(AgentManifestCompiler.ExampleJson)!;
        change(node);
        return node.ToJsonString();
    }

    [Fact]
    public async Task ImportedAgentReloadsAndEachToolReachesTheExistingLeaseLauncher()
    {
        await WithDatabase(async context =>
        {
            var imported = await new AgentManifestImporter(context).ImportAsync(AgentManifestCompiler.ExampleJson);
            var registry = new SqliteTemplateRegistry(context);
            var project = await new SqliteProjectTemplateRegistry(context).GetProjectTemplateByIdAsync(imported.Project.ProjectId);
            Assert.NotNull(project);
            Assert.Equal(new[] { "inspect_disk", "inspect_memory" }, project.Stages.Select(s => s.StageId));

            var executor = new Capture();
            var resolver = new Resolver();
            var substrate = new LinuxLeaseSubstrate(executor, new TemplatePolicyCompiler(resolver));
            foreach (var stage in project.Stages)
            {
                var template = await registry.GetTemplateByIdAsync(stage.TemplateId);
                Assert.NotNull(template);
                var source = GovernedTemplateCatalog.All.Single(t => t.TemplateId == template.SourceTemplateId);
                Assert.Equal(JsonSerializer.Serialize(source.Tool), JsonSerializer.Serialize(template.Tool));
                Assert.Equal(source.EgressRule, template.EgressRule);
                Assert.Empty(template.Remediations);
                Assert.Contains("[AGENT INSTRUCTIONS]", template.SystemPrompt);

                var mission = Guid.NewGuid();
                var selected = Assert.IsType<MissionSubstrate>(substrate.For(template, mission));
                var directory = await selected.Jails.ProvisionJailAsync(mission);
                using var job = selected.Jobs("manifest-test");
                await selected.Launcher.LaunchSuspendedInJobAsync(template.Tool.ExecutablePath,
                    GovernedArgumentBinder.Bind(template, new Dictionary<string, string>()), directory,
                    job, true, template.Tool.TimeoutSeconds);

                var lease = executor.Leases[^1];
                Assert.False(lease.AllowNetwork);
                Assert.Empty(lease.AllowedEgressIps);
                Assert.Empty(lease.AllowedEgressPorts);
                Assert.Equal(source.Tool.ExecutablePath, Assert.Single(lease.AllowedExecInodes).SourcePath);
                Assert.Equal((ulong)source.Tool.MaxMemoryBytes, lease.Limits.MaxMemoryBytes);
                Assert.Equal((uint)source.Tool.TimeoutSeconds, lease.LeaseDurationSeconds);
            }

            Assert.Empty(resolver.Hosts);
            Assert.Equal(2, executor.Leases.Select(l => l.MissionId).Distinct().Count());
            Assert.Equal(2, executor.Leases.Select(l => l.WorkingDirectory).Distinct().Count());
        });
    }

    [Fact]
    public void NetworkCapabilityRequiresExplicitAcceptanceAndIsNeverLentToAnotherTool()
    {
        var json = Manifest(n => n["tools"]![0]!["templateId"] = "source-dataset-catalog-search");
        Assert.Contains("allowNetwork", Assert.Throws<InvalidOperationException>(() => AgentManifestCompiler.Compile(json)).Message);

        var node = JsonNode.Parse(json)!;
        node["tools"]![0]!["allowNetwork"] = true;
        var compiled = AgentManifestCompiler.Compile(node.ToJsonString());
        var resolver = new Resolver();
        var compiler = new TemplatePolicyCompiler(resolver);
        var network = compiler.CompileTemplatePolicy(compiled.Templates[0], Guid.NewGuid(), "/tmp/network");
        var local = compiler.CompileTemplatePolicy(compiled.Templates[1], Guid.NewGuid(), "/tmp/local");

        Assert.True(network.AllowNetwork);
        Assert.Equal(new[] { "192.0.2.7" }, network.AllowedEgressIps);
        Assert.Equal(new uint[] { 443 }, network.AllowedEgressPorts);
        Assert.False(local.AllowNetwork);
        Assert.Empty(local.AllowedEgressIps);
        Assert.Equal(compiled.Templates[0].EgressRule.AllowedFqdn, Assert.Single(resolver.Hosts));
    }

    [Fact]
    public async Task ExplicitFileAndSyscallContractSurvivesImportReloadAndLeaseCompilation()
    {
        var policy = new ExecutionPolicy(1, "x86_64", new[] { "read", "write", "close", "execve", "exit_group" },
            new[] { new FileAccessGrant("/usr/bin/df", new[] { "read", "execute" }) });
        var json = Manifest(n => n["tools"]![0]!["executionPolicy"] = JsonSerializer.SerializeToNode(policy));
        await WithDatabase(async context =>
        {
            var imported = await new AgentManifestImporter(context).ImportAsync(json);
            var template = await new SqliteTemplateRegistry(context).GetTemplateByIdAsync(imported.Templates[0].TemplateId);
            Assert.NotNull(template);
            DerivedTemplateGuard.Validate(template);
            var lease = new TemplatePolicyCompiler(new Resolver()).CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/policy");
            Assert.Equal(JsonSerializer.Serialize(policy), JsonSerializer.Serialize(lease.ExecutionPolicy));
            Assert.False(lease.AllowNetwork);
            Assert.Null(imported.Templates[1].Tool.ExecutionPolicy);
        });
    }

    [Theory]
    [InlineData("{\"schemaVersion\":2,\"architecture\":\"x86_64\",\"syscalls\":[\"read\"],\"fileGrants\":[]}")]
    [InlineData("{\"schemaVersion\":1,\"architecture\":\"x86_64\",\"syscalls\":[],\"fileGrants\":[]}")]
    [InlineData("{\"schemaVersion\":1,\"architecture\":\"x86_64\",\"syscalls\":[\"read\"],\"fileGrants\":[{\"path\":\"/tmp/../etc\",\"access\":[\"read\"]}]}")]
    [InlineData("{\"schemaVersion\":1,\"architecture\":\"x86_64\",\"syscalls\":[\"read\"],\"fileGrants\":[{\"path\":\"/tmp\",\"access\":[\"write\"],\"scope\":\"tree\"}]}")]
    [InlineData("{\"schemaVersion\":1,\"architecture\":\"x86_64\",\"syscalls\":[\"read\"],\"fileGrants\":[],\"inferArbitrarySyscalls\":true}")]
    public void UnsupportedExecutionContractsCannotBeSavedAsEnforced(string policy)
    {
        Assert.Throws<InvalidOperationException>(() => AgentManifestCompiler.Compile(
            Manifest(n => n["tools"]![0]!["executionPolicy"] = JsonNode.Parse(policy))));
    }

    [Fact]
    public void AcceptingNetworkCannotGrantItToAnOfflineCatalogTool()
    {
        var compiled = AgentManifestCompiler.Compile(Manifest(n => n["tools"]![0]!["allowNetwork"] = true));
        var resolver = new Resolver();
        var lease = new TemplatePolicyCompiler(resolver).CompileTemplatePolicy(compiled.Templates[0], Guid.NewGuid(), "/tmp/offline");
        Assert.False(lease.AllowNetwork);
        Assert.Empty(resolver.Hosts);
    }

    [Theory]
    [InlineData("read_customer_db")]
    [InlineData("custom-untrusted-template")]
    [InlineData("endpoint-persistence-audit")]
    public void ToolNamesOrWindowsTemplatesCannotInventALinuxCapability(string templateId)
    {
        var json = Manifest(n => n["tools"]![0]!["templateId"] = templateId);
        Assert.Throws<InvalidOperationException>(() => AgentManifestCompiler.Compile(json));
    }

    [Theory]
    [InlineData("executablePath", "\"/bin/sh\"")]
    [InlineData("allowedReadPaths", "[\"/data/customer.db\"]")]
    [InlineData("inputSchema", "{\"type\":\"object\"}")]
    [InlineData("annotations", "{\"readOnlyHint\":true}")]
    public void UnsupportedToolClaimsAreRefusedInsteadOfSilentlyIgnored(string property, string value)
    {
        var json = Manifest(n => n["tools"]![0]![property] = JsonNode.Parse(value));
        Assert.Contains(property, Assert.Throws<InvalidOperationException>(() => AgentManifestCompiler.Compile(json)).Message);
    }

    [Fact]
    public void MalformedAmbiguousOrUnboundedManifestsAreRefused()
    {
        string[] invalid =
        {
            "null", "[]", "{", "{}",
            Manifest(n => n["schemaVersion"] = 2),
            Manifest(n => n["instructions"] = null),
            Manifest(n => n["agentId"] = "../escape"),
            Manifest(n => n["tools"] = new JsonArray()),
            Manifest(n => n["tools"] = null),
            Manifest(n => n["tools"]![0] = null),
            Manifest(n => n["tools"]![1]!["name"] = "INSPECT_DISK"),
            Manifest(n => n["tools"] = new JsonArray(Enumerable.Range(0, 7)
                .Select(i => (JsonNode)new JsonObject { ["name"] = $"tool_{i}", ["templateId"] = "linux-disk-usage" }).ToArray())),
            Manifest(n => n["permissions"] = new JsonObject { ["network"] = false }),
            AgentManifestCompiler.ExampleJson.Replace("\"schemaVersion\": 1", "\"schemaVersion\": 1, \"schemaVersion\": 1"),
            AgentManifestCompiler.ExampleJson.Replace("\"name\": \"inspect_disk\"", "\"name\": \"inspect_disk\", \"name\": \"hidden\""),
            new string(' ', 131073)
        };
        foreach (var json in invalid)
            Assert.Throws<InvalidOperationException>(() => AgentManifestCompiler.Compile(json));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConflictingTemplateOrProjectRollsBackTheWholeImport(bool conflictOnProject)
    {
        await WithDatabase(async context =>
        {
            var compiled = AgentManifestCompiler.Compile(AgentManifestCompiler.ExampleJson);
            var templates = new SqliteTemplateRegistry(context);
            var projects = new SqliteProjectTemplateRegistry(context);
            if (conflictOnProject)
                await projects.RegisterProjectTemplateAsync(compiled.Project with { Name = "Existing project" });
            else
                await templates.RegisterTemplateAsync(compiled.Templates[1] with { Name = "Existing tool" });

            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new AgentManifestImporter(context).ImportAsync(AgentManifestCompiler.ExampleJson));
            Assert.Contains("nothing was imported", exception.Message);
            Assert.Null(await templates.GetTemplateByIdAsync(compiled.Templates[0].TemplateId));
            if (conflictOnProject)
            {
                Assert.Null(await templates.GetTemplateByIdAsync(compiled.Templates[1].TemplateId));
                Assert.Equal("Existing project", (await projects.GetProjectTemplateByIdAsync(compiled.Project.ProjectId))!.Name);
            }
            else
            {
                Assert.Null(await projects.GetProjectTemplateByIdAsync(compiled.Project.ProjectId));
                Assert.Equal("Existing tool", (await templates.GetTemplateByIdAsync(compiled.Templates[1].TemplateId))!.Name);
            }
        });
    }

    [Fact]
    public async Task ReloadRefusesAnImportedTemplateWhoseExecutionSubstrateWasChanged()
    {
        await WithDatabase(async context =>
        {
            var imported = await new AgentManifestImporter(context).ImportAsync(AgentManifestCompiler.ExampleJson);
            var original = imported.Templates[0];
            var altered = original with { Tool = original.Tool with { Substrate = ToolSubstrate.Windows } };
            using (var connection = context.CreateConnection())
            {
                using var command = connection.CreateCommand();
                command.CommandText = "UPDATE Templates SET TemplateJson = @json WHERE TemplateId = @id";
                command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(altered));
                command.Parameters.AddWithValue("@id", original.TemplateId);
                await command.ExecuteNonQueryAsync();
            }
            await Assert.ThrowsAsync<InvalidOperationException>(() => new SqliteTemplateRegistry(context).GetTemplateByIdAsync(original.TemplateId));
        });
    }

    private static async Task WithDatabase(Func<SqliteStorageContext, Task> action)
    {
        var directory = Directory.CreateTempSubdirectory("splat-agent-manifest-");
        var context = new SqliteStorageContext(Path.Combine(directory.FullName, "test.db"));
        try { await action(context); }
        finally
        {
            using (var connection = context.CreateConnection())
                SqliteConnection.ClearPool(connection);
            directory.Delete(recursive: true);
        }
    }

    private sealed class Resolver : IHostAddressResolver
    {
        public List<string> Hosts { get; } = new();
        public IPAddress[] GetHostAddresses(string hostNameOrAddress)
        {
            Hosts.Add(hostNameOrAddress);
            return new[] { IPAddress.Parse("192.0.2.7") };
        }
    }

    private sealed class Capture : ILeasedExecutor
    {
        public List<LeaseSpec> Leases { get; } = new();
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
        {
            Leases.Add(lease);
            return Task.FromResult(new ProcessExecutionResult(0, "fixture", "", false, JobResourceMetrics.Unavailable));
        }
    }
}
