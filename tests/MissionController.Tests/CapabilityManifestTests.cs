using System.Text.Json;
using System.Text.RegularExpressions;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// F24: the CLI, the MCP tool descriptions and the substrate's own policy document each used to
/// state what SPLAT enforces, separately, so a boundary could move and leave two of them behind.
/// These tests are what makes <see cref="CapabilityManifest"/> the one contract rather than a fourth
/// copy - they bind it to the document, to the server's own tool list, and to the shipped catalog.
/// </summary>
public sealed class CapabilityManifestTests
{
    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static async Task<List<(string Name, string Description)>> ServedToolsAsync()
    {
        var handler = new McpServerHandler(new NeverCalledExecutor(), new TemplatePolicyCompiler(), new SilentLedger());

        var response = await handler.ProcessMessageAsync(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "tools/list",
        });

        return JsonDocument.Parse(response.Result!.Value.GetRawText())
            .RootElement.GetProperty("tools")
            .EnumerateArray()
            .Select(t => (t.GetProperty("name").GetString()!, t.GetProperty("description").GetString()!))
            .ToList();
    }

    [Fact]
    public void EveryLeaseRow_IsStillInTheSubstratesOwnPolicy()
    {
        string policy = File.ReadAllText(
            Path.Combine(RepositoryRoot(), "native", "splat-agent", "SUPPORTED_POLICY.md"));

        var missing = CapabilityManifest.Lease
            .Where(row => !policy.Contains(row.What, StringComparison.OrdinalIgnoreCase))
            .Select(row => row.What)
            .ToList();

        Assert.Empty(missing);
    }

    [Fact]
    public async Task TheManifestAndTheServer_NameTheSameTools()
    {
        var served = (await ServedToolsAsync()).Select(t => t.Name).ToHashSet(StringComparer.Ordinal);
        var manifest = CapabilityManifest.Tools.Select(t => t.Tool).ToHashSet(StringComparer.Ordinal);

        // Both directions: a tool that ships without a stated enforcement, and an entry for a tool
        // that no longer exists, are each a claim nobody is checking.
        Assert.Empty(served.Except(manifest));
        Assert.Empty(manifest.Except(served));
    }

    [Fact]
    public async Task EveryToolDescription_SaysWhatHoldsIt()
    {
        var undeclared = (await ServedToolsAsync())
            .Where(t => !t.Description.Contains("Enforced by", StringComparison.Ordinal))
            .Select(t => t.Name)
            .ToList();

        Assert.Empty(undeclared);
    }

    [Fact]
    public async Task AFileToolIsNotDescribedAsAKernelBoundary()
    {
        var served = await ServedToolsAsync();

        // The distinction F14 and the audits kept returning to: fs_read and fs_write are a check in
        // this process, and the description a client reads must not borrow the kernel's authority.
        string fsRead = served.Single(t => t.Name == "fs_read").Description;
        Assert.Contains("user-space boundary, not a kernel one", fsRead);

        string runCommand = served.Single(t => t.Name == "run_command").Description;
        Assert.Contains("BPF-LSM", runCommand);
    }

    [Fact]
    public void TheWindowsCensus_IsCountedFromTheCatalogTheServerShips()
    {
        var census = CapabilityManifest.CensusOf(GovernedTemplateCatalog.All);

        Assert.Equal(census.Templates, census.NetworkDenied + census.NeedsNetwork + census.LocalSubsystems);
        Assert.True(census.Templates > 0, "the catalog is empty, so the census is meaningless");

        // The roadmap states these numbers to a reader; counting them here is what stops that
        // sentence from rotting the next time a template is added.
        string roadmap = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "ROADMAP.md"));
        var stated = Regex.Match(roadmap, @"Of (?<total>\d+) catalog templates, (?<denied>\d+) launch");
        Assert.True(stated.Success, "the roadmap no longer states the census in the form this test reads");
        Assert.Equal(census.Templates, int.Parse(stated.Groups["total"].Value));
        Assert.Equal(census.NetworkDenied, int.Parse(stated.Groups["denied"].Value));

        // The Field Guide states the same census in prose, in both synced copies. That document is
        // what a non-engineer reads to decide whether to trust this, and it spent weeks telling them
        // Windows did not filter network sockets at all - which the census above disproves for 33 of
        // the 49. Bound here so the correction cannot quietly rot back into the comfortable version.
        foreach (string doc in new[] { "TUTORIAL.md", "SPLAT-Field-Guide.html" })
        {
            string text = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", doc));
            var prose = Regex.Match(text, @"of the (?<total>\d+) agents in the catalog, (?<denied>\d+) launch");
            Assert.True(prose.Success, $"{doc} no longer states the census in the form this test reads");
            Assert.Equal(census.Templates, int.Parse(prose.Groups["total"].Value));
            Assert.Equal(census.NetworkDenied, int.Parse(prose.Groups["denied"].Value));
        }
    }

    private sealed class NeverCalledExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default) =>
            throw new InvalidOperationException("tools/list must never reach the executor");
    }

    private sealed class SilentLedger : IAuditLedger
    {
        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(
            Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }
}
