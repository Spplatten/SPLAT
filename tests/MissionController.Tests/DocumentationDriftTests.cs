using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The README is the document a reader trusts before they trust the code, and it had drifted far
/// enough to be actively misleading: six of its twenty-four source links resolved to nothing -
/// including every link in the "Windows containment substrate (shipped)" table, the section a
/// reader is most likely to click through - and it advertised a tool count and a test count that
/// had both moved on.
///
/// Prose cannot be asserted, but the claims that are mechanically checkable should be, because
/// those are exactly the ones that rot silently. Nobody notices a dead link in a document they
/// wrote.
/// </summary>
public class DocumentationDriftTests
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

    private static string ReadmeText() => File.ReadAllText(Path.Combine(RepositoryRoot(), "README.md"));

    /// <summary>
    /// Every relative link in the README must resolve to something on disk. This is the check that
    /// would have caught the namespace/folder drift from the documentation side long before an
    /// audit did: the paths were written from the C# namespaces (<c>.Jails</c>, <c>.Process</c>,
    /// <c>.Vault</c>) while the files sat flat at the project root.
    /// </summary>
    [Fact]
    public void EveryRelativeLinkInTheReadme_ResolvesOnDisk()
    {
        string root = RepositoryRoot();
        var broken = new List<string>();

        foreach (Match match in Regex.Matches(ReadmeText(), @"\]\((?<path>(?:src|native|tests|packaging|docs)[^)]*)\)"))
        {
            string relative = match.Groups["path"].Value.Split('#')[0].TrimEnd('/');
            if (relative.Length == 0)
            {
                continue;
            }

            string full = Path.Combine(root, relative.Replace('/', Path.DirectorySeparatorChar));
            if (!File.Exists(full) && !Directory.Exists(full))
            {
                broken.Add(relative);
            }
        }

        Assert.Empty(broken);
    }

    /// <summary>
    /// Asserting on the tool COUNT would break every time the prose was reworded, so this asserts
    /// the property that actually matters: a tool the server exposes must be described somewhere in
    /// the README. <c>search_incident_memory</c> shipped and was never mentioned, which is how the
    /// document came to advertise eight tools against a server that served nine.
    /// </summary>
    [Fact]
    public async Task EveryToolTheMcpServerExposes_IsDocumentedInTheReadme()
    {
        string readme = ReadmeText();
        var handler = new McpServerHandler(new StubExecutor(), new TemplatePolicyCompiler(), new NullLedger());

        var response = await handler.ProcessMessageAsync(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "tools/list"
        });

        var tools = JsonDocument.Parse(response.Result!.Value.GetRawText())
            .RootElement.GetProperty("tools")
            .EnumerateArray()
            .Select(t => t.GetProperty("name").GetString()!)
            .ToList();

        Assert.NotEmpty(tools);
        var undocumented = tools.Where(name => !readme.Contains(name, StringComparison.Ordinal)).ToList();
        Assert.Empty(undocumented);
    }

    /// <summary>
    /// A guard against the specific overclaims this audit removed creeping back in a later edit.
    /// Each phrase below was in the README while the code said otherwise.
    /// </summary>
    [Theory]
    // The BPF key holds the inode number alone; there is no device field in struct inode_key.
    [InlineData("`(dev, ino)` inode identity")]
    // True only on an incremental build; a cold build emits 186 MVVMTK0045 warnings.
    [InlineData("zero compiler warnings across the solution")]
    // fs_read/fs_write run on the Windows control plane, and run_command depends on a substrate
    // whose enforcement proof is still pending.
    [InlineData("every tool call resolves to a lease")]
    public void RetiredOverclaims_DoNotReappear(string phrase)
    {
        Assert.DoesNotContain(phrase, ReadmeText(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The README states the Linux substrate is unproven in several places. If the canary run ever
    /// lands, these qualifications should be removed deliberately - and this test is where someone
    /// will be reminded to do it, rather than leaving a shipped capability described as pending.
    /// </summary>
    [Fact]
    public void TheLinuxSubstrateIsStillDescribedAsUnproven_UntilTheCanaryRunIsRecorded()
    {
        string readme = ReadmeText();

        Assert.Contains("In bring-up", readme, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("canary", readme, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------- minimal stubs

    private sealed class StubExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease, string command, string arguments,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default) =>
            Task.FromResult(new ProcessExecutionResult(0, "", "", false, JobResourceMetrics.Unavailable));
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
}
