using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
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

    /// <summary>
    /// The advertised test count is the claim in these documents that goes stale fastest - it moves
    /// on almost every commit - and nothing was checking it. This class's own summary cited a drifted
    /// test count as a reason it exists, while the README sat at 297/297 against a suite that had
    /// grown past 340 and the tutorial had been updated separately to a third number.
    ///
    /// Reflection reproduces exactly what the runner reports: one case per <c>[Fact]</c>, one per
    /// <c>[InlineData]</c> row on a <c>[Theory]</c>. That equivalence holds only while the suite uses
    /// no data source the runner expands but reflection cannot enumerate, so
    /// <see cref="NoDataSourceEscapesTheTestCounter"/> fails the moment one is introduced.
    /// </summary>
    [Fact]
    public void TheAdvertisedTestCount_MatchesTheSuite()
    {
        int actual = CountTestCases();
        var claims = FindTestCountClaims();

        // A claim that has simply been deleted must not read as agreement.
        Assert.NotEmpty(claims);

        var wrong = claims
            .Where(claim => claim.Claimed != actual)
            .Select(claim => $"{claim.File} claims {claim.Claimed}")
            .ToList();

        Assert.True(
            wrong.Count == 0,
            $"The suite contains {actual} test cases, but {string.Join("; ", wrong)}. " +
            "Update the documented count in those files to match.");
    }

    /// <summary>
    /// Guards the assumption <see cref="CountTestCases"/> rests on. xUnit expands
    /// <c>[MemberData]</c> and <c>[ClassData]</c> at run time from sources reflection here does not
    /// evaluate, so a test using one would be counted as zero cases and would silently deflate the
    /// number the documents are held to - turning the count check into a rubber stamp.
    /// </summary>
    [Fact]
    public void NoDataSourceEscapesTheTestCounter()
    {
        var unsupported = TestMethods()
            .Where(method => method.GetCustomAttributes()
                .Any(attribute => attribute is MemberDataAttribute or ClassDataAttribute))
            .Select(method => $"{method.DeclaringType?.Name}.{method.Name}")
            .ToList();

        Assert.True(
            unsupported.Count == 0,
            "These tests use a data source the documentation test counter cannot enumerate, so the " +
            $"advertised test count would silently under-report: {string.Join(", ", unsupported)}. " +
            "Teach CountTestCases to expand it, or use [InlineData].");
    }

    private static readonly Regex TestCountClaimRegex = new(
        @"(?<first>\d+)(?:/(?<second>\d+))?\s+automated tests",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Every documented test count, from both spellings in use: "297/297 automated tests" in the
    /// README's status table and "340 automated tests" in the tutorial's prose. In the paired form
    /// both halves are held to the real number, since a passing suite means run and passed are equal.
    /// </summary>
    private static List<(string File, int Claimed)> FindTestCountClaims()
    {
        string root = RepositoryRoot();
        var claims = new List<(string, int)>();

        foreach (string relative in new[] { "README.md", Path.Combine("docs", "TUTORIAL.md") })
        {
            string full = Path.Combine(root, relative);
            if (!File.Exists(full))
            {
                continue;
            }

            foreach (Match match in TestCountClaimRegex.Matches(File.ReadAllText(full)))
            {
                claims.Add((relative, int.Parse(match.Groups["first"].Value)));
                if (match.Groups["second"].Success)
                {
                    claims.Add((relative, int.Parse(match.Groups["second"].Value)));
                }
            }
        }

        return claims;
    }

    private static int CountTestCases() => TestMethods().Sum(method =>
        // TheoryAttribute derives from FactAttribute, so theories are matched first - checking Fact
        // first would count a theory once instead of once per data row.
        method.GetCustomAttribute<TheoryAttribute>() is not null
            ? method.GetCustomAttributes<InlineDataAttribute>().Count()
            : 1);

    private static IEnumerable<MethodInfo> TestMethods() =>
        typeof(DocumentationDriftTests).Assembly
            .GetTypes()
            .SelectMany(type => type.GetMethods(
                BindingFlags.Public | BindingFlags.NonPublic |
                BindingFlags.Instance | BindingFlags.Static |
                // Inherited methods would otherwise be counted once per derived class.
                BindingFlags.DeclaredOnly))
            .Where(method => method.GetCustomAttribute<FactAttribute>() is not null);

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
