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
    ///
    /// Widened on 2026-09-10 from the README to every document <see cref="DocumentationFiles"/>
    /// returns, when the architecture, context and module maps landed in docs/: those documents are
    /// mostly paths into this tree, and a path is the claim that breaks on the first rename. Each
    /// link resolves against its own document's directory, the way a reader's browser follows it.
    /// </summary>
    [Fact]
    public void EveryRelativeLinkInTheDocs_ResolvesOnDisk()
    {
        var broken = new List<string>();

        foreach (string document in DocumentationFiles())
        {
            string directory = Path.GetDirectoryName(document)!;

            foreach (Match match in Regex.Matches(File.ReadAllText(document), @"\]\((?<path>[^)\s]+)\)"))
            {
                string target = match.Groups["path"].Value;

                // A scheme (https:, mailto:, file:) or an in-page anchor is not a path into this tree.
                if (target.StartsWith('#') || Regex.IsMatch(target, @"^[A-Za-z][A-Za-z0-9+.-]*:"))
                {
                    continue;
                }

                string relative = target.Split('#')[0].TrimEnd('/');
                if (relative.Length == 0)
                {
                    continue;
                }

                string full = Path.Combine(directory, relative.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(full) && !Directory.Exists(full))
                {
                    broken.Add($"{Path.GetFileName(document)} -> {relative}");
                }
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
    // NOTE: "`(dev, ino)` inode identity" was guarded here while struct inode_key was believed to
    // hold the inode alone. It always had a dev field - the defect was that userspace seeded it
    // with glibc's st_dev while the kernel keys on (major << 20) | minor, so every lookup missed.
    // Fixed and proven by the canary on 2026-09-03, so the phrase is now accurate and no longer
    // guarded. Retiring a guard needs the same evidence as making the claim.
    //
    // True only on an incremental build; a cold build emits 186 MVVMTK0045 warnings.
    [InlineData("zero compiler warnings across the solution")]
    // fs_read/fs_write run on the Windows control plane, and run_command depends on a substrate
    // whose enforcement proof is still pending.
    [InlineData("every tool call resolves to a lease")]
    // An underclaim, which rots exactly the same way and is just as wrong to print. The Field Guide
    // told a non-engineer this for weeks while 33 of the 49 catalog templates launched in an
    // AppContainer with no network capability at all. Windows constrains whether, not where - the
    // honest sentence is longer than both the boast and the disclaimer.
    [InlineData("do not filter network sockets")]
    [InlineData("do <strong>not</strong> filter network sockets")]
    public void RetiredOverclaims_DoNotReappear(string phrase)
    {
        // Widened past the README deliberately. Every phrase above was retired from the README, and
        // the guard was written there - but the claim a reader actually acts on lives in the Field
        // Guide, which nothing was watching. A retired claim is retired everywhere or nowhere.
        foreach (string doc in new[] { "README.md", Path.Combine("docs", "TUTORIAL.md"), Path.Combine("docs", "SPLAT-Field-Guide.html") })
        {
            string text = File.ReadAllText(Path.Combine(RepositoryRoot(), doc));
            Assert.DoesNotContain(phrase, text, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Binds the substrate's documented status to the recorded canary evidence, in both directions:
    /// describing it as pending while valid proof exists understates the product, and describing it
    /// as proven without evidence is the overclaim this repository exists to avoid.
    ///
    /// This replaced a test that only asserted the README still said "In bring-up" - which locked in
    /// the pending wording and would have kept it there after the proof landed.
    /// </summary>
    [Fact]
    public void TheSubstrateProofState_MatchesWhatTheDocumentsClaim()
    {
        string readme = ReadmeText();
        var proof = CurrentKernelProof();

        // Phrases that assert the -EPERM run has NOT happened yet. Kept literal so a rewording is a
        // deliberate act rather than something this test silently stops noticing.
        string[] pendingClaims =
        {
            "canary `-EPERM` run is the next gate",
            "execution proof is pending",
            "not yet proven in operation",
        };

        var stale = pendingClaims.Where(p => readme.Contains(p, StringComparison.OrdinalIgnoreCase)).ToList();

        if (proof is not null)
        {
            Assert.True(
                stale.Count == 0,
                $"Evidence at {proof.File} records a {proof.Verdict} run on kernel {proof.KernelRelease}, " +
                $"but the README still says: {string.Join(" / ", stale)}. Update the documented status.");
        }
        else
        {
            Assert.True(
                stale.Count > 0,
                "No passing canary evidence matches the current BPF source, so the README must still " +
                "describe the Linux substrate as unproven. Record a run, or restore the qualification.");
        }
    }

    /// <summary>
    /// Evidence proves the program that produced it, not whatever the program later became. The
    /// canary records the SHA-256 of the BPF source it ran; if that source changes, the old evidence
    /// stops counting and <see cref="TheSubstrateProofState_MatchesWhatTheDocumentsClaim"/> reverts
    /// to demanding the pending wording until someone re-runs it.
    /// </summary>
    /// <summary>
    /// Binds every documented latency figure to the committed benchmark, because the enterprise
    /// brief carried an unmeasured "sub-millisecond" claim for months and the measurement, once
    /// taken, came back at roughly four times that. A number nobody ran is not a small error in a
    /// document a prospect can check.
    ///
    /// Guards the direction that actually bites: a doc may not promise sub-millisecond tool calls
    /// unless committed evidence records a p50 overhead under 1 ms. It does not force the docs to
    /// quote a figure at all - silence about performance is always honest.
    /// </summary>
    [Fact]
    public void NoDocumentPromisesSubMillisecondCalls_UnlessTheBenchmarkRecordsIt()
    {
        double? measuredP50 = null;
        string benchDir = Path.Combine(RepositoryRoot(), "src", "splat-bench", "evidence");

        if (Directory.Exists(benchDir))
        {
            foreach (string file in Directory.EnumerateFiles(benchDir, "bench-*.json"))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(file));
                var root = doc.RootElement;

                bool passed = string.Equals(
                    root.TryGetProperty("verdict", out var v) ? v.GetString() : null,
                    "PASS",
                    StringComparison.OrdinalIgnoreCase);

                if (passed
                    && root.TryGetProperty("overhead_ms", out var overhead)
                    && overhead.TryGetProperty("p50", out var p50))
                {
                    // Several machines may each commit a run; the slowest is the one a claim has to
                    // survive, so a fast outlier cannot license a promise the fleet cannot keep.
                    double value = p50.GetDouble();
                    measuredP50 = measuredP50 is null ? value : Math.Max(measuredP50.Value, value);
                }
            }
        }

        bool subMillisecondIsSupported = measuredP50 is > 0 and < 1.0;
        if (subMillisecondIsSupported)
        {
            return;
        }

        string[] phrases = { "sub-millisecond", "submillisecond", "<1ms", "< 1ms", "zero-latency" };
        var offenders = new List<string>();

        foreach (string path in DocumentationFiles())
        {
            string text = File.ReadAllText(path);
            foreach (string phrase in phrases)
            {
                foreach (int at in Occurrences(text, phrase))
                {
                    if (!IsDenial(text, at, phrase.Length))
                    {
                        offenders.Add($"{Path.GetFileName(path)}: \"{phrase}\"");
                    }
                }
            }
        }

        Assert.True(
            offenders.Count == 0,
            measuredP50 is null
                ? "A document promises sub-millisecond execution, but no passing benchmark evidence exists under "
                  + $"src/splat-bench/evidence. Run `dotnet run --project src/splat-bench -c Release` or drop the claim. Offenders: {string.Join("; ", offenders)}"
                : $"A document promises sub-millisecond execution, but the recorded benchmark measured a p50 overhead of "
                  + $"{measuredP50:F2} ms. Offenders: {string.Join("; ", offenders)}");
    }

    private static IEnumerable<int> Occurrences(string haystack, string needle)
    {
        for (int i = haystack.IndexOf(needle, StringComparison.OrdinalIgnoreCase);
             i >= 0;
             i = haystack.IndexOf(needle, i + 1, StringComparison.OrdinalIgnoreCase))
        {
            yield return i;
        }
    }

    /// <summary>
    /// True when the phrase is being denied rather than promised.
    ///
    /// The guard exists to stop the docs PROMISING sub-millisecond calls, and the most honest
    /// sentence available - "latency is measured, and it is not sub-millisecond" - contains the
    /// phrase verbatim. A test that forbids the words rather than the claim would push the docs
    /// into vaguer language, which is the opposite of what this suite is for.
    ///
    /// Deliberately a heuristic over a window of surrounding text, not a parser. It is a tripwire
    /// against drift, not a defence against someone determined to smuggle a claim past it.
    /// </summary>
    private static bool IsDenial(string text, int index, int length)
    {
        const int Window = 90;
        int start = Math.Max(0, index - Window);
        int end = Math.Min(text.Length, index + length + Window);
        string around = text[start..end];

        string[] cues = { "not ", "never", "no longer", "isn't", "is not", "wrong", "retired", "rather than", "instead of", "unmeasured", "estimate" };
        return cues.Any(cue => around.Contains(cue, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The prose a reader outside the project actually sees - README plus docs/, minus the internal
    /// planning notes.
    ///
    /// The exemption is not a loophole, it is the use/mention distinction. `PLAN-*` and the build
    /// brief quote "&lt;1ms" precisely in order to retire it - "the `&lt;1ms` class of claim stays dead
    /// until measured" is the sentence that got this benchmark written. Rewriting those would erase
    /// the project's own record of killing the claim. Everything else defaults to guarded, so a new
    /// prospect-facing document is covered the day it is added rather than the day someone
    /// remembers to list it.
    /// </summary>
    private static IEnumerable<string> DocumentationFiles()
    {
        yield return Path.Combine(RepositoryRoot(), "README.md");

        string docs = Path.Combine(RepositoryRoot(), "docs");
        if (!Directory.Exists(docs))
        {
            yield break;
        }

        foreach (string file in Directory.EnumerateFiles(docs, "*.*")
                     .Where(f => f.EndsWith(".md", StringComparison.OrdinalIgnoreCase)
                              || f.EndsWith(".html", StringComparison.OrdinalIgnoreCase)))
        {
            string name = Path.GetFileName(file);
            bool internalPlanning =
                name.StartsWith("PLAN-", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("AGENT-BUILD-BRIEF.md", StringComparison.OrdinalIgnoreCase);

            if (!internalPlanning)
            {
                yield return file;
            }
        }
    }

    [Fact]
    public void CommittedKernelEvidence_IsEitherAbsentOrMatchesItsBpfSource()
    {
        var files = EvidenceFiles();
        if (files.Count == 0)
        {
            return; // Nothing recorded yet is a valid state; the test above enforces the wording.
        }

        string currentSha = BpfSourceSha256();
        var matching = files.Where(f => ReadJsonString(f, "bpf_source_sha256") == currentSha).ToList();

        Assert.True(
            matching.Count > 0,
            $"{files.Count} evidence file(s) exist but none names the current BPF source " +
            $"({currentSha[..12]}…). The kernel program changed after the last recorded run — " +
            "re-run native/splat-canary/run-canary.sh so the proof describes the code that ships.");
    }

    /// <summary>
    /// The canary proves the BPF program under its own loader; this proves the daemon that carries
    /// it into the product. They are separate claims, so they get separate evidence and separate
    /// checks — the README may only describe the daemon as enforcing while a passing probe record
    /// says so, and must not while one does not.
    /// </summary>
    [Fact]
    public void TheDaemonEnforcementClaim_MatchesItsProbeEvidence()
    {
        string readme = ReadmeText();
        string file = Path.Combine(RepositoryRoot(), "native", "splat-agent", "evidence", "daemon-probe.json");

        bool claimsEnforcing = readme.Contains("Enforcing, proven under root", StringComparison.OrdinalIgnoreCase);
        bool proven = false;

        if (File.Exists(file))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(file));
            var root = doc.RootElement;
            proven = string.Equals(
                root.TryGetProperty("verdict", out var v) ? v.GetString() : null,
                "PASS",
                StringComparison.OrdinalIgnoreCase);

            // A probe is only proof of the program it ran against. The canary evidence has been
            // bound to its BPF source since the first recording; the daemon probe was not, so the
            // agent's kernel program could be rewritten - as it was, when the policy maps were
            // re-keyed per lease - while a months-old PASS kept the README's claim standing.
            if (proven && root.TryGetProperty("bpf_source_sha256", out var sha))
            {
                proven = string.Equals(sha.GetString(), AgentBpfSourceSha256(), StringComparison.OrdinalIgnoreCase);
            }
            else
            {
                proven = false;
            }

            if (proven && root.TryGetProperty("results", out var results))
            {
                // A PASS verdict is only as good as the properties behind it. Re-check the two that
                // matter most here, so a future loosening of the probe's own criteria cannot quietly
                // promote the README's claim.
                foreach (var required in new[] { "protected_inode_violation", "unleased_second_exec_blocked" })
                {
                    if (!results.TryGetProperty(required, out var r) || !r.GetBoolean())
                    {
                        proven = false;
                    }
                }
            }
        }

        Assert.True(
            claimsEnforcing == proven,
            proven
                ? $"{file} records a passing daemon probe, but the README does not describe the daemon as enforcing."
                : $"The README describes the daemon as enforcing, but {file} does not record a passing probe. "
                  + "Run native/splat-agent/probe-daemon.sh against a root daemon, or withdraw the claim.");
    }

    /// <summary>
    /// The daemon probe proves the daemon; this proves the road into it. They are separate claims —
    /// the daemon enforced under root for days while nothing had yet travelled from an MCP client
    /// through the C# bridge to reach it — so the README's wording is bound to its own evidence, in
    /// both directions, and to the kernel program that evidence ran against.
    /// </summary>
    [Fact]
    public void TheLastHopClaim_MatchesItsProbeEvidence()
    {
        string readme = ReadmeText();
        string file = Path.Combine(RepositoryRoot(), "native", "splat-agent", "evidence", "last-hop-probe.json");

        bool claimsDemonstrated = readme.Contains("Demonstrated end to end", StringComparison.OrdinalIgnoreCase);
        bool proven = false;

        if (File.Exists(file))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(file));
            var root = doc.RootElement;
            proven =
                string.Equals(root.TryGetProperty("verdict", out var v) ? v.GetString() : null, "PASS", StringComparison.OrdinalIgnoreCase)
                && root.TryGetProperty("bpf_source_sha256", out var sha)
                && string.Equals(sha.GetString(), AgentBpfSourceSha256(), StringComparison.OrdinalIgnoreCase);

            if (proven && root.TryGetProperty("results", out var results))
            {
                // The refusals AND the controls. Refusals alone are also what a chain that never
                // reached the guest would produce, which is why the permitted run is required here:
                // the first recorded attempt scored every refusal against a stale binary.
                foreach (var required in new[]
                         {
                             "permitted_command_ran_as_nobody",
                             "permitted_endpoint_reached_the_syscall",
                             "unleased_second_exec_blocked_by_kernel",
                             "egress_outside_the_lease_blocked_by_kernel",
                         })
                {
                    if (!results.TryGetProperty(required, out var r) || !r.GetBoolean())
                    {
                        proven = false;
                    }
                }

                if (results.TryGetProperty("unleased_exec_output_leaked", out var leaked) && leaked.GetBoolean())
                {
                    proven = false;
                }
            }
            else
            {
                proven = false;
            }
        }

        Assert.True(
            claimsDemonstrated == proven,
            proven
                ? $"{file} records a passing last-hop run, but the README does not say the hop is demonstrated end to end."
                : $"The README says the last hop is demonstrated end to end, but {file} does not record a passing run "
                  + "against the BPF source that ships. Run native/splat-agent/probe-last-hop.ps1 against a root "
                  + "daemon, or withdraw the claim.");
    }

    // ---------------------------------------------------------------- evidence helpers

    private sealed record KernelProof(string File, string Verdict, string KernelRelease);

    private static string EvidenceDir() =>
        Path.Combine(RepositoryRoot(), "native", "splat-canary", "evidence");

    private static List<string> EvidenceFiles() =>
        Directory.Exists(EvidenceDir())
            ? Directory.GetFiles(EvidenceDir(), "*.json").ToList()
            : new List<string>();

    /// <summary>The daemon's own kernel program, which is a deliberate fork of the canary's.</summary>
    private static string AgentBpfSourceSha256()
    {
        string path = Path.Combine(RepositoryRoot(), "native", "splat-agent", "src", "bpf", "lease_lsm.bpf.c");
        using var sha = System.Security.Cryptography.SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(File.ReadAllBytes(path))).ToLowerInvariant();
    }

    private static string BpfSourceSha256()
    {
        string path = Path.Combine(RepositoryRoot(), "native", "splat-canary", "src", "bpf", "lease_lsm.bpf.c");
        using var sha = System.Security.Cryptography.SHA256.Create();
        // The canary hashes the file's bytes via sha256sum, so hash bytes here too - reading it as
        // text would let a line-ending normalisation quietly change the digest.
        return Convert.ToHexString(sha.ComputeHash(File.ReadAllBytes(path))).ToLowerInvariant();
    }

    private static string? ReadJsonString(string file, string property)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(file));
        return doc.RootElement.TryGetProperty(property, out var v) ? v.GetString() : null;
    }

    /// <summary>The passing run, if any, that proves the BPF source currently in the tree.</summary>
    private static KernelProof? CurrentKernelProof()
    {
        string currentSha = BpfSourceSha256();
        foreach (var file in EvidenceFiles())
        {
            if (ReadJsonString(file, "bpf_source_sha256") != currentSha)
            {
                continue;
            }

            if (!string.Equals(ReadJsonString(file, "verdict"), "PASS", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return new KernelProof(
                Path.GetFileName(file),
                "PASS",
                ReadJsonString(file, "kernel_release") ?? "unknown");
        }

        return null;
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
    /// The shields.io badge at the top of the README states the same count in URL-encoded form
    /// (<c>Tests-297%2F297%20passing</c>), which the prose regex above cannot see. It sat at 297
    /// while the suite was at 342 - stale in the most prominent place in the repository, and missed
    /// precisely because it did not spell out "automated tests".
    /// </summary>
    private static readonly Regex TestCountBadgeRegex = new(
        @"Tests-(?<first>\d+)%2F(?<second>\d+)%20passing",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// A third spelling, found 2026-09-09 during a docs sweep: the README's tree diagram said
    /// "350 xUnit unit / integration / security tests" three lines below a correct "459 xUnit
    /// unit, integration, and security tests". Both escaped the two regexes above because neither
    /// says "automated tests" - so the count that drifted was the one no rule covered, which is the
    /// same failure this class was written to stop.
    /// </summary>
    private static readonly Regex TestCountXunitRegex = new(
        @"(?<first>\d+)\s+xUnit",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// A fourth spelling: the pasted run output. The README's verification block and the runbook's
    /// "Expect:" line both quote `Passed! - Failed: 0, Passed: N`, which none of the regexes above
    /// can see — so the runbook sat at 511 while the README said 518, and every count in it had
    /// been updated by hand each time, which is the arrangement this class exists to replace.
    /// </summary>
    private static readonly Regex TestCountRunOutputRegex = new(
        @"Failed:\s*0,\s*Passed:\s*(?<first>\d+)(?:,\s*Skipped:\s*\d+,\s*Total:\s*(?<second>\d+))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Every documented test count, from all three spellings in use: "297/297 automated tests" in
    /// the README's status table, "340 automated tests" in the tutorial's prose, and "459 xUnit …"
    /// in the README's tree diagram. In the paired form both halves are held to the real number,
    /// since a passing suite means run and passed are equal.
    /// </summary>
    private static List<(string File, int Claimed)> FindTestCountClaims()
    {
        string root = RepositoryRoot();
        var claims = new List<(string, int)>();

        // The Field Guide is the source TUTORIAL.md is derived from, and its header said this test
        // enforced the count there. It was never read: it said 387 automated tests while its own
        // copy said 459 and the suite ran 459.
        foreach (string relative in new[]
                 {
                     "README.md",
                     Path.Combine("docs", "TUTORIAL.md"),
                     Path.Combine("docs", "SPLAT-Field-Guide.html"),
                     // The runbook tells a human what to expect from the run they are about to do,
                     // so a stale number there is a verification step that fails for the wrong
                     // reason - and it went stale the first time someone else moved the count.
                     Path.Combine("docs", "RUNBOOK-human-steps.md"),
                 })
        {
            string full = Path.Combine(root, relative);
            if (!File.Exists(full))
            {
                continue;
            }

            string text = File.ReadAllText(full);
            foreach (var regex in new[] { TestCountClaimRegex, TestCountBadgeRegex, TestCountXunitRegex, TestCountRunOutputRegex })
            {
                foreach (Match match in regex.Matches(text))
                {
                    claims.Add((relative, int.Parse(match.Groups["first"].Value)));
                    if (match.Groups["second"].Success)
                    {
                        claims.Add((relative, int.Parse(match.Groups["second"].Value)));
                    }
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
            LeaseSpec lease, string command, IReadOnlyList<string> argv,
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
