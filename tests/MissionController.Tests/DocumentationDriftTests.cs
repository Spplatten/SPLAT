using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
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
    // NOTE: "zero compiler warnings across the solution" was guarded here because it was true only
    // on an incremental build - a cold one emitted MVVMTK0045 once per observable field across the
    // nine ViewModels. Both halves of that have since changed: the UI project suppresses MVVMTK0045
    // under a rationale UiWarningSuppressionTests binds to the absence of AOT and trimming, and
    // src/ and tests/ turn warnings into errors, so a warning there cannot be reported as a warning
    // at all - it fails the build. A cold solution build in a fresh worktree on 2026-09-12 reported
    // 0 Warning(s), 0 Error(s), which is the evidence this retirement needs. The claim is no longer
    // guarded because it is no longer false, and it is now structurally defended rather than lucky.
    // fs_read/fs_write run on the Windows control plane, and run_command depends on a substrate
    // whose enforcement proof is still pending.
    [InlineData("every tool call resolves to a lease")]
    // An underclaim, which rots exactly the same way and is just as wrong to print. The Field Guide
    // told a non-engineer this for weeks while 33 of the 49 catalog templates launched in an
    // AppContainer with no network capability at all. Windows constrains whether, not where - the
    // honest sentence is longer than both the boast and the disclaimer.
    [InlineData("do not filter network sockets")]
    [InlineData("do <strong>not</strong> filter network sockets")]
    // True at 33 of 49, and still printed on the guide's ring diagram at 10 of 49.
    [InlineData("most tools get no network at all")]
    [InlineData("none for most tools")]
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
    /// <summary>
    /// Roadmap 2.4 gates the bridge's caller-identity work on a written threat model, and the gate is
    /// only worth something while the analysis is still there to read. This holds three things: the
    /// section exists, the roadmap points at it, and nothing in the tree has gone back to promising
    /// that a different socket would identify the caller.
    ///
    /// The last part is the one that rots. AF_VSOCK addressing a VM rather than a process is exactly
    /// the kind of fact that reads as a detail and gets written back out as a plan - it was in the
    /// textbook as a roadmap item for weeks, and the measurement that retired it took ten seconds.
    /// </summary>
    [Fact]
    public void TheCallerIdentityThreatModel_IsWrittenDown_AndNothingPromisesASocketWillCloseIt()
    {
        string threatModel = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "THREAT-MODEL.md"));
        Assert.Contains("## Who may drive the lease daemon", threatModel, StringComparison.Ordinal);

        // The measurement the section turns on. Without it the section is an opinion.
        Assert.Contains("uid=0(root)", threatModel, StringComparison.Ordinal);

        string roadmap = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "ROADMAP.md"));
        Assert.Contains("Who may drive the lease daemon", roadmap, StringComparison.Ordinal);

        // Phrases that can only appear in an assertion, never in the retraction of one.
        string[] retired =
        [
            "true cryptographic peer identity",
            "verify the exact Windows SID",
            "cryptographically verify the exact Windows SID"
        ];

        var offenders = new List<string>();
        foreach (string file in Directory.EnumerateFiles(RepositoryRoot(), "*.md", SearchOption.AllDirectories)
                     .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                              && !f.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                              && !f.Contains($"{Path.DirectorySeparatorChar}target{Path.DirectorySeparatorChar}")))
        {
            string text = File.ReadAllText(file);
            foreach (string phrase in retired)
            {
                if (text.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                {
                    offenders.Add($"{Path.GetRelativePath(RepositoryRoot(), file)}: '{phrase}'");
                }
            }
        }

        Assert.Empty(offenders);
    }

    [Fact]
    public void TheWindowsNonEnforcementTable_MatchesTheCatalogAndOpenUiGap()
    {
        string root = RepositoryRoot();
        string architecture = File.ReadAllText(Path.Combine(root, "docs", "ARCHITECTURE-windows-substrate.md"));
        var section = Regex.Match(architecture, @"(?ms)^## What this substrate does not do\r?\n(?<body>.*?)(?=^## |\z)");
        Assert.True(section.Success, "Windows must publish its non-enforcement boundary beside the Linux contract.");
        string table = section.Groups["body"].Value;
        Assert.Contains("| Gap | Consequence | Evidence", table, StringComparison.Ordinal);
        foreach (string gap in new[] { "Destination pinning on Windows", "Network denial for local-subsystem templates",
                     "Filesystem confinement outside AppContainer", "AppContainer filesystem proof",
                     "Job objects as file/socket policy", "Resistance to the operator" })
        {
            var row = Regex.Match(table, @"(?m)^\| \*\*" + Regex.Escape(gap) + @"\*\* \|(?<rest>[^\r\n]+)\r?$");
            Assert.True(row.Success, $"The Windows boundary is missing its {gap} row.");
            Assert.Matches(@"\]\(\.\./(?:src|tests)/[^)]+\)", row.Groups["rest"].Value);
        }

        // Bind the published counts to the same catalog used at launch, not to another document
        // that could be stale in exactly the same way.
        var stated = Regex.Match(table, @"(?<all>\d+) templates: (?<denied>\d+) Windows network-denied, (?<open>\d+) Windows network-capable,\s*(?<leased>\d+) Linux-leased");
        Assert.True(stated.Success, "The Windows table must state its measured catalog census.");
        var census = CapabilityManifest.CensusOf(GovernedTemplateCatalog.All);
        Assert.Equal(census.Templates, int.Parse(stated.Groups["all"].Value));
        Assert.Equal(census.NetworkDenied, int.Parse(stated.Groups["denied"].Value));
        Assert.Equal(census.Windows - census.NetworkDenied, int.Parse(stated.Groups["open"].Value));
        Assert.Equal(census.Leased, int.Parse(stated.Groups["leased"].Value));
        var connected = Regex.Match(table, @"The \d+ comprise (?<needs>\d+) that need network access and (?<local>\d+) that need local Windows");
        Assert.True(connected.Success, "The network-capable census must name both exemption groups.");
        Assert.Equal(census.NeedsNetwork, int.Parse(connected.Groups["needs"].Value));
        Assert.Equal(census.LocalSubsystems, int.Parse(connected.Groups["local"].Value));

        string roadmap = File.ReadAllText(Path.Combine(root, "docs", "ROADMAP.md"));
        if (Regex.IsMatch(roadmap, @"(?m)^\| Job-object UI limits for tier A \|[^\r\n]*\| Open\b"))
        {
            var row = Regex.Match(table, @"(?m)^\| \*\*Job-object UI limits\*\* \|(?<rest>[^\r\n]+)\r?$");
            Assert.True(row.Success, "UI limits remain open in the roadmap; their non-enforcement row cannot disappear.");
            Assert.Contains("clipboard", row.Value, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("window-messaging", row.Value, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("JobObjectBasicUIRestrictions", row.Value, StringComparison.Ordinal);
            Assert.Contains("Win32JobSandbox.cs", row.Value, StringComparison.Ordinal);
        }
        string linux = File.ReadAllText(Path.Combine(root, "native", "splat-agent", "SUPPORTED_POLICY.md"));
        Assert.Contains("ARCHITECTURE-windows-substrate.md#what-this-substrate-does-not-do", linux, StringComparison.Ordinal);
    }

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
    /// <summary>
    /// Set <c>SPLAT_SYNC_TEST_COUNT=1</c> to make this test rewrite the documented counts instead of
    /// asserting them. The count cannot be computed before the suite is built - it comes from
    /// reflecting over the compiled assembly - so there is no earlier point at which a build step
    /// could derive it. This is the next best thing: the number is still derived rather than typed,
    /// and by the same four regexes that detect the drift, so a spelling the detector can see is
    /// necessarily one the writer can fix.
    /// </summary>
    private const string SyncEnvironmentVariable = "SPLAT_SYNC_TEST_COUNT";

    /// <summary>
    /// The sync path only earns its keep if it can write every spelling the detector can read. This
    /// covers all four in one string - prose, shields badge, tree diagram, pasted run output - and
    /// asserts the rewrite is exact, so a fifth spelling added to the detector without a matching
    /// group name fails here rather than silently leaving one document behind.
    /// </summary>
    [Fact]
    public void TheCountRewriter_WritesEverySpellingTheDetectorReads()
    {
        const string before =
            "[![Tests](https://img.shields.io/badge/Tests-11%2F11%20passing-success)](x)\n" +
            "| Governance plane | Shipped - 11/11 automated tests passing |\n" +
            "Backed by 11 automated tests, all passing.\n" +
            "Passed!  - Failed: 0, Passed: 11, Skipped: 0, Total: 11, Duration: 25 s\n" +
            "  # 11 xUnit unit / integration / security tests\n";

        string after = RewriteCounts(before, 4242);

        Assert.DoesNotContain("11", after, StringComparison.Ordinal);

        // Eight digit spans across the five lines: the badge and the paired prose, run output and
        // "N/N" forms each carry two. Counted without a word boundary on purpose - the badge's
        // second number is preceded by the F of %2F, so \b would miss it, which is the exact trap
        // that left the README badge reading 522/521 during an earlier hand-edit.
        Assert.Equal(8, Regex.Matches(after, "4242").Count);

        // Surrounding text must survive untouched; only the digits move.
        Assert.Contains("Tests-4242%2F4242%20passing", after, StringComparison.Ordinal);
        Assert.Contains("Failed: 0, Passed: 4242, Skipped: 0, Total: 4242", after, StringComparison.Ordinal);
        Assert.Contains("4242 xUnit unit / integration / security tests", after, StringComparison.Ordinal);

        // Idempotent: syncing an already-correct document must be a no-op, or every build would
        // report the docs as dirty.
        Assert.Equal(after, RewriteCounts(after, 4242), StringComparer.Ordinal);
    }

    [Fact]
    public void TheAdvertisedTestCount_MatchesTheSuite()
    {
        int actual = CountTestCases();

        if (Environment.GetEnvironmentVariable(SyncEnvironmentVariable) == "1")
        {
            var rewritten = SyncTestCountIntoDocs(actual);
            Assert.True(
                FindTestCountClaims().All(claim => claim.Claimed == actual),
                "Sync ran but left a claim disagreeing with the suite, which means a spelling is " +
                "readable by FindTestCountClaims and not writable by RewriteCounts.");
            return;
        }

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
            "Do not edit these by hand - four documents state the count in four different " +
            "spellings and hand-editing is what put them out of step before. Re-derive them with:" +
            Environment.NewLine +
            $"    {SyncEnvironmentVariable}=1 dotnet test --filter TheAdvertisedTestCount_MatchesTheSuite");
    }


    /// <summary>
    /// The one copy of the Field Guide no test could reach. The published artifact is a deterministic
    /// slice of the source - that file minus the doctype/html/head/body wrapper the artifact host
    /// supplies - so binding the source binds the page, and no network call is needed to do it.
    ///
    /// This is not a hypothetical drift. The live page sat at 511 tests telling readers that on
    /// Windows the locks "do not filter network sockets", for weeks after both repository copies were
    /// corrected to say that 33 of 49 templates launch with no network capability at all. Every other
    /// claim in this class is checked against the code; that one was checked against nothing, because
    /// the only copy a non-engineer actually reads lives outside the repository.
    ///
    /// It cannot prove the republish happened - nothing local can. It makes forgetting it a failed
    /// build instead of a silent one, which is the same bargain the warning gate strikes.
    /// </summary>
    [Fact]
    public void ThePublishedFieldGuide_IsTheSourceAsItStandsToday()
    {
        string root = RepositoryRoot();
        string record = File.ReadAllText(Path.Combine(root, "docs", "SPLAT-Field-Guide.published"));

        var stated = Regex.Match(record, @"^sha256\s+(?<hex>[0-9a-f]{64})\s*$", RegexOptions.Multiline);
        Assert.True(stated.Success, "docs/SPLAT-Field-Guide.published no longer records a sha256 line this test can read");

        // Hashed as normalised text rather than raw bytes: this repository is checked out with
        // core.autocrlf on, so the same commit is CRLF in the shared tree and LF in a worktree, and
        // a byte hash would fail on which machine ran the test rather than on what the page says.
        string source = File.ReadAllText(Path.Combine(root, "docs", "SPLAT-Field-Guide.html"))
            .Replace("\r\n", "\n");
        string actual = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source))).ToLowerInvariant();

        Assert.True(
            actual == stated.Groups["hex"].Value,
            "docs/SPLAT-Field-Guide.html has moved ahead of the published artifact at " +
            "https://claude.ai/code/artifact/18992308-da75-4782-87b8-20b6ba7b4311, so the page a reader " +
            $"opens is stale. Republish it from the current source, then record sha256 {actual} in " +
            "docs/SPLAT-Field-Guide.published. Both halves - updating the hash alone just moves the lie.");
    }

    /// <summary>
    /// The beginning read. Four lines in the record say what is on the live page and whether it is
    /// still current - the version, the hash that binds it to a source already in the tree, and one
    /// line saying what that version changed - so a session that needs to know does not open the
    /// artifact to find out. That read costs about eighteen thousand tokens of context and answers
    /// nothing these lines do not.
    ///
    /// Checked because a record that loses its handoff line loses it silently: the hash check would
    /// still pass, and the next session would go and read the page.
    /// </summary>
    [Fact]
    public void ThePublishedRecord_SaysWhichVersionIsLiveAndWhatItChanged()
    {
        string record = File.ReadAllText(Path.Combine(RepositoryRoot(), "docs", "SPLAT-Field-Guide.published"));

        Assert.True(
            Regex.IsMatch(record, @"(?m)^version\s+\d+\s*$"),
            "docs/SPLAT-Field-Guide.published no longer records which artifact version is live. " +
            "Record it with -RecordPublished -Version <n>.");

        // `\s*$`, for the same reason the version check above carries it: git checks this file out
        // CRLF on Windows, and `$` matches before `\n` but not before `\r`. Without it the assertion
        // held only in the tree that last wrote the record - where the script's own LF endings
        // survive - and failed in every fresh checkout, which is the one place a suite has to be
        // trustworthy. Found on 2026-09-25 in a worktree made minutes earlier.
        var handoff = Regex.Match(record, @"(?m)^handoff\s+(?<line>\S[^\r\n]*?)\s*$");
        Assert.True(
            handoff.Success && handoff.Groups["line"].Value.Trim().Length >= 20,
            "docs/SPLAT-Field-Guide.published no longer carries a handoff line saying what the live " +
            "version changed. Record it with -RecordPublished -Handoff \"<one line>\".");
    }

    /// <summary>
    /// Guards the assumption <see cref="CountTestCases"/> rests on. xUnit expands data attributes at
    /// run time from sources reflection here does not necessarily evaluate, so a test using one it
    /// cannot read would be counted as zero cases and would silently deflate the number the
    /// documents are held to - turning the count check into a rubber stamp.
    ///
    /// <c>[MemberData]</c> over a static, argument-free member IS expanded, by
    /// <see cref="MemberDataRowCount"/>. Everything else still has to fail here.
    /// </summary>
    [Fact]
    public void NoDataSourceEscapesTheTestCounter()
    {
        var unsupported = TestMethods()
            .Where(method => method.GetCustomAttributes()
                .Any(attribute => attribute is ClassDataAttribute
                    || (attribute is MemberDataAttribute member && member.Parameters is { Length: > 0 })))
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
    /// <summary>
    /// Every document that states the count, and every spelling it is stated in. Both lists are
    /// shared by the reader (<see cref="FindTestCountClaims"/>) and the writer
    /// (<see cref="RewriteCounts"/>) so a claim cannot be detectable but unfixable - the failure
    /// mode that would put a human back to hand-editing four files.
    ///
    /// The Field Guide is the source TUTORIAL.md is derived from, and its header once said this test
    /// enforced the count there. It was never read: it said 387 automated tests while its own copy
    /// said 459 and the suite ran 459. The runbook tells a human what to expect from the run they are
    /// about to do, so a stale number there is a verification step that fails for the wrong reason.
    ///
    /// The Field Guide is deliberately NOT in this list any more, and its prose no longer states a
    /// count at all - it points the reader at the README for the number. Every other document here
    /// is a file in this repository, so syncing one costs one edit. That one is also a page
    /// published outside it, and <see cref="ThePublishedFieldGuide_IsTheSourceAsItStandsToday"/>
    /// goes red the moment its source moves - so binding a number that changes on almost every
    /// commit made almost every commit a manual republish of a page whose prose had not changed.
    /// The census counts stay bound there: those move when the product moves, which is exactly when
    /// the page does need republishing. TUTORIAL.md left for the same reason once it became a
    /// rendering of that guide rather than a second copy of it - it states whatever the guide states.
    /// </summary>
    private static readonly string[] DocumentsStatingTheTestCount =
    {
        "README.md",
        Path.Combine("docs", "RUNBOOK-human-steps.md"),
    };

    private static readonly Regex[] TestCountRegexes =
    {
        TestCountClaimRegex, TestCountBadgeRegex, TestCountXunitRegex, TestCountRunOutputRegex,
    };

    /// <summary>
    /// Rewrites every digit span the four spellings identify to <paramref name="actual"/>. Spans are
    /// applied right-to-left so that changing a number's width cannot invalidate the offsets of the
    /// ones not yet written, and an overlapping span is skipped rather than allowed to corrupt a
    /// neighbour - two regexes can legitimately match the same digits.
    /// </summary>
    internal static string RewriteCounts(string text, int actual)
    {
        var spans = TestCountRegexes
            .SelectMany(regex => regex.Matches(text).Cast<Match>())
            .SelectMany(match => new[] { match.Groups["first"], match.Groups["second"] })
            .Where(group => group.Success)
            .Select(group => (group.Index, group.Length))
            .Distinct()
            .OrderByDescending(span => span.Index)
            .ToList();

        var builder = new System.Text.StringBuilder(text);
        int lowestWritten = int.MaxValue;
        foreach (var (index, length) in spans)
        {
            if (index + length > lowestWritten)
            {
                continue; // overlaps a span already rewritten
            }

            builder.Remove(index, length);
            builder.Insert(index, actual.ToString(System.Globalization.CultureInfo.InvariantCulture));
            lowestWritten = index;
        }

        return builder.ToString();
    }

    /// <summary>Writes the derived count into every document that states it. Returns those changed.</summary>
    private static List<string> SyncTestCountIntoDocs(int actual)
    {
        string root = RepositoryRoot();
        var changed = new List<string>();

        foreach (string relative in DocumentsStatingTheTestCount)
        {
            string full = Path.Combine(root, relative);
            if (!File.Exists(full))
            {
                continue;
            }

            string text = File.ReadAllText(full);
            string rewritten = RewriteCounts(text, actual);
            if (!string.Equals(text, rewritten, StringComparison.Ordinal))
            {
                File.WriteAllText(full, rewritten);
                changed.Add(relative);
            }
        }

        return changed;
    }

    private static List<(string File, int Claimed)> FindTestCountClaims()
    {
        string root = RepositoryRoot();
        var claims = new List<(string, int)>();

        foreach (string relative in DocumentsStatingTheTestCount)
        {
            string full = Path.Combine(root, relative);
            if (!File.Exists(full))
            {
                continue;
            }

            string text = File.ReadAllText(full);
            foreach (var regex in TestCountRegexes)
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
            ? method.GetCustomAttributes<InlineDataAttribute>().Count() + MemberDataRowCount(method)
            : 1);

    /// <summary>
    /// Rows a <c>[MemberData]</c> source will yield, for the one shape this counter supports: a
    /// static property or parameterless static method on the declaring type, taking no arguments.
    /// The corpus theories need it - the whole point of enumerating a directory is that adding a
    /// case touches no code, which [InlineData] would undo. Anything more exotic is caught by
    /// <see cref="NoDataSourceEscapesTheTestCounter"/> rather than guessed at here: a count this
    /// file cannot derive must fail loudly, never quietly become zero.
    /// </summary>
    private static int MemberDataRowCount(MethodInfo method)
    {
        int rows = 0;
        foreach (var source in method.GetCustomAttributes<MemberDataAttribute>())
        {
            var owner = source.MemberType ?? method.DeclaringType!;
            const BindingFlags Lookup = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static;

            object? value =
                owner.GetProperty(source.MemberName, Lookup)?.GetValue(null)
                ?? owner.GetMethod(source.MemberName, Lookup, Type.EmptyTypes)?.Invoke(null, null);

            // Not silently zero. An unreadable source is exactly the deflation this guards against.
            Assert.True(value is System.Collections.IEnumerable,
                $"{method.DeclaringType?.Name}.{method.Name} takes [MemberData] from " +
                $"'{source.MemberName}', which this counter could not read as a row set.");

            rows += ((System.Collections.IEnumerable)value!).Cast<object>().Count();
        }

        return rows;
    }

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
