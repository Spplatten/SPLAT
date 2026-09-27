using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using Xunit;
using Xunit.Abstractions;

namespace MissionController.Tests;

/// <summary>
/// The daemon probe's SCORING, run against recorded frames instead of a live daemon.
///
/// This exists because of what the root runs were being spent on. A re-proof costs the operator a
/// stopped service, a rebuild in the guest and two probe runs, and the permission classifier refuses
/// an agent every route to a root daemon - so each cycle is a human round trip. The 2026-09-26 run
/// came back INCOMPLETE on two checks, and NEITHER was the kernel failing to contain:
/// <c>udp_outside_the_lease_blocked</c> read a VIOLATION frame that had been lost in transit while the
/// kernel's own counter in the same receipt said the denial happened, and
/// <c>mission_workspace_made_and_removed</c> was a five-part AND that recorded nothing but its False.
///
/// An entire root run went to discovering that the probe could not read evidence it already held. That
/// is the class of defect these tests take out of the root-run budget: anything decided by reading
/// frames is decided here, on every build, for free.
///
/// What these tests do NOT establish: that the kernel contains anything. A replay contacts no daemon,
/// its verdict is the string REPLAY rather than PASS, and `DocumentationDriftTests` accepts only PASS -
/// so no fixture can ever promote a claim about a kernel. Checks read from the host rather than from a
/// frame (the jail's view of /home and /mnt, whether a workspace path exists) stay the live daemon's to
/// answer.
/// </summary>
[Collection(SerialProcessSpawning.Name)]
public class ProbeScoringTests
{
    private readonly ITestOutputHelper _out;

    public ProbeScoringTests(ITestOutputHelper output) => _out = output;

    /// <summary>
    /// The 2026-09-26 defect, as a fixture: the kernel refused a datagram, its VIOLATION frame never
    /// reached the session, and the EXIT receipt carried the kernel's own count and called it whole.
    ///
    /// The denial must be scored from the receipt, and the lost frame must remain visible. Before
    /// 2026-09-27 the first of these was False - a working kernel reported as broken, which sends the
    /// next repair at the wrong layer - and the second did not exist.
    /// </summary>
    [Fact]
    public void ADeniedDatagramWhoseFrameWasLost_IsStillScoredAsDenied()
    {
        var results = RunReplay("lost-violation-frame.json");

        Assert.True(results["udp_outside_the_lease_blocked"]!.Value,
            "the kernel's own violation count says the datagram was refused, so the claim must hold " +
            "even though the frame never arrived.");

        Assert.False(results["udp_violation_frame_reached_the_session"]!.Value,
            "the lost frame is a defect in the return path and has to stay measurable now that the " +
            "claim no longer rests on it.");

        // The receipt is what carried the denial, so its own checks must agree.
        Assert.True(results["refusal_receipt_counts_the_denial"]!.Value);
        Assert.True(results["refusal_receipt_says_it_is_complete"]!.Value);

        // And the permitted control reported zero rather than staying silent: a field that appears only
        // after a denial cannot be read as "nothing was denied".
        Assert.True(results["a_clean_lease_reports_zero_refusals"]!.Value);
    }

    /// <summary>
    /// A datagram that actually went out is NOT a denial, whatever else a receipt counted. This is the
    /// guard that keeps the change above from being the weaker test: reading the receipt would let an
    /// unrelated violation stand in for a send that succeeded, and the "SENT" check is what prevents it.
    /// </summary>
    [Fact]
    public void ADatagramThatWasSent_IsNeverScoredAsDenied_EvenWithAViolationCounted()
    {
        var results = RunReplay("datagram-sent-despite-a-counted-violation.json");

        Assert.False(results["udp_outside_the_lease_blocked"]!.Value,
            "the workload printed SENT, so the datagram left - a violation counted from something " +
            "else must not be allowed to stand in for a refusal that did not happen.");
    }

    /// <summary>
    /// The composite that could not say where it broke. Each conjunct is recorded separately now, so a
    /// failing workspace names its own cause instead of costing a second root run to find it.
    /// </summary>
    [Fact]
    public void AWorkspaceThatWasNotRemoved_NamesWhichPartFailed()
    {
        var results = RunReplay("workspace-not-removed.json");

        Assert.False(results["mission_workspace_made_and_removed"]!.Value);

        // The daemon's word and the host's are kept apart on purpose: made and written to, but the
        // daemon reported it could not remove it. That is a different defect from a daemon that said it
        // removed the workspace while the path survived, and the two used to be one False.
        Assert.True(results["mission_workspace_frame_says_created"]!.Value);
        Assert.True(results["mission_workspace_tool_wrote_in_it"]!.Value);
        Assert.False(results["mission_workspace_exit_says_removed"]!.Value);
    }

    [Fact]
    public void AReplayIsNeverEvidence_AboutAKernel()
    {
        var evidence = RunReplayRaw("lost-violation-frame.json");

        // DocumentationDriftTests binds the README's enforcement claim to verdict == "PASS". A replay
        // says REPLAY, so no fixture can promote a claim, and the file names the fixture it came from.
        Assert.Equal("REPLAY", evidence.GetProperty("verdict").GetString());
        Assert.Contains("lost-violation-frame.json", evidence.GetProperty("replay_fixture").GetString()!);
        Assert.NotEqual("PASS", evidence.GetProperty("verdict").GetString());
    }

    // ------------------------------------------------------------------ harness

    private Dictionary<string, bool?> RunReplay(string fixtureName)
    {
        var results = RunReplayRaw(fixtureName).GetProperty("results");
        var map = new Dictionary<string, bool?>(StringComparer.Ordinal);
        foreach (var property in results.EnumerateObject())
        {
            map[property.Name] = property.Value.ValueKind switch
            {
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => null,
            };
        }

        return map;
    }

    /// <summary>
    /// Runs the probe's OWN embedded Python, extracted from the shipping script rather than copied into
    /// this test. A scoring test that exercised a copy would pass while the script failed, which is
    /// exactly how a base64 NameError survived a unit test and then died on the operator's root run.
    /// </summary>
    private JsonElement RunReplayRaw(string fixtureName)
    {
        string root = RepositoryRoot();
        string script = Path.Combine(root, "native", "splat-agent", "probe-daemon.sh");
        string fixture = Path.Combine(root, "native", "splat-agent", "fixtures", fixtureName);
        Assert.True(File.Exists(script), $"{script} is missing.");
        Assert.True(File.Exists(fixture), $"{fixture} is missing.");

        string[] lines = File.ReadAllLines(script);
        int start = Array.FindIndex(lines, l => l.StartsWith("python3 - ", StringComparison.Ordinal) && l.Contains("<<'PY'"));
        Assert.True(start >= 0, "the probe no longer starts its embedded python with a `python3 - ... <<'PY'` heredoc.");
        int end = Array.FindIndex(lines, start + 1, l => l.Trim() == "PY");
        Assert.True(end > start, "the probe's embedded python block is not terminated by a line reading PY.");

        string work = Path.Combine(Path.GetTempPath(), $"splat-probe-replay-{Guid.NewGuid():N}");
        Directory.CreateDirectory(work);
        try
        {
            string program = Path.Combine(work, "probe.py");
            File.WriteAllLines(program, lines.Skip(start + 1).Take(end - start - 1));

            var psi = new ProcessStartInfo(PythonExecutable(), $"\"{program}\" 127.0.0.1 50051 replay-token")
            {
                WorkingDirectory = work,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            psi.Environment["SPLAT_PROBE_REPLAY"] = fixture;
            psi.Environment["SPLAT_EVIDENCE_DIR"] = work;

            using var process = Process.Start(psi)!;
            string output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit();
            _out.WriteLine(output);

            string evidencePath = Path.Combine(work, "daemon-probe.json");
            Assert.True(File.Exists(evidencePath),
                $"the replay wrote no evidence. Exit {process.ExitCode}. Output:{Environment.NewLine}{output}");

            using var document = JsonDocument.Parse(File.ReadAllText(evidencePath));
            return document.RootElement.Clone();
        }
        finally
        {
            try { Directory.Delete(work, recursive: true); } catch { /* temp */ }
        }
    }

    /// <summary>
    /// `python3` on a POSIX host, `python` on Windows where the py launcher installs no python3.exe.
    /// A missing interpreter FAILS rather than skips: this test is cheap and its whole purpose is to
    /// keep a defect class out of the operator's root-run budget, and a silently skipped guard would
    /// hand that budget the defects right back.
    /// </summary>
    private static string PythonExecutable() =>
        OperatingSystem.IsWindows() ? "python" : "python3";

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "native", "splat-agent")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
