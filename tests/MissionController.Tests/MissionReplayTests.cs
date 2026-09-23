using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MissionController.Core.Replay;
using Xunit;
using Xunit.Abstractions;

namespace MissionController.Tests;

/// <summary>
/// Every recorded mission runs again, offline, through the real post-tool pipeline, and must reach the
/// verdict it reached when it was recorded.
///
/// This is the test the interplay defects were never reachable by: the sensor's real output, the scrub,
/// the prompt, the model's real answer, the island, the extractor and the grounder, in one run, with
/// no API spend. A fixture is a real run - recorded by the console or splat-mcp with
/// <c>SPLAT_RECORD_MISSIONS_DIR</c> set, by the live canary, or exported from the console's own
/// database - so a change that alters what the pipeline makes of a real answer fails here first.
///
///     # export today's console runs as fixtures, then replay everything
///     $env:SPLAT_EXPORT_MISSION_FIXTURES = "1"
///     dotnet test --filter FullyQualifiedName~MissionReplayTests
///
///     # accept the current pipeline's reading of every fixture, after reviewing why it changed
///     $env:SPLAT_BLESS_MISSION_FIXTURES = "1"
///     dotnet test --filter FullyQualifiedName~MissionReplayTests
///
/// One test, not one per fixture, on purpose: the suite's advertised count is bound to the assembly,
/// and promoting a fixture must not move it.
/// </summary>
public sealed class MissionReplayTests
{
    /// <summary>Set to <c>1</c> to rewrite each fixture's expectations from this replay instead of asserting them.</summary>
    public const string BlessVariable = "SPLAT_BLESS_MISSION_FIXTURES";

    private readonly ITestOutputHelper _out;

    public MissionReplayTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public async Task EveryRecordedMission_ReplaysOffline_ToTheVerdictItRecorded()
    {
        string directory = MissionReplayHarness.FixtureDirectory;
        Assert.True(
            Directory.Exists(directory),
            $"{directory} is missing, so no fixture could ever be read. It carries a README and must exist.");

        if (Environment.GetEnvironmentVariable(MissionFixtureExporter.EnvironmentVariable) == "1")
        {
            var exported = await MissionFixtureExporter.ExportAsync(directory, _out.WriteLine);
            _out.WriteLine($"export: {exported.Count} fixture(s) written to {directory}");
        }

        bool bless = Environment.GetEnvironmentVariable(BlessVariable) == "1";
        var files = MissionReplayHarness.FixtureFiles(directory);
        if (files.Count == 0)
        {
            // Out loud, like the live tests' skip: a replay suite with nothing to replay must never
            // read as a green one.
            _out.WriteLine(
                "NO FIXTURES: nothing has been recorded into " + directory + ". Record a run with " +
                $"{MissionFixtureDirectoryRecorder.EnvironmentVariable} set, or export the console's runs with " +
                $"{MissionFixtureExporter.EnvironmentVariable}=1, then promote the reviewed file here.");
            return;
        }

        var failures = new List<string>();
        foreach (string file in files)
        {
            string name = Path.GetFileName(file);
            MissionFixture fixture;
            try
            {
                fixture = MissionFixture.Load(file);
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or System.Text.Json.JsonException)
            {
                failures.Add($"{name}: cannot be read ({ex.Message})");
                continue;
            }

            MissionReplayHarness.MissionReplay replay;
            FixtureVerdict observed;
            try
            {
                replay = await MissionReplayHarness.ReplayAsync(fixture);
                observed = replay.Observed();
            }
            catch (InvalidOperationException ex)
            {
                failures.Add($"{name}: {ex.Message}");
                continue;
            }

            var problems = new List<string>();
            if (replay.PayloadMismatch() is { } mismatch)
            {
                problems.Add(mismatch);
            }

            problems.AddRange(fixture.Expected.DifferencesFrom(observed));

            var line = new StringBuilder();
            line.Append(name).Append(": ").Append(fixture.TemplateId)
                .Append(", ").Append(fixture.SanitizedPayload().Length.ToString("N0")).Append(" chars of telemetry, ")
                .Append(fixture.Attempts.Count).Append(" attempt(s) -> ")
                .Append(observed.Status).Append(observed.Accepted ? ", accepted" : ", rejected")
                .Append(" (").Append(observed.Grounded).Append(" grounded, ")
                .Append(observed.PartiallyGrounded).Append(" partial, ")
                .Append(observed.Unsupported).Append(" unsupported, ")
                .Append(observed.Unattributed).Append(" unattributed)");

            foreach (string note in replay.Notes())
            {
                line.Append("; note: ").Append(note);
            }

            if (bless)
            {
                // The answer stays what the model said; the reading of it becomes today's. The template
                // and prompt hashes move with it, because blessing is accepting the current pipeline.
                fixture.Expected = observed;
                fixture.TemplateSha256 = MissionController.Core.Models.MissionRunFacts.HashTemplate(replay.Template);
                if (replay.ModelCalls.Count > 0)
                {
                    fixture.SystemPromptSha256 = MissionFixture.Sha256Hex(replay.ModelCalls[0].SystemPrompt);
                }

                await File.WriteAllTextAsync(file, fixture.Serialize(), new UTF8Encoding(false));
                line.Append(problems.Count == 0 ? "; blessed, unchanged" : $"; blessed, {problems.Count} expectation(s) rewritten");
            }
            else if (problems.Count > 0)
            {
                line.Append("; FAILED");
                failures.Add($"{name} ({fixture.TemplateId}):" + Environment.NewLine + "    " + string.Join(Environment.NewLine + "    ", problems));
            }

            _out.WriteLine(line.ToString());
        }

        _out.WriteLine($"{files.Count} fixture(s) replayed, {failures.Count} failed");

        Assert.True(
            failures.Count == 0,
            $"{failures.Count} of {files.Count} recorded mission(s) no longer replay to the verdict they recorded:" +
            Environment.NewLine + string.Join(Environment.NewLine, failures) + Environment.NewLine + Environment.NewLine +
            "If the pipeline is right and the fixture is stale, re-derive its expectations rather than editing them: " +
            $"{BlessVariable}=1 dotnet test --filter FullyQualifiedName~MissionReplayTests, then review the diff.");
    }
}
