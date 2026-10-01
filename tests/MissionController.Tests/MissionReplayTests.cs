using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Models;
using MissionController.Core.Replay;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Vector;
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
        Assert.NotEmpty(files);

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
                // Reinterpreting an old answer cannot prove that a model saw today's prompt. Keep
                // the recording's identity; only a fresh live run can renew template coverage.
                fixture.Expected = observed;

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

    /// <summary>
    /// The export is the operator's route from a day of console runs to a fixture set, and it reads two
    /// tables the console writes rather than anything built for it: the memory index's document and the
    /// ledger's sealed facts. So it is tested against a database those same classes wrote. A run goes
    /// through the pipeline into a real ledger and a real index, the export reads it back read-only,
    /// and the fixture it writes replays to the run's own verdict and rows; a second export writes
    /// nothing, because the mission is a fixture already.
    /// </summary>
    [Fact]
    public async Task TheExporter_TurnsARunTheConsoleIndexed_IntoAFixtureThatReplaysClean()
    {
        string dir = Path.Combine(Path.GetTempPath(), "splat-export-" + Guid.NewGuid().ToString("N"));
        string fixtures = Path.Combine(dir, "fixtures");
        string dbPath = Path.Combine(dir, "missioncontroller.db");
        Directory.CreateDirectory(dir);

        try
        {
            var context = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(context);
            var memory = new SqliteSemanticMemoryIndex(context);

            // The run, as the console would have done it: real sensor-shaped text with a credential
            // in it that the scrub takes out before anything is indexed, and a model answer that
            // quotes the telemetry.
            var run = new MissionFixture
            {
                TemplateId = "secops-ir-triage-snapshot",
                Model = "Anthropic/claude-sonnet-5",
                Sensor = new FixtureSensor
                {
                    ExitCode = 0,
                    Stdout = "--- TCP CONNECTIONS (ESTABLISHED / LISTEN) ---\r\n" +
                             "State  LocalAddress LocalPort RemoteAddress RemotePort OwningProcess\r\n" +
                             "Listen 0.0.0.0      3389      0.0.0.0       0          1204\r\n" +
                             "--- SERVICES OUTSIDE WINDOWS AND PROGRAM FILES ---\r\n" +
                             "Name    State   StartName                 PathName\r\n" +
                             "backup  Running svc_backup password=Sup3rSecret! D:\\tools\\backup.exe\r\n",
                },
                Attempts =
                {
                    new FixtureAttempt
                    {
                        Index = 0,
                        Model = "claude-sonnet-5",
                        Response = "RDP is listening and one service runs outside the Windows folders.\n" +
                                   "```json\n{\"status\":\"Warning\",\"headline\":\"RDP on 3389 and a service at D:\\\\tools\\\\backup.exe\"," +
                                   "\"findings\":[\"Port 3389 is in Listen state, owned by process 1204\"," +
                                   "\"Service backup runs D:\\\\tools\\\\backup.exe as svc_backup\"]," +
                                   "\"recommendedActions\":[\"Confirm RDP is expected on this host\"]}\n```",
                    },
                },
            };

            var live = await MissionReplayHarness.ReplayAsync(run, alsoWriteTo: ledger, memory: memory);
            Assert.Equal("Completed", live.Facts.ExecutionState);
            var liveRows = (await ledger.GetAuditLogsAsync(live.Facts.MissionId, 500)).OrderBy(e => e.Id).Select(e => e.Action).ToList();
            Assert.Equal(live.LedgerActions, liveRows);

            var written = await MissionFixtureExporter.ExportAsync(fixtures, _out.WriteLine, dbPath);
            string file = Assert.Single(written);
            var fixture = MissionFixture.Load(file);

            Assert.Equal(live.Facts.MissionId, fixture.MissionId);
            Assert.Equal(MissionFixtureExporter.RecordedByLabel, fixture.RecordedBy);
            // Undelimited on the left: what the model was handed carries the untrusted-sensor
            // boundary, and what the exporter stores is the sensor text inside it.
            Assert.Equal(
                RecalledContext.Undelimit(live.Payload!).Replace("\r\n", "\n"),
                fixture.Sensor.Stdout.Replace("\r\n", "\n"));
            Assert.DoesNotContain("Sup3rSecret", fixture.Serialize());
            Assert.Equal(live.Analysis, fixture.Attempts.Single().Response);
            Assert.Equal(liveRows, fixture.Expected.LedgerActions);
            Assert.Equal("Warning", fixture.Expected.Status);
            Assert.Empty(fixture.SystemPromptSha256);

            var replay = await MissionReplayHarness.ReplayAsync(fixture);
            Assert.Null(replay.PayloadMismatch());
            Assert.Empty(fixture.Expected.DifferencesFrom(replay.Observed()));
            Assert.Contains(replay.Notes(), note => note.Contains("was not recorded", StringComparison.Ordinal));

            Assert.Empty(await MissionFixtureExporter.ExportAsync(fixtures, _out.WriteLine, dbPath));

            // An indexed answer is not sufficient provenance. Use a fresh destination so
            // deduplication cannot hide whether sealed simulation/rejection facts are checked.
            string refusedDirectory = Path.Combine(dir, "refused-exports");
            string? model = live.Facts.Model;
            foreach (string invalidModel in new[] { "none: a local simulation (provider/model unavailable)", string.Empty })
            {
                live.Facts.Model = invalidModel;
                await ledger.AppendLogAsync(live.Facts.MissionId, run.TemplateId, MissionRunFacts.LedgerAction,
                    JsonSerializer.Serialize(live.Facts), "export-test");
                Assert.Empty(await MissionFixtureExporter.ExportAsync(refusedDirectory, _out.WriteLine, dbPath));
            }
            live.Facts.Model = model;
            live.Facts.QualityAccepted = false;
            await ledger.AppendLogAsync(live.Facts.MissionId, run.TemplateId, MissionRunFacts.LedgerAction,
                JsonSerializer.Serialize(live.Facts), "export-test");
            Assert.Empty(await MissionFixtureExporter.ExportAsync(refusedDirectory, _out.WriteLine, dbPath));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            try { Directory.Delete(dir, recursive: true); } catch { /* the pool may still hold the db */ }
        }
    }
}
