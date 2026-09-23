using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Models;
using MissionController.Core.Replay;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Catalog;

namespace MissionController.Tests;

/// <summary>
/// Turns missions the console has already run into replay fixtures, so a day's live runs become
/// regression tests without running them again.
///
/// The console indexes every accepted mission into semantic memory as one document that carries the
/// sanitized sensor text and the model's accepted answer in full, and seals the run's facts as the
/// mission's last ledger row. That is enough to rebuild the fixture: the answer the pipeline accepted,
/// replayed as the first attempt, against the telemetry it was accepted for. What the index does not
/// hold - the bound parameters, the prompt's hash, a rejected first attempt - is left empty and said so
/// in the file, and the engine's own recorder fills all of it for every run from now on.
///
/// The database is opened read-only. This is the operator's ledger; an export must not be able to
/// extend it.
/// </summary>
internal static class MissionFixtureExporter
{
    /// <summary>Set to <c>1</c> to export before the replay test runs. The database is the console's, or <c>SPLAT_DB_PATH</c>.</summary>
    public const string EnvironmentVariable = "SPLAT_EXPORT_MISSION_FIXTURES";

    /// <summary>Only missions indexed on or after this UTC date (yyyy-MM-dd) are exported. Today when unset.</summary>
    public const string SinceVariable = "SPLAT_EXPORT_MISSION_FIXTURES_SINCE";

    public const string RecordedByLabel = "export from the console database: the accepted answer, replayed as the first attempt";

    private static readonly Regex TelemetryMarker = new(@"\r?\nTELEMETRY:\r?\n", RegexOptions.Compiled);
    private static readonly Regex AnalysisMarker = new(@"\r?\nANALYSIS:", RegexOptions.Compiled | RegexOptions.RightToLeft);

    public static async Task<IReadOnlyList<string>> ExportAsync(string fixtureDirectory, Action<string> log)
    {
        string dbPath = SqliteStorageContext.GetDefaultDatabasePath();
        if (!File.Exists(dbPath))
        {
            log($"export: no console database at {dbPath}; nothing to export");
            return Array.Empty<string>();
        }

        string since = Environment.GetEnvironmentVariable(SinceVariable) is { Length: > 0 } s
            ? s.Trim()
            : DateTime.UtcNow.ToString("yyyy-MM-dd");

        Directory.CreateDirectory(fixtureDirectory);
        var alreadyRecorded = MissionReplayHarness.FixtureFiles(fixtureDirectory)
            .Select(f => { try { return MissionFixture.Load(f).MissionId; } catch { return Guid.Empty; } })
            .ToHashSet();

        var written = new List<string>();
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath, Mode = SqliteOpenMode.ReadOnly }.ToString());
        await using (connection)
        {
            await connection.OpenAsync();

            var documents = new List<(Guid MissionId, string TemplateId, string Content, string Timestamp)>();
            await using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = "SELECT MissionId, TemplateId, Content, TimestampUtc FROM MissionSemanticIndex WHERE TimestampUtc >= $since ORDER BY TimestampUtc DESC;";
                cmd.Parameters.AddWithValue("$since", since);
                await using var reader = await cmd.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    documents.Add((Guid.Parse(reader.GetString(0)), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
                }
            }

            log($"export: {documents.Count} accepted mission(s) indexed since {since} UTC in {dbPath}");

            foreach (var (missionId, templateId, content, timestamp) in documents)
            {
                if (alreadyRecorded.Contains(missionId))
                {
                    log($"  {templateId} {missionId:D}: already a fixture");
                    continue;
                }

                var template = GovernedTemplateCatalog.All.FirstOrDefault(t => t.TemplateId == templateId);
                if (template is null)
                {
                    log($"  {templateId} {missionId:D}: not a catalog template; skipped");
                    continue;
                }

                if (!TrySplitMemoryDocument(content, out string telemetry, out string analysis))
                {
                    log($"  {templateId} {missionId:D}: the memory document has no TELEMETRY/ANALYSIS markers; skipped");
                    continue;
                }

                MissionRunFacts? facts = await ReadFactsAsync(connection, missionId);
                if (facts is null)
                {
                    log($"  {templateId} {missionId:D}: no sealed run facts in the ledger; skipped");
                    continue;
                }

                var fixture = new MissionFixture
                {
                    MissionId = missionId,
                    RecordedAtUtc = DateTime.UtcNow.ToString("O"),
                    RecordedBy = RecordedByLabel,
                    Note = $"Exported from the console's own run of {timestamp}. Parameters were not indexed; the template's defaults bind on replay.",
                    TemplateId = templateId,
                    TemplateName = template.Name,
                    TemplateSha256 = facts.TemplateSha256,
                    Model = facts.Model ?? string.Empty,
                    Sensor = new FixtureSensor
                    {
                        ExitCode = facts.ExitCode ?? 0,
                        TimedOut = facts.TimedOut ?? false,
                        Stdout = telemetry,
                        Stderr = string.Empty,
                        RedactionCount = facts.RedactionCount,
                        RedactedCategories = facts.RedactedCategories.ToList(),
                        AppliedControls = facts.AppliedControls.ToList(),
                    },
                    Attempts =
                    {
                        new FixtureAttempt
                        {
                            Index = 0,
                            Model = template.TargetModel,
                            Response = analysis,
                        },
                    },
                };

                // The expectations are what the pipeline makes of this answer today, and the prompt's
                // hash is today's too: from here on, a change in either is what the fixture detects.
                MissionReplayHarness.MissionReplay replay;
                try
                {
                    replay = await MissionReplayHarness.ReplayAsync(fixture);
                    fixture.Expected = replay.Observed();
                }
                catch (InvalidOperationException ex)
                {
                    log($"  {templateId} {missionId:D}: could not be replayed ({ex.Message}); skipped");
                    continue;
                }

                if (replay.ModelCalls.Count > 0)
                {
                    fixture.SystemPromptSha256 = MissionFixture.Sha256Hex(replay.ModelCalls[0].SystemPrompt);
                }

                if (replay.Island is not null)
                {
                    var first = replay.Island.EvaluatedCohort.OrderBy(c => c.AttemptIndex).First();
                    fixture.Attempts[0].Quadrant = first.Evaluation.Quadrant.ToString();
                    fixture.Attempts[0].X = first.Evaluation.Point.X;
                    fixture.Attempts[0].Y = first.Evaluation.Point.Y;
                }

                string path = Path.Combine(fixtureDirectory, MissionFixtureDirectoryRecorder.FileNameFor(fixture));
                await File.WriteAllTextAsync(path, fixture.Serialize(), new UTF8Encoding(false));
                written.Add(path);
                log($"  {templateId} {missionId:D}: wrote {Path.GetFileName(path)} ({telemetry.Length:N0} chars of telemetry, verdict {fixture.Expected.Status}, accepted {fixture.Expected.Accepted})");
            }
        }

        return written;
    }

    /// <summary>
    /// The memory document is verdict, findings, then <c>TELEMETRY:</c> and the sanitized payload, then
    /// <c>ANALYSIS:</c> and the answer - the shape <c>MissionExecutionEngine.BuildMemoryDocument</c>
    /// writes. The first telemetry marker and the last analysis marker bound the payload, so a payload
    /// that happens to contain either word is still cut in the right place unless the answer itself
    /// begins a line with <c>ANALYSIS:</c>, which the structured contract does not ask of it.
    /// </summary>
    internal static bool TrySplitMemoryDocument(string document, out string telemetry, out string analysis)
    {
        telemetry = string.Empty;
        analysis = string.Empty;

        var start = TelemetryMarker.Match(document);
        if (!start.Success)
        {
            return false;
        }

        var end = AnalysisMarker.Match(document);
        if (!end.Success || end.Index < start.Index + start.Length)
        {
            return false;
        }

        telemetry = document.Substring(start.Index + start.Length, end.Index - (start.Index + start.Length));
        analysis = document.Substring(end.Index + end.Length);
        return true;
    }

    private static async Task<MissionRunFacts?> ReadFactsAsync(SqliteConnection connection, Guid missionId)
    {
        await using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Details FROM AuditLedger WHERE MissionId = $mid AND Action = $action ORDER BY Id DESC LIMIT 1;";
        cmd.Parameters.AddWithValue("$mid", missionId.ToString("D"));
        cmd.Parameters.AddWithValue("$action", MissionRunFacts.LedgerAction);
        object? details = await cmd.ExecuteScalarAsync();
        if (details is not string json || json.Length == 0)
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<MissionRunFacts>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
