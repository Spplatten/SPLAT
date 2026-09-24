using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland;

namespace MissionController.Core.Replay;

/// <summary>
/// One mission's post-tool path, recorded so it can be replayed without a model.
///
/// The defects that reach this product are in the interplay: the sensor's real output, the scrub
/// over it, the prompt built from it, what the model answered, and what the extractor and grounder
/// made of that answer. None of that is reachable from a unit test with a made-up telemetry string,
/// and every live run costs an API call. A fixture keeps the real inputs - the sensor text as the
/// model saw it, and the model's answer - beside the verdict the pipeline reached, so the whole path
/// from the sensor to the verdict runs again offline, and a change that alters the verdict fails a
/// test instead of a mission.
///
/// What is kept is what the live pipeline let through: the sensor text AFTER the credential and DLP
/// scrub, and the model's answer after the island's own scrub. The raw output is not recorded, for
/// the same reason it is not sent anywhere.
/// </summary>
public sealed class MissionFixture
{
    public const int CurrentSchema = 1;

    public int Schema { get; set; } = CurrentSchema;
    public Guid MissionId { get; set; }
    public string RecordedAtUtc { get; set; } = string.Empty;

    /// <summary>Which host wrote this: the console, splat-mcp, the live canary, or an export from a database.</summary>
    public string RecordedBy { get; set; } = string.Empty;

    /// <summary>What this fixture guards, in the operator's words. Optional; written when the file is promoted.</summary>
    public string? Note { get; set; }

    public string TemplateId { get; set; } = string.Empty;
    public string TemplateName { get; set; } = string.Empty;

    /// <summary>
    /// <see cref="MissionRunFacts.HashTemplate"/> of the template as it ran. A replay against a template
    /// that has since changed still runs - the model's answer is still real - but says so.
    /// </summary>
    public string TemplateSha256 { get; set; } = string.Empty;

    /// <summary>The bound parameters, scrubbed like the command line is.</summary>
    public Dictionary<string, string> Parameters { get; set; } = new();

    /// <summary>The provider and model that answered, as the run record names it.</summary>
    public string Model { get; set; } = string.Empty;

    /// <summary>
    /// SHA-256 of the system prompt the first attempt was sent: the template's prompt, the operator's
    /// directive, recalled memory and the structured-output contract. A replay rebuilds it from the
    /// same template and reports when the rebuilt prompt is not the one the model answered.
    /// </summary>
    public string SystemPromptSha256 { get; set; } = string.Empty;

    public FixtureSensor Sensor { get; set; } = new();

    /// <summary>Every model attempt the quality island made, in order: the first, and the escalation if there was one.</summary>
    public List<FixtureAttempt> Attempts { get; set; } = new();

    /// <summary>The verdict the pipeline reached when this was recorded, which a replay is held to.</summary>
    public FixtureVerdict Expected { get; set; } = new();

    // Relaxed escaping on purpose: a fixture is reviewed by a person before it is committed, and
    // telemetry full of < and ' cannot be reviewed. Indented for the same reader.
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string Serialize() => JsonSerializer.Serialize(this, Options);

    public static MissionFixture Deserialize(string json)
    {
        var fixture = JsonSerializer.Deserialize<MissionFixture>(json, Options)
            ?? throw new InvalidDataException("the fixture is not a JSON object");
        if (fixture.Schema != CurrentSchema)
        {
            throw new InvalidDataException($"the fixture is schema {fixture.Schema}; this build reads schema {CurrentSchema}");
        }

        return fixture;
    }

    public static MissionFixture Load(string path) => Deserialize(File.ReadAllText(path));

    /// <summary>
    /// The user prompt the model is sent: the sanitized stdout, then the sanitized stderr on its own line
    /// when there is any. The same shape <c>MissionExecutionEngine</c> builds, so a replay can check the
    /// model would see the bytes it saw.
    /// </summary>
    public string SanitizedPayload() => string.IsNullOrEmpty(Sensor.Stderr)
        ? Sensor.Stdout
        : Sensor.Stdout + "\n" + Sensor.Stderr;

    public static string Sha256Hex(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant();

    /// <summary>
    /// Captures a mission at the point its analysis is decided: after the scrub, after the island, before
    /// the memory index and the teardown. Called by the engine; every argument is what the engine already
    /// holds, so nothing is reconstructed.
    /// </summary>
    public static MissionFixture Capture(
        SingleToolTemplate template,
        IReadOnlyDictionary<string, string> scrubbedParameters,
        MissionRunFacts facts,
        string sanitizedStdout,
        string sanitizedStderr,
        int exitCode,
        bool timedOut,
        string effectiveSystemPrompt,
        QualityIslandResult island,
        ExecutiveDiagnosisResult verdict)
    {
        var fixture = new MissionFixture
        {
            MissionId = facts.MissionId,
            RecordedAtUtc = DateTime.UtcNow.ToString("O"),
            TemplateId = template.TemplateId,
            TemplateName = template.Name,
            TemplateSha256 = facts.TemplateSha256,
            Parameters = new Dictionary<string, string>(scrubbedParameters),
            Model = facts.Model ?? string.Empty,
            // Nonce-free: the sensor boundary is redrawn every assembly, so hashing the prompt
            // as-is would make a recorded prompt differ from a rebuilt one on every replay.
            SystemPromptSha256 = Sha256Hex(RecalledContext.NormalizeBoundaries(effectiveSystemPrompt)),
            Sensor = new FixtureSensor
            {
                ExitCode = exitCode,
                TimedOut = timedOut,
                Stdout = sanitizedStdout,
                Stderr = sanitizedStderr,
                RedactionCount = facts.RedactionCount,
                RedactedCategories = facts.RedactedCategories.ToList(),
                AppliedControls = facts.AppliedControls.ToList(),
            },
            Attempts = island.EvaluatedCohort
                .OrderBy(candidate => candidate.AttemptIndex)
                .Select(candidate => new FixtureAttempt
                {
                    Index = candidate.AttemptIndex,
                    Model = candidate.ModelId,
                    // The island's scrubbed copy, for the reason the raw sensor output is not kept.
                    Response = candidate.SanitizedContent,
                    LatencyMs = candidate.LatencyMs,
                    Quadrant = candidate.Evaluation?.Quadrant.ToString() ?? string.Empty,
                    X = candidate.Evaluation?.Point.X ?? 0d,
                    Y = candidate.Evaluation?.Point.Y ?? 0d,
                })
                .ToList(),
            Expected = FixtureVerdict.From(island, verdict, ledgerActions: null),
        };

        return fixture;
    }
}

/// <summary>The sensor's run, as the model was allowed to see it.</summary>
public sealed class FixtureSensor
{
    public int ExitCode { get; set; }
    public bool TimedOut { get; set; }

    /// <summary>Standard output after the credential and DLP scrub. Never the raw text.</summary>
    public string Stdout { get; set; } = string.Empty;

    /// <summary>Standard error after the same scrub.</summary>
    public string Stderr { get; set; } = string.Empty;

    /// <summary>What the live scrub removed from the raw output, by count and category; the raw text itself is gone.</summary>
    public int RedactionCount { get; set; }
    public List<string> RedactedCategories { get; set; } = new();

    /// <summary>What confined the live run, read back from the kernel objects, for the record.</summary>
    public List<string> AppliedControls { get; set; } = new();
}

/// <summary>One model call the quality island made.</summary>
public sealed class FixtureAttempt
{
    public int Index { get; set; }

    /// <summary>The model the island asked for on this attempt: the template's, or the escalation model.</summary>
    public string Model { get; set; } = string.Empty;

    /// <summary>The model's answer, after the island's scrub.</summary>
    public string Response { get; set; } = string.Empty;

    public long LatencyMs { get; set; }
    public string Quadrant { get; set; } = string.Empty;
    public double X { get; set; }
    public double Y { get; set; }
}

/// <summary>
/// The verdict the pipeline reached, as a replay is held to it. Every field is what the engine, the
/// island and the extractor produced, never what a person thought they should produce.
/// </summary>
public sealed class FixtureVerdict
{
    public bool Accepted { get; set; }

    /// <summary>The run record's state for the analysis: Completed, or AnalysisRejected.</summary>
    public string ExecutionState { get; set; } = string.Empty;
    public string? RejectionReason { get; set; }
    public bool EscalationTriggered { get; set; }

    /// <summary>SHA-256 of the analysis text the mission published, so a replay proves the same bytes came out.</summary>
    public string OutputSha256 { get; set; } = string.Empty;

    public string Status { get; set; } = string.Empty;
    public string Headline { get; set; } = string.Empty;
    public List<string> Findings { get; set; } = new();
    public List<string> RecommendedActions { get; set; } = new();
    public int Grounded { get; set; }
    public int PartiallyGrounded { get; set; }
    public int Unsupported { get; set; }
    public int Unattributed { get; set; }

    /// <summary>
    /// The ledger's actions for the mission, in order. Null when the recorder could not see the ledger
    /// (the engine's own recorder cannot); filled in by a replay, and then held to.
    /// </summary>
    public List<string>? LedgerActions { get; set; }

    public static FixtureVerdict From(QualityIslandResult island, ExecutiveDiagnosisResult verdict, IReadOnlyList<string>? ledgerActions) => new()
    {
        Accepted = island.IsSuccess,
        ExecutionState = island.IsSuccess ? "Completed" : "AnalysisRejected",
        RejectionReason = island.IsSuccess ? null : island.Telemetry.InitialFailureReason,
        EscalationTriggered = island.Telemetry.EscalationTriggered,
        OutputSha256 = MissionFixture.Sha256Hex(island.OutputContent),
        Status = verdict.OverallStatus.ToString(),
        Headline = verdict.StatusHeadline,
        Findings = verdict.KeyFindings.ToList(),
        RecommendedActions = (verdict.RecommendedActions ?? Array.Empty<string>()).ToList(),
        Grounded = verdict.Attestation?.GroundedCount ?? 0,
        PartiallyGrounded = verdict.Attestation?.PartiallyGroundedCount ?? 0,
        Unsupported = verdict.Attestation?.UnsupportedCount ?? 0,
        Unattributed = verdict.Attestation?.UnattributedCount ?? 0,
        LedgerActions = ledgerActions?.ToList(),
    };

    /// <summary>
    /// Every way <paramref name="observed"/> departs from this verdict, one line each, empty when it does
    /// not. The ledger's actions are compared only when this verdict recorded them.
    /// </summary>
    public IReadOnlyList<string> DifferencesFrom(FixtureVerdict observed)
    {
        var differences = new List<string>();

        void Check<T>(string what, T expected, T actual) where T : notnull
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
            {
                differences.Add($"{what}: recorded {Show(expected)}, replay produced {Show(actual)}");
            }
        }

        Check("accepted", Accepted, observed.Accepted);
        Check("execution state", ExecutionState, observed.ExecutionState);
        Check("rejection reason", RejectionReason ?? string.Empty, observed.RejectionReason ?? string.Empty);
        Check("escalation", EscalationTriggered, observed.EscalationTriggered);
        Check("output sha256", OutputSha256, observed.OutputSha256);
        Check("status", Status, observed.Status);
        Check("headline", Headline, observed.Headline);
        CheckList("findings", Findings, observed.Findings, differences);
        CheckList("recommended actions", RecommendedActions, observed.RecommendedActions, differences);
        Check("grounded", Grounded, observed.Grounded);
        Check("partially grounded", PartiallyGrounded, observed.PartiallyGrounded);
        Check("unsupported", Unsupported, observed.Unsupported);
        Check("unattributed", Unattributed, observed.Unattributed);

        if (LedgerActions is { Count: > 0 })
        {
            CheckList("ledger actions", LedgerActions, observed.LedgerActions ?? new List<string>(), differences);
        }

        return differences;
    }

    private static void CheckList(string what, IReadOnlyList<string> expected, IReadOnlyList<string> actual, List<string> differences)
    {
        if (expected.SequenceEqual(actual, StringComparer.Ordinal))
        {
            return;
        }

        if (expected.Count != actual.Count)
        {
            differences.Add($"{what}: recorded {expected.Count}, replay produced {actual.Count}");
        }

        for (int i = 0; i < Math.Min(expected.Count, actual.Count); i++)
        {
            if (!string.Equals(expected[i], actual[i], StringComparison.Ordinal))
            {
                differences.Add($"{what}[{i}]: recorded {Show(expected[i])}, replay produced {Show(actual[i])}");
            }
        }
    }

    private static string Show<T>(T value) => value switch
    {
        string s when s.Length > 160 => "\"" + s[..160] + "…\"",
        string s => "\"" + s + "\"",
        _ => value?.ToString() ?? "null",
    };
}

/// <summary>Where a mission's fixture goes once the engine has captured it.</summary>
public interface IMissionRecorder
{
    Task RecordAsync(MissionFixture fixture, CancellationToken cancellationToken = default);
}

/// <summary>
/// Writes each fixture as one JSON file in a directory the operator names. Attached by a host when
/// <see cref="EnvironmentVariable"/> is set, and by the live canary; the file is then reviewed and
/// promoted into the suite's fixture directory by hand, because it carries the operator's own
/// telemetry.
/// </summary>
public sealed class MissionFixtureDirectoryRecorder : IMissionRecorder
{
    public const string EnvironmentVariable = "SPLAT_RECORD_MISSIONS_DIR";

    private readonly string _recordedBy;

    public MissionFixtureDirectoryRecorder(string directoryPath, string recordedBy)
    {
        DirectoryPath = directoryPath;
        _recordedBy = recordedBy;
    }

    public string DirectoryPath { get; }

    /// <summary>The file the last call wrote, for a caller that wants to read it back.</summary>
    public string? LastWrittenPath { get; private set; }

    /// <summary>A recorder for the directory the environment names, or null when it names none.</summary>
    public static MissionFixtureDirectoryRecorder? FromEnvironment(string recordedBy)
    {
        string? directory = Environment.GetEnvironmentVariable(EnvironmentVariable);
        return string.IsNullOrWhiteSpace(directory) ? null : new MissionFixtureDirectoryRecorder(directory, recordedBy);
    }

    /// <summary>Template, the moment, and enough of the mission id to tell two runs of one template apart.</summary>
    public static string FileNameFor(MissionFixture fixture) =>
        $"{fixture.TemplateId}--{DateTime.UtcNow:yyyyMMdd-HHmmss}--{fixture.MissionId.ToString("N")[..8]}.json";

    public async Task RecordAsync(MissionFixture fixture, CancellationToken cancellationToken = default)
    {
        fixture.RecordedBy = _recordedBy;
        Directory.CreateDirectory(DirectoryPath);
        string path = Path.Combine(DirectoryPath, FileNameFor(fixture));
        await File.WriteAllTextAsync(path, fixture.Serialize(), new UTF8Encoding(false), cancellationToken);
        LastWrittenPath = path;
    }
}
