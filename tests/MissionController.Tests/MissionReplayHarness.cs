using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland;
using MissionController.Core.QualityIsland.Contracts;
using MissionController.Core.Replay;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Network.Dlp;
using MissionController.Infrastructure.Network.Identity;

namespace MissionController.Tests;

/// <summary>
/// Runs a recorded mission's post-tool path again with no model and no sandbox: the fixture's sensor
/// text stands in for the tool, its recorded answers stand in for the provider, and everything between
/// them - the credential and DLP scrub, the prompt, the quality island, the extractor, the grounder,
/// the ledger rows and the run facts - is the real code the console and splat-mcp run.
///
/// The Windows substrate is the one thing not under test here, and it is the one thing this harness
/// fakes: a jail path, a job that holds nothing, and a launcher that answers with the recorded output.
/// </summary>
internal static class MissionReplayHarness
{
    public static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        return dir?.FullName ?? throw new DirectoryNotFoundException("MissionController.sln was not found above the test assembly");
    }

    /// <summary>Where the suite's fixtures live. Read from the source tree, so a promoted file needs no build step.</summary>
    public static string FixtureDirectory =>
        Path.Combine(RepositoryRoot(), "tests", "MissionController.Tests", "Fixtures", "Missions");

    public static IReadOnlyList<string> FixtureFiles(string? directory = null)
    {
        string dir = directory ?? FixtureDirectory;
        return Directory.Exists(dir)
            ? Directory.EnumerateFiles(dir, "*.json").OrderBy(f => f, StringComparer.Ordinal).ToList()
            : Array.Empty<string>();
    }

    public static SingleToolTemplate TemplateFor(MissionFixture fixture) =>
        GovernedTemplateCatalog.All.FirstOrDefault(t => t.TemplateId == fixture.TemplateId)
        ?? throw new InvalidOperationException(
            $"the fixture names template '{fixture.TemplateId}', which is not in the shipped catalog; a fixture replays the catalog's template so that the template's prompt is the one under test");

    /// <summary>
    /// Replays one fixture and returns everything the pipeline produced. With <paramref name="alsoWriteTo"/>
    /// and <paramref name="memory"/> the same run is also written where a host would write it - a real
    /// ledger and a real memory index - which is how a test stands up "a run the console did".
    /// </summary>
    public static async Task<MissionReplay> ReplayAsync(
        MissionFixture fixture,
        IAuditLedger? alsoWriteTo = null,
        ISemanticMemoryIndex? memory = null,
        CancellationToken cancellationToken = default)
    {
        var template = TemplateFor(fixture);
        var ledger = new RecordingLedger(alsoWriteTo);
        var client = new ReplayModelClient(fixture);
        var dlp = new RegexDataLossPreventionSanitizer();
        var credentials = new PromptCredentialSanitizer();
        var extractor = new JsonFindingsExtractor();

        // The island is built exactly as the engine builds its own, and wrapped only to keep its
        // result: the engine's recorder sees the result directly, and a replay has to see the same.
        var island = new CapturingIsland(new QualityIslandEngine(
            client,
            ledger,
            dlpSanitizer: dlp,
            credentialSanitizer: credentials,
            findingsExtractor: extractor));

        var engine = new MissionExecutionEngine(
            new ReplayJailManager(),
            new FixtureSensorLauncher(fixture.Sensor),
            client,
            ledger,
            _ => new ReplayJobSandbox(),
            semanticMemoryIndex: memory,
            dlpSanitizer: dlp,
            credentialSanitizer: credentials,
            revocationManager: null,
            findingsExtractor: extractor,
            qualityIsland: island);

        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteMissionAsync(template, fixture.Parameters, "replay", cancellationToken))
        {
            chunks.Add(chunk);
        }

        return new MissionReplay(fixture, template, chunks, ledger.Actions, client.Calls, island.Result, ledger.Facts());
    }

    // ------------------------------------------------------------------ what one replay produced

    internal sealed record ModelCall(string Model, string SystemPrompt, string UserPrompt);

    internal sealed record MissionReplay(
        MissionFixture Fixture,
        SingleToolTemplate Template,
        IReadOnlyList<MissionChunk> Chunks,
        IReadOnlyList<string> LedgerActions,
        IReadOnlyList<ModelCall> ModelCalls,
        QualityIslandResult? Island,
        MissionRunFacts Facts)
    {
        /// <summary>The analysis the mission published, which the fixture's OutputSha256 is over.</summary>
        public string Analysis => string.Concat(Chunks.Where(c => c.ChunkType == MissionChunkType.AiToken).Select(c => c.Content));

        /// <summary>The bytes the model was handed as its user prompt, null when the mission never got that far.</summary>
        public string? Payload => ModelCalls.Count > 0 ? ModelCalls[0].UserPrompt : null;

        /// <summary>The verdict this replay reached, in the fixture's own terms, for comparison with what was recorded.</summary>
        public FixtureVerdict Observed()
        {
            if (Island is null)
            {
                string why = Chunks.FirstOrDefault(c => c.ChunkType == MissionChunkType.Stderr)?.Content ?? "no reason was reported";
                throw new InvalidOperationException($"the replay never reached the model: {why}");
            }

            var verdict = new JsonFindingsExtractor().ExtractFindings(Island.OutputContent, Payload, Template.Name);
            return FixtureVerdict.From(Island, verdict, LedgerActions);
        }

        /// <summary>
        /// Departures that are not failures: a template or a prompt that moved since the recording. The
        /// model's answer is still real, and the verdict is still held; the note says what the replay
        /// could no longer prove about the prompt.
        /// </summary>
        public IReadOnlyList<string> Notes()
        {
            var notes = new List<string>();
            string templateNow = MissionRunFacts.HashTemplate(Template);
            if (!string.IsNullOrEmpty(Fixture.TemplateSha256) && Fixture.TemplateSha256 != templateNow)
            {
                notes.Add($"the template has changed since this was recorded ({Fixture.TemplateSha256[..Math.Min(19, Fixture.TemplateSha256.Length)]}… then, {templateNow[..19]}… now)");
            }

            if (ModelCalls.Count > 0)
            {
                string promptNow = MissionFixture.Sha256Hex(ModelCalls[0].SystemPrompt);
                if (string.IsNullOrEmpty(Fixture.SystemPromptSha256))
                {
                    notes.Add("the system prompt the model answered was not recorded, so the rebuilt prompt is unchecked");
                }
                else if (Fixture.SystemPromptSha256 != promptNow)
                {
                    notes.Add("the system prompt rebuilt today is not the one the model answered, so the answer is replayed against a prompt it did not see");
                }
            }

            return notes;
        }

        /// <summary>
        /// The one check on the sensor side: the model would be handed the bytes it was handed when this was
        /// recorded. Line endings are normalised because the engine joins stdout and stderr with the host's
        /// newline, and a fixture recorded on Windows replays on Linux too.
        /// </summary>
        public string? PayloadMismatch()
        {
            if (Payload is null)
            {
                return "the model was never called";
            }

            string expected = Fixture.SanitizedPayload().Replace("\r\n", "\n");
            string actual = Payload.Replace("\r\n", "\n");
            if (expected == actual)
            {
                return null;
            }

            int at = 0;
            while (at < expected.Length && at < actual.Length && expected[at] == actual[at]) at++;
            return $"the scrub or the prompt changed the sensor text: first difference at byte {at} of {expected.Length} " +
                   $"(recorded '{Excerpt(expected, at)}', replay '{Excerpt(actual, at)}')";
        }

        private static string Excerpt(string text, int at) =>
            text.Substring(at, Math.Min(48, text.Length - at)).Replace("\n", "\\n");
    }

    // ------------------------------------------------------------------ the stand-ins

    /// <summary>Answers each model call with the next recorded attempt, and records what it was asked.</summary>
    private sealed class ReplayModelClient : IModelStreamClient
    {
        private readonly Queue<FixtureAttempt> _attempts;
        private readonly string _provider;
        private readonly string _modelId;
        public readonly List<ModelCall> Calls = new();

        public ReplayModelClient(MissionFixture fixture)
        {
            _attempts = new Queue<FixtureAttempt>(fixture.Attempts.OrderBy(a => a.Index));
            int slash = fixture.Model.IndexOf('/');
            _provider = slash > 0 ? fixture.Model[..slash] : "recorded";
            _modelId = slash > 0 ? fixture.Model[(slash + 1)..] : fixture.Model;
        }

        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, _provider, _modelId.Length > 0 ? _modelId : requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel, string systemPrompt, string userPrompt,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            lock (Calls) Calls.Add(new ModelCall(requestedModel, systemPrompt, userPrompt));

            FixtureAttempt attempt;
            lock (_attempts)
            {
                if (_attempts.Count == 0)
                {
                    // The island asked for more than the live run needed: an answer the live pipeline
                    // accepted is now rejected and escalated, which is a change in the verdict, not a
                    // missing recording.
                    throw new InvalidOperationException(
                        $"the pipeline asked the model for attempt {Calls.Count - 1}, but the fixture recorded only {Calls.Count - 1}: " +
                        "an answer that was accepted when this was recorded is being escalated now");
                }

                attempt = _attempts.Dequeue();
            }

            await Task.Yield();
            yield return attempt.Response;
        }
    }

    /// <summary>The tool, as it ran: the recorded exit, the recorded output, nothing launched.</summary>
    private sealed class FixtureSensorLauncher : IProcessLauncher
    {
        private readonly FixtureSensor _sensor;

        public FixtureSensorLauncher(FixtureSensor sensor) => _sensor = sensor;

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            Task.FromResult(new ProcessExecutionResult(
                _sensor.ExitCode,
                _sensor.Stdout,
                _sensor.Stderr,
                _sensor.TimedOut,
                JobResourceMetrics.Unavailable,
                AppliedControls: _sensor.AppliedControls.Count > 0 ? _sensor.AppliedControls : null));
    }

    private sealed class CapturingIsland : IIsolatedQualityIsland
    {
        private readonly IIsolatedQualityIsland _inner;

        public CapturingIsland(IIsolatedQualityIsland inner) => _inner = inner;

        public QualityIslandResult? Result { get; private set; }

        public Task<QuadrantEvaluationResult> EvaluateArtifactAsync(
            string candidateContent, string? rawTelemetry, SchemaContractType contractType,
            QualityIslandOptions options, CancellationToken cancellationToken = default) =>
            _inner.EvaluateArtifactAsync(candidateContent, rawTelemetry, contractType, options, cancellationToken);

        public async Task<QualityIslandResult> ExecuteIslandAsync(
            QualityIslandRequest request,
            IProgress<string>? tokenProgress = null,
            IProgress<MissionChunk>? chunkProgress = null,
            CancellationToken cancellationToken = default)
        {
            Result = await _inner.ExecuteIslandAsync(request, tokenProgress, chunkProgress, cancellationToken);
            return Result;
        }
    }

    private sealed class RecordingLedger : IAuditLedger
    {
        private readonly List<(string Action, string Details)> _rows = new();
        private readonly IAuditLedger? _forward;

        public RecordingLedger(IAuditLedger? forward = null) => _forward = forward;

        public IReadOnlyList<string> Actions
        {
            get { lock (_rows) return _rows.Select(r => r.Action).ToList(); }
        }

        public MissionRunFacts Facts()
        {
            lock (_rows)
            {
                var row = _rows.LastOrDefault(r => r.Action == MissionRunFacts.LedgerAction);
                return row.Details is null
                    ? throw new InvalidOperationException("the replay sealed no run facts")
                    : System.Text.Json.JsonSerializer.Deserialize<MissionRunFacts>(row.Details)!;
            }
        }

        public async Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (_rows) _rows.Add((action, details));
            if (_forward is not null)
            {
                await _forward.AppendLogAsync(missionId, templateId, action, details, operatorIdentity, cancellationToken);
            }
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            _forward?.GetAuditLogsAsync(missionId, limit, cancellationToken)
            ?? Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            _forward?.VerifyLedgerIntegrityAsync(cancellationToken) ?? Task.FromResult(true);
    }

    private sealed class ReplayJailManager : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult(Path.Combine("replay", "jail", missionId.ToString("N")));

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) => Task.CompletedTask;

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class ReplayJobSandbox : IJobSandbox
    {
        public string JobName => "replay-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(SafeProcessHandle processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(null, null, null, null, ActiveProcessCount: 0);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }
}
