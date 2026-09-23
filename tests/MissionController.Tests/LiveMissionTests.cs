using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Network.Ai;
using MissionController.Infrastructure.Network.Dlp;
using MissionController.Infrastructure.Network.Http;
using MissionController.Infrastructure.Network.Identity;
using MissionController.Infrastructure.Windows.Vault;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using MissionController.Core.Replay;
using Xunit;
using Xunit.Abstractions;

namespace MissionController.Tests;

/// <summary>
/// The one thing the rest of the suite cannot do: run a mission against the real model, over the
/// real network, and hold the resulting bundle to the same standard a stranger would.
///
/// It needs a key, so it is inert without one, and it looks for that key exactly where the app does:
/// the DPAPI vault the Settings screen writes to, then <c>ANTHROPIC_API_KEY</c>. Reading the vault
/// is the point - it means a live run needs no secret on a command line, in a script, or in a
/// terminal history, and it exercises the same path a user's own key takes.
///
///     # either: paste the key into SPLAT's Settings screen once, then
///     dotnet test --filter FullyQualifiedName~LiveMissionTests
///     # or, without the app:
///     $env:ANTHROPIC_API_KEY = "..."
///
/// Every assertion below is on the live path; a run that only proved the skip would be worse than
/// no test, so the skip is reported out loud rather than passing quietly.
/// </summary>
public sealed class LiveMissionTests
{
    private readonly ITestOutputHelper _out;

    public LiveMissionTests(ITestOutputHelper output) => _out = output;

    private static readonly DpapiCredentialVault Vault = new();

    /// <summary>Whether a key is reachable at all - never the key itself, which is not read here.</summary>
    private static async Task<bool> HaveKeyAsync()
        => !string.IsNullOrWhiteSpace(await Vault.RetrieveSecretStringAsync(ClaudeStreamClient.ApiKeyVaultKey))
           || !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY"));

    private static ClaudeStreamClient NewClient()
    {
        var (http, firewall) = HardenedHttpClientFactory.CreateHardenedClient();
        return new ClaudeStreamClient(http, firewall, Vault);
    }

    [Fact]
    public async Task TheKeyReachesTheModel_AndTheFirstBytesArriveInsideTheStallWindow()
    {
        if (!await HaveKeyAsync()) { _out.WriteLine("SKIPPED: no Anthropic key in the vault or the environment."); return; }

        var client = NewClient();
        var availability = await client.CheckAvailabilityAsync("claude-sonnet-5");
        Assert.True(availability.IsLive, availability.UnavailableReason);

        // The roadmap's open question: Sonnet 5 thinks adaptively when `thinking` is omitted, and
        // the client cancels any read that sees no bytes for 30 seconds. Whether a thinking model
        // sends anything inside that window before its first text had never been observed.
        var clock = Stopwatch.StartNew();
        TimeSpan firstByte = TimeSpan.Zero;
        var text = new System.Text.StringBuilder();

        await foreach (string chunk in client.StreamAnalysisAsync(
            "claude-sonnet-5",
            "You are a network engineer. Answer in one short sentence.",
            "Reason carefully about why a gateway ping of 2 packets might show 25% loss, then answer."))
        {
            if (firstByte == TimeSpan.Zero) firstByte = clock.Elapsed;
            text.Append(chunk);
        }

        string answer = text.ToString();
        _out.WriteLine($"first byte after {firstByte.TotalSeconds:F1}s, {answer.Length} chars in {clock.Elapsed.TotalSeconds:F1}s");
        _out.WriteLine(answer.Length > 400 ? answer[..400] + "…" : answer);

        Assert.DoesNotContain("MODEL REQUEST FAILED", answer);
        Assert.DoesNotContain("MODEL STREAM TIMEOUT", answer);
        Assert.True(firstByte < TimeSpan.FromSeconds(30), $"first byte took {firstByte.TotalSeconds:F1}s");
        Assert.NotEqual(0, answer.Trim().Length);
    }

    [Fact]
    public async Task AWholeMission_RunsLive_AndItsSignedBundleVerifiesFromTheBundleAlone()
    {
        if (!await HaveKeyAsync()) { _out.WriteLine("SKIPPED: no Anthropic key in the vault or the environment."); return; }

        string dir = Path.Combine(Path.GetTempPath(), "splat-live-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string dbPath = Path.Combine(dir, "ledger.db");

        try
        {
            var context = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(context);
            var merkle = new MerkleTreeEngine();

            string keyPath = Path.Combine(dir, "signing.pem");
            File.WriteAllText(keyPath, RunRecordKeyFile.NewKeyPem(out string keyId));
            var signer = RunRecordKeyFile.Load(keyPath);

            var engine = new MissionExecutionEngine(
                new NtAclJailManager(),
                new SuspendedProcessLauncher(new RestrictedTokenProvider()),
                NewClient(),
                ledger,
                name => new Win32JobSandbox(name),
                semanticMemoryIndex: null,
                dlpSanitizer: new RegexDataLossPreventionSanitizer(),
                credentialSanitizer: new PromptCredentialSanitizer(),
                revocationManager: new IncidentRevocationManager(ledger));

            // A real catalog template, with its real tool, against the loopback gateway.
            var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "net-dns-audit");

            var chunks = new List<MissionChunk>();
            await foreach (var chunk in engine.ExecuteMissionAsync(
                template,
                new Dictionary<string, string> { { "TargetHost", "127.0.0.1" } },
                "live-test-operator"))
            {
                chunks.Add(chunk);
            }

            Guid missionId = chunks[0].MissionId;
            string analysis = string.Concat(chunks.Where(c => c.ChunkType == MissionChunkType.AiToken).Select(c => c.Content));
            _out.WriteLine($"mission {missionId}: {chunks.Count} chunks, {analysis.Length} chars of analysis");
            _out.WriteLine(analysis.Length > 600 ? analysis[..600] + "…" : analysis);

            // The model is asserted at the END of this test, not here: everything below runs on the
            // mission's own evidence, so a provider outage still leaves that proven rather than
            // costing the whole live run.

            // The record is built from what the mission sealed, and nothing else.
            var assembler = new MissionRunRecordAssembler(ledger, merkle, new ComplianceArchiveExporter(merkle, signer));
            var record = await assembler.AssembleRunRecordAsync(missionId);

            _out.WriteLine($"permission: {record.EffectivePermission.CommandLine}");
            _out.WriteLine($"egress:     {record.EffectivePermission.EgressEnforcement}");
            _out.WriteLine($"enforced:   {string.Join(" | ", record.EnforcementState.AttachedControls ?? new List<string>())}");
            _out.WriteLine($"limits:     {JsonSerializer.Serialize(record.EnforcementState.EffectiveLimitsReadback)}");
            _out.WriteLine($"outcome:    exit {record.Outcome.ExitCode}, contract met {record.Outcome.ExitContractMet}");
            _out.WriteLine($"cleanup:    {string.Join(" -> ", record.Cleanup.TeardownOrder ?? new List<string>())}; left running {record.Cleanup.ProcessesLeftAtTeardown}");

            Assert.Equal(missionId, record.RequestIdentity.MissionId);
            Assert.Contains("127.0.0.1", record.EffectivePermission.CommandLine);
            // Read back from the kernel, not repeated from the request.
            Assert.Contains(record.EnforcementState.AttachedControls!, c => c.StartsWith("job:", StringComparison.Ordinal));
            Assert.Contains(record.EnforcementState.AttachedControls!, c => c.StartsWith("token:integrity=", StringComparison.Ordinal));
            Assert.NotNull(record.EnforcementState.EffectiveLimitsReadback);
            Assert.Equal(template.Tool.MaxMemoryBytes, record.EnforcementState.EffectiveLimitsReadback!.ProcessMemoryLimitBytes);
            Assert.True(record.Outcome.ExitContractMet);
            Assert.Equal(0u, record.Cleanup.ProcessesLeftAtTeardown);

            // And a stranger with the zip and nothing else can check it.
            string zipPath = await assembler.AssembleAndExportBundleAsync(missionId, dir);
            string bundle = Path.Combine(dir, "bundle");
            ZipFile.ExtractToDirectory(zipPath, bundle);

            var signature = JsonSerializer.Deserialize<Dictionary<string, string>>(
                File.ReadAllText(Path.Combine(bundle, "signature.json")))!;
            Assert.Equal(keyId, signature["KeyId"]);

            var python = Process.Start(new ProcessStartInfo("python", "verify_proofs.py")
            {
                WorkingDirectory = bundle,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            })!;
            string verifierOutput = python.StandardOutput.ReadToEnd() + python.StandardError.ReadToEnd();
            python.WaitForExit();
            _out.WriteLine("--- verify_proofs.py ---");
            _out.WriteLine(verifierOutput);

            Assert.True(python.ExitCode == 0, $"the verifier refused a bundle this run produced: {verifierOutput}");

            // Last, because it is the only part that depends on the provider being reachable.
            Assert.DoesNotContain("MODEL REQUEST FAILED", analysis);
            Assert.NotEqual(0, analysis.Trim().Length);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            try { Directory.Delete(dir, recursive: true); } catch { /* the pool may still hold the db */ }
        }
    }

    /// <summary>The template the canary runs unless <c>SPLAT_CANARY_TEMPLATE</c> names another: the largest sensor in the catalog.</summary>
    public const string DefaultCanaryTemplate = "secops-ir-triage-snapshot";

    /// <summary>
    /// The canary: one live mission on a large template, and the proof that recording it loses nothing.
    ///
    /// The replay suite runs real answers with no model, so it is only as good as the recording. This
    /// runs the biggest sensor in the catalog - tens of kilobytes of connections, processes, signatures,
    /// accounts, tasks and DNS cache - through the real model, records the fixture the engine's own
    /// recorder writes, replays it offline through the same harness the suite uses, and holds the
    /// replay to the live verdict and the live ledger. A change in the scrub, the prompt, the island or
    /// the grounder that the fixture format cannot carry would show up here, on a real answer, before
    /// it hid in a fixture that replays to the wrong thing.
    ///
    /// The fixture is left in <c>SPLAT_RECORD_MISSIONS_DIR</c> when that is set, ready to be reviewed and
    /// promoted; otherwise in a temporary directory that is removed with the run.
    /// </summary>
    [Fact]
    public async Task TheCanary_ALargeTemplateRunsLive_AndItsRecordingReplaysToTheSameVerdict()
    {
        if (!await HaveKeyAsync()) { _out.WriteLine("SKIPPED: no Anthropic key in the vault or the environment."); return; }

        string templateId = Environment.GetEnvironmentVariable("SPLAT_CANARY_TEMPLATE") is { Length: > 0 } chosen
            ? chosen.Trim()
            : DefaultCanaryTemplate;
        var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == templateId);

        string dir = Path.Combine(Path.GetTempPath(), "splat-canary-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        string recordTo = Environment.GetEnvironmentVariable(MissionFixtureDirectoryRecorder.EnvironmentVariable) is { Length: > 0 } named
            ? named
            : dir;

        try
        {
            var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(Path.Combine(dir, "ledger.db")));
            var recorder = new MissionFixtureDirectoryRecorder(recordTo, "LiveMissionTests canary");

            var engine = new MissionExecutionEngine(
                new NtAclJailManager(),
                new SuspendedProcessLauncher(new RestrictedTokenProvider()),
                NewClient(),
                ledger,
                name => new Win32JobSandbox(name),
                semanticMemoryIndex: null,
                dlpSanitizer: new RegexDataLossPreventionSanitizer(),
                credentialSanitizer: new PromptCredentialSanitizer(),
                revocationManager: null,
                findingsExtractor: new JsonFindingsExtractor(),
                recorder: recorder);

            var clock = Stopwatch.StartNew();
            var chunks = new List<MissionChunk>();
            await foreach (var chunk in engine.ExecuteMissionAsync(template, new Dictionary<string, string>(), "live-test-operator"))
            {
                chunks.Add(chunk);
            }

            Guid missionId = chunks[0].MissionId;
            string telemetry = string.Concat(chunks.Where(c => c.ChunkType == MissionChunkType.Stdout).Select(c => c.Content));
            string analysis = string.Concat(chunks.Where(c => c.ChunkType == MissionChunkType.AiToken).Select(c => c.Content));
            _out.WriteLine($"mission {missionId} on {templateId}: {telemetry.Length:N0} chars of telemetry, {analysis.Length:N0} chars of analysis, {clock.Elapsed.TotalSeconds:F1}s");
            foreach (var warning in chunks.Where(c => c.ChunkType is MissionChunkType.SystemWarning or MissionChunkType.Stderr))
            {
                _out.WriteLine($"  {warning.ChunkType}: {(warning.Content.Length > 300 ? warning.Content[..300] + "…" : warning.Content)}");
            }

            // The sensor is the point of a large template: a canary whose tool printed nothing has
            // measured nothing about the scrub, the prompt or the grounder.
            Assert.True(telemetry.Length > 0, "the sensor produced no output, so nothing downstream was exercised");
            Assert.True(chunks.Any(c => c.ChunkType is MissionChunkType.Completed) || analysis.Length > 0,
                "the mission ended before any analysis: " + (chunks.LastOrDefault(c => c.ChunkType == MissionChunkType.Stderr)?.Content ?? "no reason reported"));
            Assert.DoesNotContain("MODEL REQUEST FAILED", analysis);
            Assert.DoesNotContain("MODEL STREAM TIMEOUT", analysis);

            // The engine wrote the fixture as part of the mission, or said why not.
            Assert.True(recorder.LastWrittenPath is not null && File.Exists(recorder.LastWrittenPath),
                "the engine recorded no fixture: " + (chunks.FirstOrDefault(c => c.ChunkType == MissionChunkType.SystemWarning)?.Content ?? "and gave no reason"));
            var fixture = MissionFixture.Load(recorder.LastWrittenPath!);
            _out.WriteLine($"recorded {Path.GetFileName(recorder.LastWrittenPath)}: {fixture.Attempts.Count} attempt(s), verdict {fixture.Expected.Status}, accepted {fixture.Expected.Accepted}, " +
                           $"{fixture.Expected.Grounded} grounded / {fixture.Expected.PartiallyGrounded} partial / {fixture.Expected.Unsupported} unsupported / {fixture.Expected.Unattributed} unattributed");

            Assert.Equal(missionId, fixture.MissionId);
            Assert.Equal(telemetry.Replace("\r\n", "\n"), fixture.Sensor.Stdout.Replace("\r\n", "\n"));
            Assert.NotEmpty(fixture.Attempts);
            Assert.Equal(MissionFixture.Sha256Hex(analysis), fixture.Expected.OutputSha256);

            // The same mission, offline, through the suite's harness: the model is the recording, the
            // sandbox is a stand-in, and every verdict-bearing piece in between is the real code.
            var replay = await MissionReplayHarness.ReplayAsync(fixture);
            var observed = replay.Observed();
            Assert.Null(replay.PayloadMismatch());

            var differences = fixture.Expected.DifferencesFrom(observed);
            Assert.True(differences.Count == 0,
                "the offline replay does not reach the live verdict, so the fixture does not carry what the pipeline needs:" +
                Environment.NewLine + string.Join(Environment.NewLine, differences));

            // And the live ledger's rows are the replay's rows: the mission's audit trail is a function
            // of its inputs, not of the run that happened to write it.
            var liveActions = (await ledger.GetAuditLogsAsync(missionId, 500))
                .OrderBy(entry => entry.Id)
                .Select(entry => entry.Action)
                .ToList();
            Assert.Equal(liveActions, replay.LedgerActions.ToList());

            foreach (string note in replay.Notes())
            {
                _out.WriteLine("note: " + note);
            }

            _out.WriteLine(recordTo == dir
                ? "the fixture was recorded to a temporary directory; set SPLAT_RECORD_MISSIONS_DIR to keep one for review"
                : $"the fixture is at {recorder.LastWrittenPath}, ready to review and promote into tests/MissionController.Tests/Fixtures/Missions");
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
