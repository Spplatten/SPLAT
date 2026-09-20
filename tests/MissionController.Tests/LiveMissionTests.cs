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
}
