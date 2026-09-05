using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Guards the OUTBOUND half of structured diagnosis. JsonFindingsExtractor could always read a
/// schema-shaped reply, but until the engine started asking for one, live providers returned prose
/// and the UI silently fell back to regex bullet-scraping. These tests pin the request side so that
/// regression cannot return unnoticed.
/// </summary>
public class StructuredDiagnosisContractTests
{
    // ---------------------------------------------------------------- fakes

    private sealed class FakeJailManager : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult($@"C:\fake\jail\{missionId:N}");

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) =>
            Task.CompletedTask;

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class HappyProcessLauncher : IProcessLauncher
    {
        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            Task.FromResult(new ProcessExecutionResult(
                0, "Reply from 10.0.0.1: time=12ms", "", false, new JobResourceMetrics(1, 10, 10, 1024, 2048)));
    }

    private sealed class FakeJobSandbox : IJobSandbox
    {
        public string JobName => "fake-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(IntPtr processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(0, 0, 0, 0, 0);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    private sealed class NullAuditLedger : IAuditLedger
    {
        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default) => Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    /// <summary>Captures the exact system prompt that would cross the wire to a provider.</summary>
    private sealed class RecordingModelClient : IModelStreamClient
    {
        public string? CapturedSystemPrompt;

        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, "Fake", requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(string requestedModel, string systemPrompt,
            string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            CapturedSystemPrompt = systemPrompt;
            await Task.Yield();
            yield return "ok";
        }
    }

    /// <summary>
    /// Worst-case sanitizer: destroys everything handed to it. Proves by construction that the
    /// schema is appended AFTER sanitization rather than merely surviving a benign redaction pass.
    /// </summary>
    private sealed class ScorchedEarthSanitizer : ICredentialSanitizer
    {
        public SanitizationResult Sanitize(string input) =>
            new("[ALL REDACTED]", 1, new Dictionary<string, string>());
    }

    private static SingleToolTemplate BuildTemplate() => new(
        "contract-test",
        "Contract Probe",
        "Structured output contract test",
        "Net",
        "gemini-2.0-flash",
        new SingleToolDefinition("tool-c1", "ping", "cmd.exe", "/c ping 127.0.0.1", new[] { 0 }),
        new EgressRule("googleapis.com"),
        "Analyze output",
        new Dictionary<string, string>());

    private static async Task<string> CaptureSystemPromptAsync(ICredentialSanitizer? sanitizer = null)
    {
        var client = new RecordingModelClient();
        var engine = new MissionExecutionEngine(
            new FakeJailManager(), new HappyProcessLauncher(), client, new NullAuditLedger(),
            _ => new FakeJobSandbox(), credentialSanitizer: sanitizer);

        await foreach (var _ in engine.ExecuteMissionAsync(BuildTemplate(), new Dictionary<string, string>(), "op"))
        {
        }

        Assert.NotNull(client.CapturedSystemPrompt);
        return client.CapturedSystemPrompt!;
    }

    // ---------------------------------------------------------------- guarantees

    [Fact]
    public async Task Engine_AppendsStructuredSchemaContract_ToOutboundSystemPrompt()
    {
        string prompt = await CaptureSystemPromptAsync();

        Assert.Contains("[REQUIRED RESPONSE FORMAT]", prompt);
        // The four keys the extractor actually reads - drift here silently breaks parsing.
        Assert.Contains("\"status\"", prompt);
        Assert.Contains("\"headline\"", prompt);
        Assert.Contains("\"findings\"", prompt);
        Assert.Contains("\"recommendedActions\"", prompt);
        // The template's own instructions must survive alongside the contract, not be replaced.
        Assert.Contains("Analyze output", prompt);
    }

    [Fact]
    public async Task SchemaContract_SurvivesCredentialSanitization()
    {
        string prompt = await CaptureSystemPromptAsync(new ScorchedEarthSanitizer());

        Assert.Contains("[ALL REDACTED]", prompt);
        Assert.Contains("[REQUIRED RESPONSE FORMAT]", prompt);
        Assert.Contains("\"recommendedActions\"", prompt);
    }

    [Fact]
    public void ContractShapedResponse_RoundTripsThroughExtractor()
    {
        // Exactly the shape the contract asks for: operator prose, then one fenced JSON block.
        string modelReply = """
            Drive C: is close to exhaustion. Only 4.2 GB remains of a 250 GB volume, which is below
            the 10% safety threshold and will begin to block Windows updates shortly.

            ```json
            {
              "status": "Critical",
              "headline": "Drive C: has 1.7% free space remaining",
              "findings": [
                "Volume C: reports 4.2 GB free of 250 GB total (1.7% remaining)",
                "Windows Update cache in SoftwareDistribution holds 11 GB of superseded packages"
              ],
              "recommendedActions": [
                "Clear the SoftwareDistribution download cache",
                "Run cleanmgr.exe against drive C:"
              ]
            }
            ```
            """;

        var result = new JsonFindingsExtractor().ExtractFindings(
            modelReply, rawToolOutput: "C: 4.2 GB 250 GB", templateName: "Titan-SysOps");

        Assert.Equal(DiagnosticHealthStatus.Critical, result.OverallStatus);
        // Contains, not Equal: TelemetryGrounder may prefix the headline with an UNVERIFIED marker
        // when no finding is anchored in the captured telemetry. This fixture uses deliberately
        // minimal stdout, so the marker is correct behaviour - what this test pins is that the
        // model's own headline survives the round trip, not how grounding decorates it.
        Assert.Contains("Drive C: has 1.7% free space remaining", result.StatusHeadline);
        Assert.Equal(2, result.KeyFindings.Count);
        Assert.Contains(result.KeyFindings, f => f.Contains("4.2 GB free of 250 GB"));
        Assert.Equal(2, result.RecommendedActions!.Count);
        Assert.Contains("cleanmgr.exe", result.RecommendedActions![1]);
    }
}
