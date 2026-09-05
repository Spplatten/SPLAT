using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Network.Identity;
using Xunit;

namespace MissionController.Tests;

public class SanitizationAndRevocationTests
{
    private sealed class MockJobSandbox : IJobSandbox
    {
        public string JobName => "MockJob";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(IntPtr processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(1, 0, 0, 1024, 2048);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    private sealed class MockJailManager : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult(Path.GetTempPath());
        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) => Task.CompletedTask;
        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class MockProcessLauncher : IProcessLauncher
    {
        public bool WasLaunched { get; private set; }

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable,
            string arguments,
            string workingDirectory,
            IJobSandbox jobSandbox,
            bool dropAdminPrivileges,
            int timeoutSeconds,
            IProgress<string>? stdoutProgress = null,
            IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false)
        {
            WasLaunched = true;
            return Task.FromResult(new ProcessExecutionResult(0, "Tool stdout with normal data", "", false, new JobResourceMetrics(1, 10, 10, 1024, 2048)));
        }
    }

    private sealed class MockVertexStreamClient : IModelStreamClient
    {
        public Task<ModelAvailability> CheckAvailabilityAsync(
            string requestedModel,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, "MockProvider", requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel,
            string systemPrompt,
            string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return "AI Analysis Complete.";
        }
    }

    [Fact]
    public void PromptCredentialSanitizer_RedactsJwtsAndApiKeys_AndRestoresCorrectly()
    {
        var sanitizer = new PromptCredentialSanitizer();

        string sampleJwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
        string sampleApiKey = "mc_live_secops_super_secret_key_12345678";
        string rawText = $"Execute query with Bearer {sampleJwt} and apiKey={sampleApiKey}";

        var result = sanitizer.Sanitize(rawText);

        Assert.Equal(2, result.RedactedCount);
        Assert.DoesNotContain(sampleJwt, result.SanitizedText);
        Assert.DoesNotContain(sampleApiKey, result.SanitizedText);
        Assert.Contains("[SECRET_REF:sec_", result.SanitizedText);

        // Test restoring
        string restored = sanitizer.RestoreCredentials(result.SanitizedText, result.OpaqueToSecretMap);
        Assert.Contains(sampleJwt, restored);
        Assert.Contains(sampleApiKey, restored);
    }

    [Fact]
    public void PromptCredentialSanitizer_RedactsPemPrivateKeys()
    {
        var sanitizer = new PromptCredentialSanitizer();

        string pemKey = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y1u...\n-----END RSA PRIVATE KEY-----";
        string rawText = $"Here is the server private key:\n{pemKey}\nPlease analyze.";

        var result = sanitizer.Sanitize(rawText);

        Assert.Equal(1, result.RedactedCount);
        Assert.DoesNotContain("BEGIN RSA PRIVATE KEY", result.SanitizedText);
        Assert.Contains("[SECRET_REF:sec_", result.SanitizedText);
    }

    [Fact]
    public async Task IncidentRevocationManager_RecordsRevocationInAuditLedger()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"revocation_test_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);
            var revocationManager = new IncidentRevocationManager(ledger);

            string compromisedOperator = "operator-compromised@corp.com";

            // Verify initially not revoked
            Assert.False(await revocationManager.IsRevokedAsync(compromisedOperator));

            // Trigger revocation
            await revocationManager.RevokeAsync(
                compromisedOperator,
                "OPERATOR_IDENTITY",
                "Compromised credentials detected by SOC",
                "SecOpsLead");

            // Verify now revoked
            Assert.True(await revocationManager.IsRevokedAsync(compromisedOperator));
            var status = await revocationManager.CheckRevocationAsync(compromisedOperator);
            Assert.True(status.IsRevoked);
            Assert.Equal("Compromised credentials detected by SOC", status.Entry?.Reason);

            // Verify tamper-evident audit ledger contains revocation event
            var logs = await ledger.GetAuditLogsAsync();
            var revLog = logs.FirstOrDefault(l => l.Action == "EMERGENCY_REVOCATION");
            Assert.NotNull(revLog);
            Assert.Contains(compromisedOperator, revLog.Details);
            Assert.Equal("SecOpsLead", revLog.OperatorIdentity);

            // Verify integrity of ledger
            Assert.True(await ledger.VerifyLedgerIntegrityAsync());
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task MissionExecutionEngine_HaltsImmediately_WhenOperatorIsRevoked()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"engine_revocation_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);
            var revocationManager = new IncidentRevocationManager(ledger);
            var sanitizer = new PromptCredentialSanitizer();

            var jailManager = new MockJailManager();
            var launcher = new MockProcessLauncher();
            var vertexClient = new MockVertexStreamClient();

            var engine = new MissionExecutionEngine(
                jailManager,
                launcher,
                vertexClient,
                ledger,
                name => new MockJobSandbox(),
                semanticMemoryIndex: null,
                dlpSanitizer: null,
                credentialSanitizer: sanitizer,
                revocationManager: revocationManager);

            string revokedUser = "rogue_operator";
            await revocationManager.RevokeAsync(revokedUser, "OPERATOR", "Unauthorized insider threat", "SecOpsAdmin");

            var template = new SingleToolTemplate(
                "dns-test",
                "DNS Audit",
                "Tests DNS",
                "Net",
                "gemini-2.0-flash",
                new SingleToolDefinition("tool-1", "ping", "cmd.exe", "/c ping 127.0.0.1", new[] { 0 }),
                new EgressRule("googleapis.com"),
                "Analyze output",
                new Dictionary<string, string>());

            var chunks = new List<MissionChunk>();
            await foreach (var chunk in engine.ExecuteMissionAsync(template, new Dictionary<string, string>(), revokedUser))
            {
                chunks.Add(chunk);
            }

            // Assert that process was NEVER launched due to circuit breaker
            Assert.False(launcher.WasLaunched);

            // Assert that security abort chunks were yielded
            Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.Stderr && c.Content.Contains("SECURITY ABORT"));
            Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.StatusChange && c.Content.Contains("Circuit Breaker"));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            GC.Collect();
            GC.WaitForPendingFinalizers();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }
}
