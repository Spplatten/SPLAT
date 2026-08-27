using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Network.Edr;
using MissionController.Infrastructure.Network.Identity;
using MissionController.Infrastructure.Network.Siem;
using MissionController.UI.ViewModels;
using Xunit;

namespace MissionController.Tests;

public class SecurityHubViewModelTests
{
    private sealed class InMemoryCredentialVault : ICredentialVault
    {
        private readonly Dictionary<string, string> _store = new(StringComparer.Ordinal);

        public Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default)
        {
            _store[key] = Convert.ToBase64String(secretBytes);
            return Task.CompletedTask;
        }

        public Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            if (_store.TryGetValue(key, out var val))
            {
                return Task.FromResult<byte[]?>(Convert.FromBase64String(val));
            }
            return Task.FromResult<byte[]?>(null);
        }

        public Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default)
        {
            _store.TryGetValue(key, out var val);
            return Task.FromResult(val);
        }

        public Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default)
        {
            _store[key] = secretString;
            return Task.CompletedTask;
        }

        public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            _store.Remove(key);
            return Task.CompletedTask;
        }
    }

    private sealed class MockSiemForwarder : ISiemForwarder
    {
        public Task<bool> ForwardAuditLogAsync(AuditLogEntry entry, SiemConfiguration config, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
        public Task<bool> ForwardSyslogAsync(SyslogMessage message, string host, int port, bool useTls, CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private sealed class MockEdrBridge : IEdrIngestionBridge
    {
        public Task<EdrDevicePosture> QueryLocalDevicePostureAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new EdrDevicePosture(true, true, true, "1.0", false, "Healthy", DateTimeOffset.UtcNow));
        public Task<IReadOnlyList<EdrSecurityAlert>> GetRecentThreatDetectionsAsync(int limit = 50, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<EdrSecurityAlert>>(new List<EdrSecurityAlert>());
        public Task IsolateHostAsync(string reason, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task ReleaseHostIsolationAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class MockComplianceArchiveExporter : IComplianceArchiveExporter
    {
        public Task<string> ExportCompliancePackageAsync(ComplianceFramework framework, string outputPath, IReadOnlyList<AuditLogEntry> logs, string operatorIdentity, CancellationToken cancellationToken = default) =>
            Task.FromResult(Path.Combine(Path.GetTempPath(), "compliance_test.zip"));
    }

    [Fact]
    public async Task SecurityAuditViewModel_EmergencyRevocation_BlacklistsAndAppendsAudit()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"vm_revocation_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);
            var merkleEngine = new MerkleTreeEngine();
            var exporter = new MockComplianceArchiveExporter();
            var siem = new MockSiemForwarder();
            var edr = new MockEdrBridge();
            var revocationManager = new IncidentRevocationManager(ledger);
            var vault = new InMemoryCredentialVault();
            var lifecycleManager = new TokenLifecycleManager(vault);

            var vm = new SecurityAuditViewModel(
                ledger,
                merkleEngine,
                exporter,
                siem,
                edr,
                revocationManager,
                lifecycleManager,
                vault);

            // Configure revocation input
            vm.RevocationTarget = "compromised-token-xyz-12345";
            vm.RevocationType = "TOKEN_FINGERPRINT";
            vm.RevocationReason = "Credential leaked in chat log";

            // Trigger emergency circuit breaker
            await vm.TriggerEmergencyRevocationAsync();

            // Assertions
            Assert.Contains("CIRCUIT BREAKER TRIPPED", vm.RevocationActionMessage);
            Assert.Single(vm.ActiveRevocations);
            Assert.Equal("compromised-token-xyz-12345", vm.ActiveRevocations[0].Identifier);
            Assert.Equal("TOKEN_FINGERPRINT", vm.ActiveRevocations[0].RevocationType);

            // Assert backend revocation manager state
            Assert.True(await revocationManager.IsRevokedAsync("compromised-token-xyz-12345"));

            // Assert audit log entry created
            var logs = await ledger.GetAuditLogsAsync();
            var revLog = logs.FirstOrDefault(l => l.Action == "EMERGENCY_REVOCATION");
            Assert.NotNull(revLog);
            Assert.Contains("compromised-token-xyz-12345", revLog.Details);
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
    public async Task SecurityAuditViewModel_ProactiveTokenRefresh_RenewsSuccessfully()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"vm_token_refresh_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);
            var merkleEngine = new MerkleTreeEngine();
            var exporter = new MockComplianceArchiveExporter();
            var siem = new MockSiemForwarder();
            var edr = new MockEdrBridge();
            var revocationManager = new IncidentRevocationManager(ledger);
            var vault = new InMemoryCredentialVault();
            var lifecycleManager = new TokenLifecycleManager(vault);

            // Register refresh handler
            lifecycleManager.RegisterRefreshHandler("GoogleCloud.OAuthToken", ct =>
            {
                var descriptor = new TokenDescriptor(
                    AccessToken: "ya29.fresh_mocked_token_9999",
                    TokenType: "Bearer",
                    ExpiresAtUtc: DateTimeOffset.UtcNow.AddHours(1));
                return Task.FromResult<TokenDescriptor?>(descriptor);
            });

            var vm = new SecurityAuditViewModel(
                ledger,
                merkleEngine,
                exporter,
                siem,
                edr,
                revocationManager,
                lifecycleManager,
                vault);

            // Trigger proactive renew
            await vm.ProactiveRenewTokensAsync();

            Assert.Contains("SUCCESS: Refreshed token expires", vm.TokenRenewalStatusMessage);
            Assert.Contains("ya29.fresh_mo", vm.OAuthTokenTtlStatus);
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
