using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Network.Identity;
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

    [Fact]
    public async Task IncidentRevocationManager_EmergencyRevocation_BlacklistsAndAppendsAudit()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"vm_revocation_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);
            var revocationManager = new IncidentRevocationManager(ledger);

            string target = "compromised-token-xyz-12345";
            string type = "TOKEN_FINGERPRINT";
            string reason = "Credential leaked in chat log";

            await revocationManager.RevokeAsync(target, type, reason, "SecOps_Admin");

            Assert.True(await revocationManager.IsRevokedAsync(target));

            var status = await revocationManager.CheckRevocationAsync(target);
            Assert.True(status.IsRevoked);
            Assert.Equal(target, status.Entry?.Identifier);

            var logs = await ledger.GetAuditLogsAsync();
            var revLog = logs.FirstOrDefault(l => l.Action == "EMERGENCY_REVOCATION");
            Assert.NotNull(revLog);
            Assert.Contains(target, revLog.Details);
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
    public async Task TokenLifecycleManager_ProactiveTokenRefresh_RenewsSuccessfully()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"vm_token_refresh_{Guid.NewGuid():N}.db");
        try
        {
            var vault = new InMemoryCredentialVault();
            var lifecycleManager = new TokenLifecycleManager(vault);

            lifecycleManager.RegisterRefreshHandler("GoogleCloud.OAuthToken", ct =>
            {
                var descriptor = new TokenDescriptor(
                    AccessToken: "ya29.fresh_mocked_token_9999",
                    TokenType: "Bearer",
                    ExpiresAtUtc: DateTimeOffset.UtcNow.AddHours(1));
                return Task.FromResult<TokenDescriptor?>(descriptor);
            });

            var refreshResult = await lifecycleManager.RefreshTokenAsync("GoogleCloud.OAuthToken");

            Assert.True(refreshResult.Success);
            Assert.NotNull(refreshResult.Token);
            Assert.Equal("ya29.fresh_mocked_token_9999", refreshResult.Token.AccessToken);
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
