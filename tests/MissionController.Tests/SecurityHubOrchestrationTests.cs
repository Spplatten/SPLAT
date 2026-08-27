using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Network.Identity;
using Xunit;

namespace MissionController.Tests;

public class SecurityHubOrchestrationTests
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
    public async Task IncidentRevocationManager_RevokeAndQuery_EnforcesBlacklistAndAudits()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"hub_revocation_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);
            var revocationManager = new IncidentRevocationManager(ledger);

            string target = "compromised-token-xyz-12345";
            string type = "TOKEN_FINGERPRINT";
            string reason = "Credential leaked in chat log";
            string operatorId = "SecOps-Officer-99";

            // Trigger revocation
            await revocationManager.RevokeAsync(target, type, reason, operatorId);

            // Assert IsRevoked
            Assert.True(await revocationManager.IsRevokedAsync(target));

            // Assert CheckRevocation details
            var status = await revocationManager.CheckRevocationAsync(target);
            Assert.True(status.IsRevoked);
            Assert.NotNull(status.Entry);
            Assert.Equal(target, status.Entry.Identifier);
            Assert.Equal(type, status.Entry.RevocationType);
            Assert.Equal(reason, status.Entry.Reason);
            Assert.Equal(operatorId, status.Entry.RevokedBy);

            // Assert non-revoked identifier returns false
            Assert.False(await revocationManager.IsRevokedAsync("clean-token-abc"));

            // Assert audit log record was written with tamper-evident chain
            var logs = await ledger.GetAuditLogsAsync();
            var revLog = logs.FirstOrDefault(l => l.Action == "EMERGENCY_REVOCATION");
            Assert.NotNull(revLog);
            Assert.Contains(target, revLog.Details);
            Assert.Contains(reason, revLog.Details);
            Assert.Equal(operatorId, revLog.OperatorIdentity);

            // Assert integrity verification succeeds
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
    public async Task TokenLifecycleManager_ProactiveRenewal_PersistsToVaultAndRenews()
    {
        var vault = new InMemoryCredentialVault();
        var lifecycleManager = new TokenLifecycleManager(vault);

        int refreshCount = 0;
        lifecycleManager.RegisterRefreshHandler("GoogleCloud.OAuthToken", ct =>
        {
            refreshCount++;
            var descriptor = new TokenDescriptor(
                AccessToken: $"ya29.fresh_mocked_token_{refreshCount}",
                TokenType: "Bearer",
                ExpiresAtUtc: DateTimeOffset.UtcNow.AddHours(1));
            return Task.FromResult<TokenDescriptor?>(descriptor);
        });

        // First refresh
        var res = await lifecycleManager.RefreshTokenAsync("GoogleCloud.OAuthToken");
        Assert.True(res.Success);
        Assert.NotNull(res.Token);
        Assert.Equal("ya29.fresh_mocked_token_1", res.Token.AccessToken);

        // Verify stored in vault
        string? stored = await vault.RetrieveSecretStringAsync("GoogleCloud.OAuthToken");
        Assert.Equal("ya29.fresh_mocked_token_1", stored);

        // Subsequent valid retrieval without needing immediate renewal
        string? valid = await lifecycleManager.GetValidAccessTokenAsync("GoogleCloud.OAuthToken", bufferSeconds: 120);
        Assert.Equal("ya29.fresh_mocked_token_1", valid);
        Assert.Equal(1, refreshCount); // Handler not called again because token is valid
    }

    [Fact]
    public async Task MerkleTreeEngine_GeneratesValidProofsAcrossLedger()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"hub_merkle_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);
            var merkleEngine = new MerkleTreeEngine();

            var missionId = Guid.NewGuid();
            await ledger.AppendLogAsync(missionId, "CampusOps", "CHECK_POSTURE", "Initial sweep", "secops@corp.local");
            await ledger.AppendLogAsync(missionId, "CampusOps", "ISOLATE_PORT", "Port 80 blocked", "secops@corp.local");
            await ledger.AppendLogAsync(missionId, "CampusOps", "EMERGENCY_REVOCATION", "Revoked key", "secops@corp.local");

            var entries = await ledger.GetAuditLogsAsync();
            Assert.Equal(3, entries.Count);

            var tree = merkleEngine.BuildTree(entries);
            Assert.NotNull(tree.RootHash);
            Assert.Equal(3, tree.LeafCount);

            // Verify each proof
            foreach (var entry in entries)
            {
                var proof = merkleEngine.GenerateProof(tree, entry.Id);
                Assert.NotNull(proof);
                Assert.True(merkleEngine.VerifyProof(proof));
            }
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
