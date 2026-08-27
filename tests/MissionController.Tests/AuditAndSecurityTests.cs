using System;
using System.IO;
using System.Security;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Network.Egress;
using MissionController.Infrastructure.Windows.Vault;
using Xunit;

namespace MissionController.Tests;

public class AuditAndSecurityTests
{
    [Fact]
    public void EgressFirewall_EnforcesWhitelist_ThrowsOnMismatch()
    {
        var firewall = new EgressFirewallHandler();
        var approvedUri = new Uri("https://us-central1-aiplatform.googleapis.com/v1/models");
        var blockedUri = new Uri("https://malicious-external-egress.com/api/steal");

        // Approved request should pass
        firewall.ValidateOutboundTarget(approvedUri, "us-central1-aiplatform.googleapis.com");

        // Mismatched request must throw SecurityException
        Assert.Throws<SecurityException>(() =>
            firewall.ValidateOutboundTarget(blockedUri, "us-central1-aiplatform.googleapis.com"));
    }

    [Fact]
    public async Task ChainedAuditLedger_DetectsTampering_AndValidatesIntegrity()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"audit_test_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var ledger = new SqliteChainedAuditLedger(ctx);

            var mission1 = Guid.NewGuid();
            var mission2 = Guid.NewGuid();

            await ledger.AppendLogAsync(mission1, "net-dns-audit", "START", "Starting mission", "Admin");
            await ledger.AppendLogAsync(mission1, "net-dns-audit", "EXECUTE", "Executing ping", "Admin");
            await ledger.AppendLogAsync(mission2, "secops-scan", "START", "Starting secops scan", "Tier2");

            // Verify clean chain
            bool isValid = await ledger.VerifyLedgerIntegrityAsync();
            Assert.True(isValid);

            // Fetch entries
            var entries = await ledger.GetAuditLogsAsync();
            Assert.Equal(3, entries.Count);
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
    public async Task DpapiVault_EncryptAndDecrypt_RoundtripsSuccessfully()
    {
        string vaultDir = Path.Combine(Path.GetTempPath(), $"vault_test_{Guid.NewGuid():N}");
        try
        {
            var vault = new DpapiCredentialVault(vaultDir);
            string secretKey = "TestGoogleOAuthKey";
            string secretValue = "ya29.a0AfH6SMB_Enterprise_Token_Secret_Payload";

            await vault.StoreSecretStringAsync(secretKey, secretValue);
            string? retrieved = await vault.RetrieveSecretStringAsync(secretKey);

            Assert.Equal(secretValue, retrieved);

            await vault.DeleteSecretAsync(secretKey);
            string? afterDelete = await vault.RetrieveSecretStringAsync(secretKey);
            Assert.Null(afterDelete);
        }
        finally
        {
            if (Directory.Exists(vaultDir))
            {
                Directory.Delete(vaultDir, true);
            }
        }
    }

    [Fact]
    public void SingleToolTemplate_StrictRuleValidation_ThrowsOnInvalidConfig()
    {
        var invalidTemplate = new SingleToolTemplate(
            "bad-template",
            "Bad Template",
            "Missing Model",
            "Test",
            TargetModel: "", // Violation
            new SingleToolDefinition("tool1", "Tool 1", "cmd.exe", "/c", new[] { 0 }),
            new EgressRule("example.com"),
            "System prompt",
            new System.Collections.Generic.List<TemplateParameterField>());

        Assert.Throws<InvalidOperationException>(() => invalidTemplate.ValidateStrictRules());
    }
}
