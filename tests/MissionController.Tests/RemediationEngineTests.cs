using System;
using System.IO;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Windows;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.Remediation;
using Xunit;

namespace MissionController.Tests;

public class RemediationEngineTests
{
    [Fact]
    public async Task ExecuteFixAsync_RunsSafeFix_AndLogsToAuditLedger()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RemediationTest_{Guid.NewGuid():N}.db");
        var context = new SqliteStorageContext(dbPath);
        var auditLedger = new SqliteChainedAuditLedger(context);
        var jailManager = new NtAclJailManager();
        var restrictedTokenProvider = new RestrictedTokenProvider();
        var processLauncher = new SuspendedProcessLauncher(restrictedTokenProvider);

        var engine = new SandboxedRemediationEngine(
            jailManager,
            processLauncher,
            auditLedger,
            name => new Win32JobSandbox(name));

        var action = new RemediationAction(
            "test-fix-echo",
            "net-dns-audit",
            "Test Safe Echo Fix",
            "Outputs test remediation string",
            RemediationRiskLevel.Safe,
            CanRollback: false,
            FixExecutable: "cmd.exe",
            FixArguments: "/c \"echo REMEDIATION_SUCCESSFUL\"");

        var result = await engine.ExecuteFixAsync(action, "Operator_SecOpsTier2");

        Assert.True(result.Success);
        Assert.Contains("REMEDIATION_SUCCESSFUL", result.Output);
        Assert.False(result.IsRollback);

        var logs = await auditLedger.GetAuditLogsAsync();
        Assert.Contains(logs, l => l.Action == "REMEDIATION_FIX_COMPLETED");
        Assert.True(await auditLedger.VerifyLedgerIntegrityAsync());

        if (File.Exists(dbPath)) File.Delete(dbPath);
    }

    [Fact]
    public async Task ExecuteRollbackAsync_RollsBackAction_WhenConfigured()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RollbackTest_{Guid.NewGuid():N}.db");
        var context = new SqliteStorageContext(dbPath);
        var auditLedger = new SqliteChainedAuditLedger(context);
        var jailManager = new NtAclJailManager();
        var restrictedTokenProvider = new RestrictedTokenProvider();
        var processLauncher = new SuspendedProcessLauncher(restrictedTokenProvider);

        var engine = new SandboxedRemediationEngine(
            jailManager,
            processLauncher,
            auditLedger,
            name => new Win32JobSandbox(name));

        var action = new RemediationAction(
            "test-rollback-action",
            "secops-registry-persistence",
            "Test Rollback Action",
            "Tests undo capability",
            RemediationRiskLevel.Moderate,
            CanRollback: true,
            FixExecutable: "cmd.exe",
            FixArguments: "/c \"echo FIX_APPLIED\"",
            RollbackExecutable: "cmd.exe",
            RollbackArguments: "/c \"echo ROLLBACK_APPLIED\"");

        var fixResult = await engine.ExecuteFixAsync(action, "Operator_Admin");
        Assert.True(fixResult.Success);

        var rollbackResult = await engine.ExecuteRollbackAsync(action, "Operator_Admin");
        Assert.True(rollbackResult.Success);
        Assert.True(rollbackResult.IsRollback);
        Assert.Contains("ROLLBACK_APPLIED", rollbackResult.Output);

        var logs = await auditLedger.GetAuditLogsAsync();
        Assert.Contains(logs, l => l.Action == "REMEDIATION_ROLLBACK_COMPLETED");
        Assert.True(await auditLedger.VerifyLedgerIntegrityAsync());

        if (File.Exists(dbPath)) File.Delete(dbPath);
    }
}
