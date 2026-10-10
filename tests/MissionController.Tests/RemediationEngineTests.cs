using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Remediation;
using MissionController.Infrastructure.Windows.Security;
using Xunit;

namespace MissionController.Tests;

public class RemediationEngineTests
{
    [Fact]
    public async Task ExecuteFixAsync_RunsSafeFix_AndLogsToAuditLedger()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RemediationTest_{Guid.NewGuid():N}.db");
        try
        {
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
                FixArguments: "/c \"echo REMEDIATION_SUCCESSFUL\"",
                ValidationExecutable: "cmd.exe",
                ValidationArguments: "/c \"echo STATE_HEALTHY\"",
                ValidationExpectedOutput: "STATE_HEALTHY");

            var result = await engine.ExecuteFixAsync(action, "Operator_SecOpsTier2");

            Assert.True(result.Success);
            Assert.Equal(RemediationVerdict.VerifiedFix, result.Verdict);
            Assert.Contains("REMEDIATION_SUCCESSFUL", result.Output);
            Assert.False(result.IsRollback);

            var logs = await auditLedger.GetAuditLogsAsync();
            Assert.Contains(logs, l => l.Action == "REMEDIATION_FIX_COMPLETED");
            Assert.True(await auditLedger.VerifyLedgerIntegrityAsync());
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
    public async Task ExecuteRollbackAsync_RollsBackAction_WhenConfigured()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RollbackTest_{Guid.NewGuid():N}.db");
        try
        {
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
                RollbackArguments: "/c \"echo ROLLBACK_APPLIED\"",
                ValidationExecutable: "cmd.exe",
                ValidationArguments: "/c \"echo FIXED_STATE\"",
                ValidationExpectedOutput: "FIXED_STATE",
                RollbackValidationExecutable: "cmd.exe",
                RollbackValidationArguments: "/c \"echo PRIOR_STATE\"",
                RollbackValidationExpectedOutput: "PRIOR_STATE");

            var fixResult = await engine.ExecuteFixAsync(action, "Operator_Admin");
            Assert.True(fixResult.Success);

            var rollbackResult = await engine.ExecuteRollbackAsync(action, "Operator_Admin");
            Assert.True(rollbackResult.Success);
            Assert.True(rollbackResult.IsRollback);
            Assert.Equal(RemediationVerdict.Restored, rollbackResult.Verdict);
            Assert.Contains("ROLLBACK_APPLIED", rollbackResult.Output);

            var logs = await auditLedger.GetAuditLogsAsync();
            Assert.Contains(logs, l => l.Action == "REMEDIATION_FIX_COMPLETED");
            Assert.Contains(logs, l => l.Action == "REMEDIATION_ROLLBACK_COMPLETED");
            Assert.True(await auditLedger.VerifyLedgerIntegrityAsync());
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
    public async Task ExecuteFixAsync_WithFailingPostcondition_FailsEvenWhenExitCodeIsZero()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RemediationPostFail_{Guid.NewGuid():N}.db");
        try
        {
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
                "fix-failing-probe",
                "net-dns-audit",
                "Fix With Failing Probe",
                "Remediation exits 0 but measurement proves condition uncured",
                RemediationRiskLevel.Safe,
                CanRollback: false,
                FixExecutable: "cmd.exe",
                FixArguments: "/c \"echo FIX_APPLIED\"",
                ValidationExecutable: "cmd.exe",
                ValidationArguments: "/c \"exit /b 1\"",
                PostconditionDescription: "Verify listening socket bound");

            var result = await engine.ExecuteFixAsync(action, "Operator_SecOps");

            // Exit code 0 is circumstantial: measured postcondition failed, so success MUST be false.
            Assert.False(result.Success);
            Assert.Equal(RemediationVerdict.PostconditionFailed, result.Verdict);
            Assert.False(result.IsVerifiedFix);
            Assert.Contains("measured postcondition failed", result.ErrorMessage);

            var logs = await auditLedger.GetAuditLogsAsync();
            Assert.Contains(logs, l => l.Action == "REMEDIATION_FIX_POSTCONDITION_FAILED");
            Assert.DoesNotContain(logs, l => l.Action == "REMEDIATION_FIX_COMPLETED");
            Assert.True(await auditLedger.VerifyLedgerIntegrityAsync());
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
    public async Task ExecuteRollbackAsync_WithPassingPostcondition_DeclaresRestoredVerdict()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RollbackPass_{Guid.NewGuid():N}.db");
        try
        {
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
                "rollback-verified",
                "identity-auth-posture",
                "Rollback With Verified Probe",
                "Rollback executes and independent probe confirms restored state",
                RemediationRiskLevel.Moderate,
                CanRollback: true,
                FixExecutable: "cmd.exe",
                FixArguments: "/c \"echo FIX_APPLIED\"",
                RollbackExecutable: "cmd.exe",
                RollbackArguments: "/c \"echo ROLLING_BACK\"",
                RollbackValidationExecutable: "cmd.exe",
                RollbackValidationArguments: "/c \"echo STATUS_RESTORED\"",
                RollbackValidationExpectedOutput: "STATUS_RESTORED",
                PostconditionDescription: "Prior configuration restored");

            var result = await engine.ExecuteRollbackAsync(action, "Operator_SecOps");

            Assert.True(result.Success);
            Assert.Equal(RemediationVerdict.Restored, result.Verdict);
            Assert.True(result.IsRestored);
            Assert.Contains("STATUS_RESTORED", result.PostconditionMeasurement);

            var logs = await auditLedger.GetAuditLogsAsync();
            Assert.Contains(logs, l => l.Action == "REMEDIATION_ROLLBACK_COMPLETED");
            Assert.True(await auditLedger.VerifyLedgerIntegrityAsync());
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
    public async Task ExecuteRollbackAsync_WithFailingPostcondition_RefusesRestoredVerdict()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RollbackFail_{Guid.NewGuid():N}.db");
        try
        {
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
                "rollback-fail-probe",
                "identity-auth-posture",
                "Rollback With Failing Expected Output",
                "Rollback exits 0 but probe detects state still broken",
                RemediationRiskLevel.Moderate,
                CanRollback: true,
                FixExecutable: "cmd.exe",
                FixArguments: "/c \"echo FIX_APPLIED\"",
                RollbackExecutable: "cmd.exe",
                RollbackArguments: "/c \"echo ROLLING_BACK\"",
                RollbackValidationExecutable: "cmd.exe",
                RollbackValidationArguments: "/c \"echo STILL_DIRTY\"",
                RollbackValidationExpectedOutput: "CLEAN_BASELINE_RESTORED",
                PostconditionDescription: "Clean baseline restored");

            var result = await engine.ExecuteRollbackAsync(action, "Operator_SecOps");

            Assert.False(result.Success);
            Assert.Equal(RemediationVerdict.PostconditionFailed, result.Verdict);
            Assert.False(result.IsRestored);
            Assert.Contains("measured postcondition failed", result.ErrorMessage);

            var logs = await auditLedger.GetAuditLogsAsync();
            Assert.Contains(logs, l => l.Action == "REMEDIATION_ROLLBACK_POSTCONDITION_FAILED");
            Assert.DoesNotContain(logs, l => l.Action == "REMEDIATION_ROLLBACK_COMPLETED");
            Assert.True(await auditLedger.VerifyLedgerIntegrityAsync());
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
    public async Task ExecuteFixAsync_WithDelegatePostcondition_EvaluatesPredicate()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"DelegatePost_{Guid.NewGuid():N}.db");
        try
        {
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

            bool stateIsClean = false;

            var action = new RemediationAction(
                "fix-delegate-check",
                "sysops-disk-space",
                "Fix With Delegate Predicate",
                "Measures postcondition via programmatic check",
                RemediationRiskLevel.Safe,
                CanRollback: false,
                FixExecutable: "cmd.exe",
                FixArguments: "/c \"echo ATTEMPTING_FIX\"",
                PostconditionCheck: _ => Task.FromResult(stateIsClean),
                PostconditionDescription: "In-memory state flag is clean");

            // 1. Should fail when predicate returns false
            var result1 = await engine.ExecuteFixAsync(action, "Operator_SysOps");
            Assert.False(result1.Success);
            Assert.Equal(RemediationVerdict.PostconditionFailed, result1.Verdict);

            // 2. Flip state and re-execute
            stateIsClean = true;
            var result2 = await engine.ExecuteFixAsync(action, "Operator_SysOps");
            Assert.True(result2.Success);
            Assert.Equal(RemediationVerdict.VerifiedFix, result2.Verdict);
            Assert.True(result2.IsVerifiedFix);
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

    [Theory]
    [InlineData(false, "REMEDIATION_FIX_REFUSED")]
    [InlineData(true, "REMEDIATION_ROLLBACK_REFUSED")]
    public async Task AStepThatDeclaresNoPostcondition_IsRefused_BeforeAnythingRuns(bool rollback, string refusedTag)
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RefusedStep_{Guid.NewGuid():N}.db");
        try
        {
            var auditLedger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath));
            var launcher = new MustNotRunLauncher();
            var engine = new SandboxedRemediationEngine(
                new NtAclJailManager(),
                launcher,
                auditLedger,
                name => new Win32JobSandbox(name));

            // Each step declares its own postcondition, so the other step's probe does not count.
            var action = new RemediationAction(
                "no-probe",
                "secops-auth",
                "A Step Without Its Own Postcondition",
                "Nothing says what success would look like",
                RemediationRiskLevel.Moderate,
                CanRollback: true,
                FixExecutable: "cmd.exe",
                FixArguments: "/c \"echo FIX\"",
                RollbackExecutable: "cmd.exe",
                RollbackArguments: "/c \"echo ROLLBACK\"",
                ValidationExecutable: rollback ? "cmd.exe" : null,
                RollbackValidationExecutable: rollback ? null : "cmd.exe");

            var result = rollback
                ? await engine.ExecuteRollbackAsync(action, "Operator_SecOps")
                : await engine.ExecuteFixAsync(action, "Operator_SecOps");

            Assert.False(result.Success);
            Assert.Equal(RemediationVerdict.Refused, result.Verdict);
            Assert.Equal(0, launcher.Calls);

            var logs = await auditLedger.GetAuditLogsAsync();
            Assert.Contains(logs, l => l.Action == refusedTag);
            Assert.DoesNotContain(logs, l => l.Action.EndsWith("_INITIATED", StringComparison.Ordinal));
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
    public void ATemplateWhoseFixCarriesACodeCheck_StillSavesAsJson()
    {
        // SqliteTemplateRegistry stores a template as exactly this JSON, and the serializer refuses a delegate.
        var template = new SingleToolTemplate(
            "sysops-disk-space",
            "Disk Space",
            "Reports free space",
            "SysOps",
            "claude-sonnet-5",
            new SingleToolDefinition("disk", "Disk", "cmd.exe", "/c dir", new[] { 0 }),
            new EgressRule("localhost"),
            "Report free space.",
            Array.Empty<TemplateParameterField>(),
            AvailableRemediations: new[]
            {
                new RemediationAction(
                    "fix-delegate-check",
                    "sysops-disk-space",
                    "Fix With Delegate Predicate",
                    "Measures its postcondition in code",
                    RemediationRiskLevel.Safe,
                    CanRollback: false,
                    FixExecutable: "cmd.exe",
                    FixArguments: "/c \"echo FIX\"",
                    PostconditionCheck: _ => Task.FromResult(true),
                    PostconditionDescription: "Free space above the floor")
            });

        var loaded = JsonSerializer.Deserialize<SingleToolTemplate>(JsonSerializer.Serialize(template))!;

        var action = Assert.Single(loaded.Remediations);
        Assert.Equal("fix-delegate-check", action.ActionId);
        Assert.Equal("Free space above the floor", action.PostconditionDescription);
        Assert.Null(action.PostconditionCheck);
    }

    [Fact]
    public void EveryFixTheCatalogShips_DeclaresItsPostconditionAsData()
    {
        // As data, not as a check in code: the console reads templates back from the registry, which
        // stores JSON, and a coded check does not survive that trip - the engine would then refuse
        // the very fix the catalog offers.
        var undeclared = GovernedTemplateCatalog.All
            .SelectMany(t => t.Remediations.Select(r => (Template: t.TemplateId, Fix: r)))
            .Where(x => string.IsNullOrWhiteSpace(x.Fix.ValidationExecutable)
                     || (x.Fix.CanRollback && string.IsNullOrWhiteSpace(x.Fix.RollbackValidationExecutable)))
            .Select(x => $"{x.Template}/{x.Fix.ActionId}")
            .ToList();

        Assert.Empty(undeclared);
    }

    [Fact]
    public void ExactlyOneTemplateInTheCatalog_DeclaresARemediation()
    {
        var withRemediations = GovernedTemplateCatalog.All
            .Where(t => t.Remediations.Count > 0)
            .ToList();

        var single = Assert.Single(withRemediations);
        Assert.Equal("sysops-time-sync", single.TemplateId);
        var action = Assert.Single(single.Remediations);
        Assert.Equal("sysops-time-sync-start-w32time", action.ActionId);
        Assert.Equal(RemediationRiskLevel.Safe, action.RiskLevel);
        Assert.True(action.CanRollback);
        Assert.Equal("RUNNING", action.ValidationExpectedOutput);
        Assert.Equal("STOPPED", action.RollbackValidationExpectedOutput);
    }

    [Fact]
    public async Task SysopsTimeSyncRemediation_FailsClosed_WhenPostconditionStrippedOrOutputLacksToken()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"TimeSyncFailClosed_{Guid.NewGuid():N}.db");
        try
        {
            var auditLedger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath));
            var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "sysops-time-sync");
            var originalAction = Assert.Single(template.Remediations);

            // 1. Refusal when postcondition is stripped
            var launcher = new MustNotRunLauncher();
            var engine = new SandboxedRemediationEngine(
                new NtAclJailManager(),
                launcher,
                auditLedger,
                name => new Win32JobSandbox(name));

            var stripped = originalAction with { ValidationExecutable = null, PostconditionCheck = null };
            var refusedResult = await engine.ExecuteFixAsync(stripped, "Operator_SysOps");

            Assert.False(refusedResult.Success);
            Assert.Equal(RemediationVerdict.Refused, refusedResult.Verdict);
            Assert.Equal(0, launcher.Calls);

            // 2. PostconditionFailed when probe stdout lacks the required token
            var stubLauncher = new FakeProbeLauncher(validationStdout: "STATE : 1  STOPPED");
            var engineWithStub = new SandboxedRemediationEngine(
                new NtAclJailManager(),
                stubLauncher,
                auditLedger,
                name => new Win32JobSandbox(name));

            var failedResult = await engineWithStub.ExecuteFixAsync(originalAction, "Operator_SysOps");

            Assert.False(failedResult.Success);
            Assert.Equal(RemediationVerdict.PostconditionFailed, failedResult.Verdict);
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
    public async Task SqliteTemplateRegistry_RoundTrip_PreservesCommandRemediation_WhileDelegateCheckVanishes()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"RegistryRoundTrip_{Guid.NewGuid():N}.db");
        try
        {
            var context = new SqliteStorageContext(dbPath);
            var registry = new SqliteTemplateRegistry(context);

            var templates = await registry.GetAllTemplatesAsync();
            var timeSync = templates.Single(t => t.TemplateId == "sysops-time-sync");
            var action = Assert.Single(timeSync.Remediations);

            Assert.Equal("sysops-time-sync-start-w32time", action.ActionId);
            Assert.True(action.HasFixPostcondition);
            Assert.True(action.HasRollbackPostcondition);
            Assert.Equal("RUNNING", action.ValidationExpectedOutput);
            Assert.Equal("STOPPED", action.RollbackValidationExpectedOutput);

            // Contrast with delegate: register a template whose fix relies solely on a code check
            var delegateAction = new RemediationAction(
                "temp-delegate-check",
                "custom-diagnostic",
                "Delegate Only",
                "Check lives in code",
                RemediationRiskLevel.Safe,
                CanRollback: false,
                FixExecutable: "cmd.exe",
                FixArguments: "/c echo FIX",
                PostconditionCheck: _ => Task.FromResult(true),
                PostconditionDescription: "Delegate predicate");

            var customTemplate = new SingleToolTemplate(
                "custom-diagnostic",
                "Custom Diagnostic",
                "Test delegate postcondition persistence",
                "Custom",
                "claude-haiku-4-5",
                new SingleToolDefinition("dummy", "Dummy", "cmd.exe", "/c echo 1", new[] { 0 }),
                new EgressRule("localhost"),
                "Prompt",
                new Dictionary<string, string>(),
                availableRemediations: new[] { delegateAction });

            await registry.RegisterTemplateAsync(customTemplate);

            var reloaded = (await registry.GetAllTemplatesAsync()).Single(t => t.TemplateId == "custom-diagnostic");
            var reloadedAction = Assert.Single(reloaded.Remediations);

            // The delegate vanished across JSON serialization
            Assert.Null(reloadedAction.PostconditionCheck);
            Assert.False(reloadedAction.HasFixPostcondition);
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

    private sealed class FakeProbeLauncher : IProcessLauncher
    {
        private readonly string _validationStdout;

        public FakeProbeLauncher(string validationStdout)
        {
            _validationStdout = validationStdout;
        }

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable,
            string arguments,
            string workingDirectory,
            IJobSandbox jobSandbox,
            bool dropAdminPrivileges,
            int timeoutSeconds,
            IProgress<string>? stdoutProgress = null,
            IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default,
            bool denyNetworkAccess = false)
        {
            return Task.FromResult(new ProcessExecutionResult(
                ExitCode: 0,
                StandardOutput: _validationStdout,
                StandardError: string.Empty,
                TimedOut: false,
                FinalMetrics: JobResourceMetrics.Unavailable));
        }
    }

    private sealed class MustNotRunLauncher : IProcessLauncher
    {
        public int Calls { get; private set; }

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable,
            string arguments,
            string workingDirectory,
            IJobSandbox jobSandbox,
            bool dropAdminPrivileges,
            int timeoutSeconds,
            IProgress<string>? stdoutProgress = null,
            IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default,
            bool denyNetworkAccess = false)
        {
            Calls++;
            throw new InvalidOperationException("A refused step must not launch anything.");
        }
    }
}
