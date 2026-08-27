using System;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Windows.Remediation;

public sealed class SandboxedRemediationEngine : IRemediationEngine
{
    private readonly IJailManager _jailManager;
    private readonly IProcessLauncher _processLauncher;
    private readonly IAuditLedger _auditLedger;
    private readonly Func<string, IJobSandbox> _jobSandboxFactory;

    public SandboxedRemediationEngine(
        IJailManager jailManager,
        IProcessLauncher processLauncher,
        IAuditLedger auditLedger,
        Func<string, IJobSandbox> jobSandboxFactory)
    {
        _jailManager = jailManager;
        _processLauncher = processLauncher;
        _auditLedger = auditLedger;
        _jobSandboxFactory = jobSandboxFactory;
    }

    public async Task<RemediationExecutionResult> ExecuteFixAsync(
        RemediationAction action,
        string operatorIdentity,
        CancellationToken cancellationToken = default)
    {
        return await ExecuteSandboxedActionAsync(
            action.ActionId,
            action.TemplateId,
            action.FixExecutable,
            action.FixArguments,
            isRollback: false,
            operatorIdentity,
            cancellationToken);
    }

    public async Task<RemediationExecutionResult> ExecuteRollbackAsync(
        RemediationAction action,
        string operatorIdentity,
        CancellationToken cancellationToken = default)
    {
        if (!action.CanRollback || string.IsNullOrWhiteSpace(action.RollbackExecutable))
        {
            return new RemediationExecutionResult(
                action.ActionId,
                false,
                string.Empty,
                "This remediation action does not support rollback or has no rollback script defined.",
                IsRollback: true,
                DateTime.UtcNow);
        }

        return await ExecuteSandboxedActionAsync(
            action.ActionId,
            action.TemplateId,
            action.RollbackExecutable,
            action.RollbackArguments ?? string.Empty,
            isRollback: true,
            operatorIdentity,
            cancellationToken);
    }

    private async Task<RemediationExecutionResult> ExecuteSandboxedActionAsync(
        string actionId,
        string templateId,
        string executable,
        string arguments,
        bool isRollback,
        string operatorIdentity,
        CancellationToken cancellationToken)
    {
        var missionId = Guid.NewGuid();
        string jailPath = string.Empty;

        try
        {
            // 1. Audit Intention
            string actionTag = isRollback ? "REMEDIATION_ROLLBACK_INITIATED" : "REMEDIATION_FIX_INITIATED";
            await _auditLedger.AppendLogAsync(
                missionId,
                templateId,
                actionTag,
                $"ActionId: {actionId} | Executable: {executable} {arguments}",
                operatorIdentity,
                cancellationToken);

            // 2. Provision Isolated Jail
            jailPath = await _jailManager.ProvisionJailAsync(missionId, cancellationToken);

            // 3. Configure Hardware Sandboxed Job Object
            using var jobSandbox = _jobSandboxFactory($"RemediationJob_{missionId:N}");
            jobSandbox.ConfigureExtendedLimits(maxMemoryBytes: 256 * 1024 * 1024, maxCpuPercent: 80);

            // 4. Launch Suspended in Job Sandbox
            var execResult = await _processLauncher.LaunchSuspendedInJobAsync(
                executable,
                arguments,
                jailPath,
                jobSandbox,
                dropAdminPrivileges: false, // Remediation may require standard system repair permissions
                timeoutSeconds: 45,
                cancellationToken: cancellationToken);

            bool success = execResult.ExitCode == 0;
            string output = string.IsNullOrEmpty(execResult.StandardError)
                ? execResult.StandardOutput
                : $"{execResult.StandardOutput}\n[STDERR]: {execResult.StandardError}";

            // 5. Audit Result
            string completionTag = isRollback ? "REMEDIATION_ROLLBACK_COMPLETED" : "REMEDIATION_FIX_COMPLETED";
            await _auditLedger.AppendLogAsync(
                missionId,
                templateId,
                completionTag,
                $"ActionId: {actionId} | ExitCode: {execResult.ExitCode} | Success: {success}",
                operatorIdentity,
                cancellationToken);

            return new RemediationExecutionResult(
                actionId,
                success,
                output,
                success ? null : $"Process failed with exit code {execResult.ExitCode}",
                isRollback,
                DateTime.UtcNow);
        }
        catch (Exception ex)
        {
            await _auditLedger.AppendLogAsync(
                missionId,
                templateId,
                "REMEDIATION_EXECUTION_FAILED",
                $"ActionId: {actionId} | Error: {ex.Message}",
                operatorIdentity,
                cancellationToken);

            return new RemediationExecutionResult(
                actionId,
                false,
                string.Empty,
                ex.Message,
                isRollback,
                DateTime.UtcNow);
        }
        finally
        {
            if (!string.IsNullOrEmpty(jailPath))
            {
                await _jailManager.DrainAndCleanupJailAsync(jailPath);
            }
        }
    }
}
