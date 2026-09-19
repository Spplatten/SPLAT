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
            action,
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
                DateTime.UtcNow,
                Verdict: RemediationVerdict.ExecutionFailed,
                PostconditionMeasurement: "Rollback not supported or no rollback script defined.");
        }

        return await ExecuteSandboxedActionAsync(
            action,
            isRollback: true,
            operatorIdentity,
            cancellationToken);
    }

    private async Task<RemediationExecutionResult> ExecuteSandboxedActionAsync(
        RemediationAction action,
        bool isRollback,
        string operatorIdentity,
        CancellationToken cancellationToken)
    {
        var missionId = Guid.NewGuid();
        string jailPath = string.Empty;
        string executable = isRollback ? action.RollbackExecutable! : action.FixExecutable;
        string arguments = isRollback ? (action.RollbackArguments ?? string.Empty) : action.FixArguments;

        // F20: the verdict is read from a declared postcondition, so a step that declares none is not
        // run. Running it and calling the result "unverified" left the judgement to whoever read the
        // result; refusing makes the declaration the price of running at all.
        if (!(isRollback ? action.HasRollbackPostcondition : action.HasFixPostcondition))
        {
            string reason = $"{(isRollback ? "The rollback" : "The fix")} declares no postcondition to measure its result by, so it was not run.";
            await _auditLedger.AppendLogAsync(
                missionId,
                action.TemplateId,
                isRollback ? "REMEDIATION_ROLLBACK_REFUSED" : "REMEDIATION_FIX_REFUSED",
                $"ActionId: {action.ActionId} | {reason}",
                operatorIdentity,
                cancellationToken);

            return new RemediationExecutionResult(
                action.ActionId,
                false,
                string.Empty,
                reason,
                isRollback,
                DateTime.UtcNow,
                Verdict: RemediationVerdict.Refused,
                PostconditionMeasurement: "Not run: no postcondition declared.");
        }

        try
        {
            // 1. Audit Intention with declared postcondition
            string actionTag = isRollback ? "REMEDIATION_ROLLBACK_INITIATED" : "REMEDIATION_FIX_INITIATED";
            await _auditLedger.AppendLogAsync(
                missionId,
                action.TemplateId,
                actionTag,
                $"ActionId: {action.ActionId} | Executable: {executable} {arguments} | Postcondition: {action.PostconditionDescription ?? "None declared"}",
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

            string output = string.IsNullOrEmpty(execResult.StandardError)
                ? execResult.StandardOutput
                : $"{execResult.StandardOutput}\n[STDERR]: {execResult.StandardError}";

            bool processCompletedCleanly = execResult.ExitCode == 0 && !execResult.TimedOut;
            RemediationVerdict verdict;
            bool success;
            string? failureReason;
            string postconditionMeasurement;

            if (!processCompletedCleanly)
            {
                success = false;
                verdict = RemediationVerdict.ExecutionFailed;
                failureReason = execResult.TimedOut
                    ? "Process exceeded its 45s remediation budget and was terminated; the change may be half-applied."
                    : $"Process failed with exit code {execResult.ExitCode}";
                postconditionMeasurement = "Execution failed; postcondition measurement skipped.";
            }
            else
            {
                // The process exited 0 within budget. Now measure the declared postcondition.
                // An exit code alone does not prove restoration or health (Clinical Audit F20).
                var (valExec, valArgs, valExpected, delegateCheck, desc) = isRollback
                    ? (action.RollbackValidationExecutable, action.RollbackValidationArguments, action.RollbackValidationExpectedOutput, action.RollbackPostconditionCheck, action.PostconditionDescription ?? "Prior state restored")
                    : (action.ValidationExecutable, action.ValidationArguments, action.ValidationExpectedOutput, action.PostconditionCheck, action.PostconditionDescription ?? "Remediation fix applied");

                // The step was refused before launch unless one of these is declared (see above).
                bool measurementPassed = false;
                string measurementDetail = string.Empty;

                if (delegateCheck != null)
                {
                    try
                    {
                        measurementPassed = await delegateCheck(cancellationToken);
                        measurementDetail = measurementPassed
                            ? $"Delegate postcondition verified: {desc}"
                            : $"Delegate postcondition failed: {desc} was not satisfied";
                    }
                    catch (Exception ex)
                    {
                        measurementPassed = false;
                        measurementDetail = $"Delegate postcondition verification threw: {ex.Message}";
                    }
                }
                else
                {
                    var valResult = await _processLauncher.LaunchSuspendedInJobAsync(
                        valExec!,
                        valArgs ?? string.Empty,
                        jailPath,
                        jobSandbox,
                        dropAdminPrivileges: false,
                        timeoutSeconds: 30,
                        cancellationToken: cancellationToken);

                    if (valResult.TimedOut)
                    {
                        measurementPassed = false;
                        measurementDetail = $"Validation probe timed out after 30s: {desc}";
                    }
                    else if (valResult.ExitCode != 0)
                    {
                        measurementPassed = false;
                        string valErr = string.IsNullOrWhiteSpace(valResult.StandardError)
                            ? $"exit code {valResult.ExitCode}"
                            : valResult.StandardError.Trim();
                        measurementDetail = $"Validation probe failed ({valErr}): {desc}";
                    }
                    else if (!string.IsNullOrEmpty(valExpected) && !valResult.StandardOutput.Contains(valExpected))
                    {
                        measurementPassed = false;
                        measurementDetail = $"Validation probe output did not contain expected token '{valExpected}': {desc}";
                    }
                    else
                    {
                        measurementPassed = true;
                        string stdoutTrim = valResult.StandardOutput.Trim();
                        measurementDetail = string.IsNullOrWhiteSpace(stdoutTrim)
                            ? $"Validation probe confirmed postcondition: {desc}"
                            : $"Validation probe confirmed postcondition: {desc} ({stdoutTrim})";
                    }
                }

                if (measurementPassed)
                {
                    success = true;
                    verdict = isRollback ? RemediationVerdict.Restored : RemediationVerdict.VerifiedFix;
                    failureReason = null;
                    postconditionMeasurement = measurementDetail;
                }
                else
                {
                    // Fail-closed: Even though process exited 0, the measured state proved failure.
                    success = false;
                    verdict = RemediationVerdict.PostconditionFailed;
                    failureReason = $"Process exited 0, but measured postcondition failed: {measurementDetail}";
                    postconditionMeasurement = measurementDetail;
                }
            }

            // 5. Audit Result. The action name carries the verdict, so a reader scanning the ledger
            // for what happened does not have to parse the detail string to find out. COMPLETED
            // only ever follows a measured postcondition.
            string completionTag = (isRollback, verdict) switch
            {
                (true, RemediationVerdict.Restored) => "REMEDIATION_ROLLBACK_COMPLETED",
                (true, RemediationVerdict.PostconditionFailed) => "REMEDIATION_ROLLBACK_POSTCONDITION_FAILED",
                (true, RemediationVerdict.ExecutionFailed) => "REMEDIATION_ROLLBACK_FAILED",
                (false, RemediationVerdict.VerifiedFix) => "REMEDIATION_FIX_COMPLETED",
                (false, RemediationVerdict.PostconditionFailed) => "REMEDIATION_FIX_POSTCONDITION_FAILED",
                (false, RemediationVerdict.ExecutionFailed) => "REMEDIATION_FIX_FAILED",
                _ => isRollback ? "REMEDIATION_ROLLBACK_FAILED" : "REMEDIATION_FIX_FAILED"
            };

            await _auditLedger.AppendLogAsync(
                missionId,
                action.TemplateId,
                completionTag,
                $"ActionId: {action.ActionId} | ExitCode: {execResult.ExitCode} | TimedOut: {execResult.TimedOut} | Verdict: {verdict} | Measurement: {postconditionMeasurement} | Success: {success}",
                operatorIdentity,
                cancellationToken);

            return new RemediationExecutionResult(
                action.ActionId,
                success,
                output,
                failureReason,
                isRollback,
                DateTime.UtcNow,
                Verdict: verdict,
                PostconditionMeasurement: postconditionMeasurement);
        }
        catch (Exception ex)
        {
            await _auditLedger.AppendLogAsync(
                missionId,
                action.TemplateId,
                "REMEDIATION_EXECUTION_FAILED",
                $"ActionId: {action.ActionId} | Error: {ex.Message}",
                operatorIdentity,
                cancellationToken);

            return new RemediationExecutionResult(
                action.ActionId,
                false,
                string.Empty,
                ex.Message,
                isRollback,
                DateTime.UtcNow,
                Verdict: RemediationVerdict.ExecutionFailed,
                PostconditionMeasurement: $"Execution exception: {ex.Message}");
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
