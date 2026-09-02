using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Windows.JobObjects;

namespace MissionController.Infrastructure.Windows.Copilot;

/// <summary>
/// Native Windows Safety Substrate for Microsoft Copilot, Copilot Studio, and Semantic Kernel.
/// Enforces kernel-level containment, hardware clamps, restricted tokens, and real-time SIEM streaming.
/// </summary>
public sealed class CopilotSafetySubstrate : ICopilotSafetySubstrate
{
    private readonly ICopilotSafetyPolicyEngine _policyEngine;
    private readonly IProcessLauncher _processLauncher;
    private readonly IRestrictedTokenProvider _tokenProvider;
    private readonly IJailManager _jailManager;
    private readonly IAuditLedger _auditLedger;
    private readonly IDataLossPreventionSanitizer? _dlpSanitizer;
    private readonly ILeasedExecutor? _leasedExecutor;
    private readonly SentinelCopilotTelemetryBridge? _sentinelBridge;

    public CopilotSafetySubstrate(
        IProcessLauncher processLauncher,
        IRestrictedTokenProvider tokenProvider,
        IJailManager jailManager,
        IAuditLedger auditLedger,
        ICopilotSafetyPolicyEngine? policyEngine = null,
        IDataLossPreventionSanitizer? dlpSanitizer = null,
        ILeasedExecutor? leasedExecutor = null,
        ISiemForwarder? siemForwarder = null)
    {
        _processLauncher = processLauncher ?? throw new ArgumentNullException(nameof(processLauncher));
        _tokenProvider = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        _jailManager = jailManager ?? throw new ArgumentNullException(nameof(jailManager));
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _policyEngine = policyEngine ?? new CopilotSafetyPolicyEngine();
        _dlpSanitizer = dlpSanitizer;
        _leasedExecutor = leasedExecutor;
        if (siemForwarder != null)
        {
            _sentinelBridge = new SentinelCopilotTelemetryBridge(siemForwarder);
        }
    }

    public async Task<CopilotExecutionResult> ExecuteSafeToolAsync(
        CopilotToolCallContext context,
        CopilotSafetyPolicy? policy = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        policy ??= CopilotSafetyPolicy.CreateEnterpriseDefault();

        // 1. Evaluate Pre-Execution Policy
        var eval = _policyEngine.EvaluatePolicy(context, policy);
        if (!eval.IsPermitted)
        {
            string violationDetails = eval.DenialReason ?? "Blocked by CISO Copilot policy.";

            await _auditLedger.AppendLogAsync(
                context.SessionId,
                $"copilot-tool-{context.ToolName}",
                "COPILOT_POLICY_BLOCKED",
                $"AgentId={context.AgentId} Tool={context.ToolName} Reason='{violationDetails}'",
                context.OperatorIdentity,
                cancellationToken);

            var logs = await _auditLedger.GetAuditLogsAsync(context.SessionId, 1, cancellationToken);
            string? merkleHash = logs.Count > 0 ? logs[^1].EntryHash : null;

            return CopilotExecutionResult.Blocked(violationDetails, eval.Violations, merkleHash);
        }

        // 2. Sanitize arguments if DLP is configured
        string effectiveArgs = context.Arguments;
        if (_dlpSanitizer != null && !string.IsNullOrWhiteSpace(effectiveArgs))
        {
            var dlpResult = _dlpSanitizer.Sanitize(effectiveArgs);
            effectiveArgs = dlpResult.SanitizedContent;
        }

        // 3. Execute according to chosen environment
        if (context.PreferredEnvironment == CopilotExecutionEnvironment.LinuxBpfLsmLease && _leasedExecutor != null)
        {
            return await ExecuteLinuxLeasedToolAsync(context, policy, effectiveArgs, cancellationToken);
        }

        return await ExecuteWindowsJobSandboxedToolAsync(context, policy, effectiveArgs, cancellationToken);
    }

    private async Task<CopilotExecutionResult> ExecuteWindowsJobSandboxedToolAsync(
        CopilotToolCallContext context,
        CopilotSafetyPolicy policy,
        string effectiveArgs,
        CancellationToken cancellationToken)
    {
        string? provisionedJailPath = null;
        string effectiveWorkDir = context.WorkingDirectory ?? string.Empty;

        // If no explicit working directory was supplied or isolated jail required, provision ephemeral NT ACL jail
        if (string.IsNullOrWhiteSpace(effectiveWorkDir) || !Directory.Exists(effectiveWorkDir))
        {
            provisionedJailPath = await _jailManager.ProvisionJailAsync(context.SessionId, cancellationToken);
            effectiveWorkDir = provisionedJailPath;
        }

        using var jobSandbox = new Win32JobSandbox($"Copilot_{context.SessionId:N}");
        if (policy.EnforceJobObjectResourceLimits)
        {
            jobSandbox.ConfigureExtendedLimits(policy.MaxMemoryBytes, policy.MaxCpuPercent);
        }

        try
        {
            var procResult = await _processLauncher.LaunchSuspendedInJobAsync(
                executable: context.ExecutableOrCommand,
                arguments: effectiveArgs,
                workingDirectory: effectiveWorkDir,
                jobSandbox: jobSandbox,
                dropAdminPrivileges: policy.EnforceRestrictedToken,
                timeoutSeconds: policy.TimeoutSeconds,
                cancellationToken: cancellationToken);

            bool isSuccess = procResult.ExitCode == 0 && !procResult.TimedOut;

            await _auditLedger.AppendLogAsync(
                context.SessionId,
                $"copilot-tool-{context.ToolName}",
                isSuccess ? "COPILOT_TOOL_SUCCESS" : "COPILOT_TOOL_FAILED",
                $"AgentId={context.AgentId} Exec='{context.ExecutableOrCommand}' ExitCode={procResult.ExitCode} TimedOut={procResult.TimedOut} " +
                $"KernelMs={JobResourceMetrics.Describe(procResult.FinalMetrics.TotalCpuKernelTimeMs, string.Empty)} " +
                $"UserMs={JobResourceMetrics.Describe(procResult.FinalMetrics.TotalCpuUserTimeMs, string.Empty)}",
                context.OperatorIdentity,
                cancellationToken);

            var logs = await _auditLedger.GetAuditLogsAsync(context.SessionId, 1, cancellationToken);
            string? merkleHash = logs.Count > 0 ? logs[^1].EntryHash : null;

            return new CopilotExecutionResult(
                IsSuccess: isSuccess,
                PolicyBlocked: false,
                ExitCode: procResult.ExitCode,
                StandardOutput: procResult.StandardOutput,
                StandardError: procResult.StandardError,
                TimedOut: procResult.TimedOut,
                ResourceMetrics: procResult.FinalMetrics,
                Violations: Array.Empty<CopilotSecurityViolation>(),
                MerkleEntryHash: merkleHash,
                TimestampUtc: DateTime.UtcNow);
        }
        finally
        {
            if (provisionedJailPath != null)
            {
                await _jailManager.DrainAndCleanupJailAsync(provisionedJailPath);
            }
        }
    }

    private async Task<CopilotExecutionResult> ExecuteLinuxLeasedToolAsync(
        CopilotToolCallContext context,
        CopilotSafetyPolicy policy,
        string effectiveArgs,
        CancellationToken cancellationToken)
    {
        if (_leasedExecutor == null)
        {
            throw new InvalidOperationException("Linux BPF-LSM leased executor is not configured on this host.");
        }

        var lease = new LeaseSpec(
            MissionId: context.SessionId,
            WorkingDirectory: context.WorkingDirectory ?? "/tmp",
            AllowNetwork: policy.AllowNetworkEgress,
            AllowedEgressIps: policy.AllowedEgressIps ?? new List<string> { "127.0.0.1" },
            AllowedEgressPorts: policy.AllowedEgressPorts ?? new List<uint> { 80, 443 },
            ReadOnlyFs: false,
            ProtectedInodes: new List<InodeIdentifierModel>
            {
                new(1, 0, "/etc/shadow"),
                new(2, 0, "/etc/sudoers")
            },
            AllowedExecInodes: new List<InodeIdentifierModel>(),
            LeaseDurationSeconds: (uint)policy.TimeoutSeconds,
            Limits: new LeaseResourceLimits(
                MaxMemoryBytes: (ulong)policy.MaxMemoryBytes,
                MaxCpuPercent: (uint)policy.MaxCpuPercent,
                MaxPids: 100));

        var kernelViolations = new List<CopilotSecurityViolation>();
        var violationProgress = new Progress<LeaseViolationEvent>(v =>
        {
            kernelViolations.Add(new CopilotSecurityViolation(
                ViolationType: $"KERNEL_BPF_LSM_{v.Hook.ToString().ToUpperInvariant()}",
                Description: v.DetailText,
                Severity: CopilotSecuritySeverity.Critical,
                OffendingValue: $"PID={v.ProcessId} Comm={v.ProcessComm}",
                TimestampUtc: v.TimestampUtc));
        });

        var execResult = await _leasedExecutor.ExecuteLeasedAsync(
            lease: lease,
            command: context.ExecutableOrCommand,
            arguments: effectiveArgs,
            violations: violationProgress,
            ct: cancellationToken);

        bool isSuccess = execResult.ExitCode == 0 && !execResult.TimedOut && kernelViolations.Count == 0;

        await _auditLedger.AppendLogAsync(
            context.SessionId,
            $"copilot-tool-{context.ToolName}",
            isSuccess ? "COPILOT_TOOL_SUCCESS" : "COPILOT_TOOL_FAILED",
            $"AgentId={context.AgentId} Command='{context.ExecutableOrCommand}' ExitCode={execResult.ExitCode} Violations={kernelViolations.Count}",
            context.OperatorIdentity,
            cancellationToken);

        var logs = await _auditLedger.GetAuditLogsAsync(context.SessionId, 1, cancellationToken);
        string? merkleHash = logs.Count > 0 ? logs[^1].EntryHash : null;

        return new CopilotExecutionResult(
            IsSuccess: isSuccess,
            PolicyBlocked: kernelViolations.Count > 0,
            ExitCode: execResult.ExitCode,
            StandardOutput: execResult.StandardOutput,
            StandardError: execResult.StandardError,
            TimedOut: execResult.TimedOut,
            ResourceMetrics: execResult.FinalMetrics,
            Violations: kernelViolations,
            MerkleEntryHash: merkleHash,
            TimestampUtc: DateTime.UtcNow);
    }

    public async Task<bool> StreamAlertToSentinelAsync(
        CopilotToolCallContext context,
        CopilotExecutionResult result,
        SiemConfiguration sentinelConfig,
        CancellationToken cancellationToken = default)
    {
        if (_sentinelBridge == null)
        {
            return false;
        }

        return await _sentinelBridge.StreamCopilotEventAsync(context, result, sentinelConfig, cancellationToken);
    }
}
