using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Windows.Copilot;

/// <summary>
/// Ready-to-use Microsoft Semantic Kernel Plugin providing kernel-isolated tool execution
/// for Windows 11 Copilot and Copilot Studio agents.
/// </summary>
public sealed class SplatCopilotPlugin
{
    private readonly ICopilotSafetySubstrate _substrate;
    private readonly CopilotSafetyPolicy _policy;
    private readonly string _operatorIdentity;

    public SplatCopilotPlugin(
        ICopilotSafetySubstrate substrate,
        CopilotSafetyPolicy? policy = null,
        string operatorIdentity = "copilot-agent-user")
    {
        _substrate = substrate ?? throw new ArgumentNullException(nameof(substrate));
        _policy = policy ?? CopilotSafetyPolicy.CreateEnterpriseDefault();
        _operatorIdentity = operatorIdentity;
    }

    [Description("Executes an approved CLI command inside a Win32 Job Object sandbox with CPU/Memory limits and low-privilege token.")]
    public async Task<string> ExecuteSandboxedCommandAsync(
        [Description("The executable name (e.g. powershell.exe, python.exe, git.exe)")] string executable,
        [Description("Command line arguments")] string arguments,
        [Description("Optional working directory")] string? workingDirectory = null,
        CancellationToken cancellationToken = default)
    {
        var context = new CopilotToolCallContext(
            SessionId: Guid.NewGuid(),
            AgentId: "copilot-agent",
            ToolName: "ExecuteSandboxedCommand",
            ExecutableOrCommand: executable,
            Arguments: arguments,
            WorkingDirectory: workingDirectory,
            OperatorIdentity: _operatorIdentity);

        var result = await _substrate.ExecuteSafeToolAsync(context, _policy, cancellationToken);

        var responseObj = new
        {
            success = result.IsSuccess,
            exitCode = result.ExitCode,
            stdout = result.StandardOutput,
            stderr = result.StandardError,
            timedOut = result.TimedOut,
            merkleHash = result.MerkleEntryHash,
            resourceMetrics = result.ResourceMetrics != null ? new
            {
                kernelTimeMs = result.ResourceMetrics.TotalCpuKernelTimeMs,
                userTimeMs = result.ResourceMetrics.TotalCpuUserTimeMs,
                peakMemoryBytes = result.ResourceMetrics.PeakMemoryBytes,
                activeProcesses = result.ResourceMetrics.ActiveProcessCount
            } : null,
            violations = result.Violations
        };

        return JsonSerializer.Serialize(responseObj, new JsonSerializerOptions { WriteIndented = true });
    }

    [Description("Executes a PowerShell script block inside an unprivileged sandbox with strict execution policy and resource clamps.")]
    public async Task<string> ExecuteSandboxedPowerShellAsync(
        [Description("The PowerShell script content or command expression")] string script,
        [Description("Optional working directory")] string? workingDirectory = null,
        CancellationToken cancellationToken = default)
    {
        string encodedArgs = $"-NoProfile -NonInteractive -ExecutionPolicy Restricted -Command \"{script.Replace("\"", "\\\"")}\"";
        return await ExecuteSandboxedCommandAsync("powershell.exe", encodedArgs, workingDirectory, cancellationToken);
    }

    [Description("Safely reads a file with automatic CISO path-traversal and credential directory protection.")]
    public async Task<string> ReadSandboxedFileAsync(
        [Description("Absolute or relative file path to read")] string filePath,
        CancellationToken cancellationToken = default)
    {
        // First check policy
        var context = new CopilotToolCallContext(
            SessionId: Guid.NewGuid(),
            AgentId: "copilot-agent",
            ToolName: "ReadSandboxedFile",
            ExecutableOrCommand: "fs_read",
            Arguments: filePath,
            WorkingDirectory: null,
            OperatorIdentity: _operatorIdentity);

        var result = await _substrate.ExecuteSafeToolAsync(context, _policy, cancellationToken);
        if (result.PolicyBlocked)
        {
            return JsonSerializer.Serialize(new
            {
                success = false,
                error = result.StandardError,
                merkleHash = result.MerkleEntryHash
            });
        }

        if (!File.Exists(filePath))
        {
            return JsonSerializer.Serialize(new { success = false, error = $"File not found: {filePath}" });
        }

        try
        {
            string content = await File.ReadAllTextAsync(filePath, cancellationToken);
            return JsonSerializer.Serialize(new
            {
                success = true,
                filePath,
                bytes = content.Length,
                content
            });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { success = false, error = ex.Message });
        }
    }

    [Description("Safely writes a file within an approved workspace or temporary scratch directory.")]
    public async Task<string> WriteSandboxedFileAsync(
        [Description("Target file path")] string filePath,
        [Description("Content to write")] string content,
        CancellationToken cancellationToken = default)
    {
        var context = new CopilotToolCallContext(
            SessionId: Guid.NewGuid(),
            AgentId: "copilot-agent",
            ToolName: "WriteSandboxedFile",
            ExecutableOrCommand: "fs_write",
            Arguments: filePath,
            WorkingDirectory: null,
            OperatorIdentity: _operatorIdentity);

        var result = await _substrate.ExecuteSafeToolAsync(context, _policy, cancellationToken);
        if (result.PolicyBlocked)
        {
            return JsonSerializer.Serialize(new
            {
                success = false,
                error = result.StandardError,
                merkleHash = result.MerkleEntryHash
            });
        }

        try
        {
            string? dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            await File.WriteAllTextAsync(filePath, content, cancellationToken);
            return JsonSerializer.Serialize(new
            {
                success = true,
                filePath,
                bytesWritten = content.Length,
                merkleHash = result.MerkleEntryHash
            });
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { success = false, error = ex.Message });
        }
    }

    [Description("Returns the active SPLAT security posture, kernel hooks status, and CISO policy enforcement summary.")]
    public string GetSubstrateSecurityStatus()
    {
        var status = new
        {
            substrate = "SPLAT Native Windows Safety Substrate",
            version = "2.0.0",
            osPlatform = Environment.OSVersion.ToString(),
            cisoPolicyId = _policy.PolicyId,
            cisoPolicyName = _policy.PolicyName,
            restrictedTokenEnforced = _policy.EnforceRestrictedToken,
            jobObjectLimitsEnforced = _policy.EnforceJobObjectResourceLimits,
            maxMemoryBytes = _policy.MaxMemoryBytes,
            maxCpuPercent = _policy.MaxCpuPercent,
            sentinelStreaming = _policy.StreamToMicrosoftSentinel,
            allowedExecutablesCount = _policy.AllowedExecutables.Count,
            blockedPathsCount = _policy.BlockedPathSubstrings.Count
        };

        return JsonSerializer.Serialize(status, new JsonSerializerOptions { WriteIndented = true });
    }
}
