using System;
using System.Collections.Generic;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Windows.Copilot;

/// <summary>
/// Execution filter context for Semantic Kernel / Copilot function invocations.
/// </summary>
public record SplatFunctionInvocationContext(
    string PluginName,
    string FunctionName,
    IReadOnlyDictionary<string, object?> Arguments,
    Guid SessionId,
    string AgentId,
    string OperatorIdentity);

/// <summary>
/// Function Invocation Filter that intercepts Microsoft Semantic Kernel and Copilot tool calls
/// before they reach the OS, enforcing SPLAT kernel leases and fail-closed security.
/// </summary>
public sealed class SplatCopilotInvocationFilter
{
    private readonly ICopilotSafetySubstrate _substrate;
    private readonly CopilotSafetyPolicy _policy;
    private readonly SiemConfiguration? _sentinelConfig;

    public SplatCopilotInvocationFilter(
        ICopilotSafetySubstrate substrate,
        CopilotSafetyPolicy? policy = null,
        SiemConfiguration? sentinelConfig = null)
    {
        _substrate = substrate ?? throw new ArgumentNullException(nameof(substrate));
        _policy = policy ?? CopilotSafetyPolicy.CreateEnterpriseDefault();
        _sentinelConfig = sentinelConfig;
    }

    /// <summary>
    /// Intercepts a Semantic Kernel function invocation.
    /// If the function executes a command or touches system resources, SPLAT validates and sandboxes it.
    /// </summary>
    public async Task<CopilotExecutionResult> InterceptAndExecuteAsync(
        SplatFunctionInvocationContext context,
        Func<Task<string>> innerExecutionFallback,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(innerExecutionFallback);

        // Extract command & arguments from common parameter names
        string executableOrCmd = ExtractStringArg(context.Arguments, "command", "executable", "path", "target") ?? "powershell.exe";
        string args = ExtractStringArg(context.Arguments, "arguments", "args", "script", "code", "input") ?? string.Empty;
        string? workDir = ExtractStringArg(context.Arguments, "workingDirectory", "workDir", "directory", "dir");

        var toolContext = new CopilotToolCallContext(
            SessionId: context.SessionId,
            AgentId: context.AgentId,
            ToolName: $"{context.PluginName}.{context.FunctionName}",
            ExecutableOrCommand: executableOrCmd,
            Arguments: args,
            WorkingDirectory: workDir,
            OperatorIdentity: context.OperatorIdentity);

        var result = await _substrate.ExecuteSafeToolAsync(toolContext, _policy, cancellationToken);

        // Stream telemetry to Sentinel if configured
        if (_sentinelConfig != null && _policy.StreamToMicrosoftSentinel)
        {
            await _substrate.StreamAlertToSentinelAsync(toolContext, result, _sentinelConfig, cancellationToken);
        }

        if (result.PolicyBlocked)
        {
            throw new SecurityException(
                $"[SPLAT COPILOT AIRBAG] Blocked execution of tool '{context.PluginName}.{context.FunctionName}'. " +
                $"Reason: {result.StandardError}. Audit entry signed into Merkle Ledger: {result.MerkleEntryHash}");
        }

        return result;
    }

    private static string? ExtractStringArg(IReadOnlyDictionary<string, object?> args, params string[] candidateKeys)
    {
        foreach (var key in candidateKeys)
        {
            foreach (var kvp in args)
            {
                if (string.Equals(kvp.Key, key, StringComparison.OrdinalIgnoreCase) && kvp.Value != null)
                {
                    return kvp.Value.ToString();
                }
            }
        }
        return null;
    }
}
