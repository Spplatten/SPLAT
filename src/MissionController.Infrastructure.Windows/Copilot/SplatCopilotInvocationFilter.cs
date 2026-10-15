using System;
using System.Collections.Generic;
using System.Linq;
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

// Installed by the host, never inferred from model arguments or a tool's display name.
public sealed record SplatFunctionBinding(
    string PluginName,
    string FunctionName,
    string Executable,
    IReadOnlyList<string> ParameterNames,
    Func<IReadOnlyDictionary<string, object?>, string> BuildArguments,
    string? WorkingDirectory = null);

/// <summary>
/// Function Invocation Filter that intercepts Microsoft Semantic Kernel and Copilot tool calls
/// before they reach the OS, enforcing SPLAT kernel leases and fail-closed security.
/// </summary>
public sealed class SplatCopilotInvocationFilter
{
    private readonly ICopilotSafetySubstrate _substrate;
    private readonly CopilotSafetyPolicy _policy;
    private readonly SiemConfiguration? _sentinelConfig;
    private readonly Dictionary<(string Plugin, string Function), SplatFunctionBinding> _bindings;

    public SplatCopilotInvocationFilter(
        ICopilotSafetySubstrate substrate,
        CopilotSafetyPolicy? policy = null,
        SiemConfiguration? sentinelConfig = null,
        IEnumerable<SplatFunctionBinding>? bindings = null)
    {
        _substrate = substrate ?? throw new ArgumentNullException(nameof(substrate));
        _policy = policy ?? CopilotSafetyPolicy.CreateEnterpriseDefault();
        _sentinelConfig = sentinelConfig;
        _bindings = new();
        foreach (var binding in bindings ?? [])
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(binding.PluginName);
            ArgumentException.ThrowIfNullOrWhiteSpace(binding.FunctionName);
            ArgumentException.ThrowIfNullOrWhiteSpace(binding.Executable);
            ArgumentNullException.ThrowIfNull(binding.BuildArguments);
            _bindings.Add((binding.PluginName, binding.FunctionName), binding with
            {
                ParameterNames = binding.ParameterNames.ToArray()
            });
        }
    }

    /// <summary>
    /// Intercepts a Semantic Kernel function invocation.
    /// Executes the host's explicit binding; arbitrary registered host callbacks are never run.
    /// </summary>
    public async Task<CopilotExecutionResult> InterceptAndExecuteAsync(
        SplatFunctionInvocationContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!_bindings.TryGetValue((context.PluginName, context.FunctionName), out var binding))
            throw new SecurityException("[SPLAT POLICY] Function has no host-approved execution binding.");
        var arguments = new Dictionary<string, object?>(context.Arguments, StringComparer.Ordinal);
        if (arguments.Keys.Any(key => !binding.ParameterNames.Contains(key, StringComparer.Ordinal)))
            throw new SecurityException("[SPLAT POLICY] Function arguments exceed the approved binding.");

        var toolContext = new CopilotToolCallContext(
            SessionId: context.SessionId,
            AgentId: context.AgentId,
            ToolName: $"{context.PluginName}.{context.FunctionName}",
            ExecutableOrCommand: binding.Executable,
            Arguments: binding.BuildArguments(arguments),
            WorkingDirectory: binding.WorkingDirectory,
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
                $"Reason: {result.StandardError}. Audit entry hash: {result.MerkleEntryHash}");
        }

        return result;
    }

}
