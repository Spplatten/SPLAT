using System;
using Microsoft.Extensions.DependencyInjection;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;

namespace MissionController.Infrastructure.Windows.Copilot;

/// <summary>
/// Dependency injection and configuration extensions for Microsoft Semantic Kernel and Copilot hosts.
/// </summary>
public static class SemanticKernelExtensions
{
    /// <summary>
    /// Adds SPLAT Native Windows Copilot Safety Substrate and policy engine to the service container.
    /// </summary>
    public static IServiceCollection AddSplatCopilotSafety(
        this IServiceCollection services,
        CopilotSafetyPolicy? policy = null,
        SiemConfiguration? sentinelConfig = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton(policy ?? CopilotSafetyPolicy.CreateEnterpriseDefault());

        if (sentinelConfig != null)
        {
            services.AddSingleton(sentinelConfig);
        }

        services.AddSingleton<IRestrictedTokenProvider, RestrictedTokenProvider>();
        services.AddSingleton<IJailManager, NtAclJailManager>();
        services.AddSingleton<IProcessLauncher, SuspendedProcessLauncher>();
        services.AddSingleton<ICopilotSafetyPolicyEngine, CopilotSafetyPolicyEngine>();
        services.AddSingleton<ICopilotSafetySubstrate, CopilotSafetySubstrate>();
        services.AddSingleton<SplatCopilotInvocationFilter>();
        services.AddSingleton<SplatCopilotPlugin>();

        return services;
    }
}
