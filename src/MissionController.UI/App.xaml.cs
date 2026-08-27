using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Data.Vector;
using MissionController.Infrastructure.Network.Dlp;
using MissionController.Infrastructure.Network.Edr;
using MissionController.Infrastructure.Network.Http;
using MissionController.Infrastructure.Network.Identity;
using MissionController.Infrastructure.Network.Siem;
using MissionController.Infrastructure.Network.Ai;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Remediation;
using MissionController.Infrastructure.Windows.Security;
using MissionController.Infrastructure.Windows.Vault;
using MissionController.UI.ViewModels;

namespace MissionController.UI;

public partial class App : Application
{
    public static IServiceProvider Services { get; private set; } = null!;
    public static Window? MainWindowInstance { get; private set; }

    public App()
    {
        InitializeComponent();
        ConfigureServices();
    }

    private static void ConfigureServices()
    {
        var services = new ServiceCollection();

        // Infrastructure - Windows & Kernel Sandboxing
        services.AddSingleton<IRestrictedTokenProvider, RestrictedTokenProvider>();
        services.AddSingleton<IJailManager, NtAclJailManager>();
        services.AddSingleton<IProcessLauncher, SuspendedProcessLauncher>();
        services.AddSingleton<ICredentialVault, DpapiCredentialVault>();
        services.AddSingleton<Func<string, IJobSandbox>>(_ => name => new Win32JobSandbox(name));
        services.AddSingleton<IRemediationEngine, SandboxedRemediationEngine>();

        // Infrastructure - Network & AI & DLP & SIEM & EDR
        var (httpClient, firewall) = HardenedHttpClientFactory.CreateHardenedClient();
        services.AddSingleton(httpClient);
        services.AddSingleton(firewall);
        services.AddSingleton<IEgressFirewall>(firewall);
        services.AddSingleton<IDataLossPreventionSanitizer, RegexDataLossPreventionSanitizer>();
        // Provider-by-available-key routing: Claude is the default and wins when both keys exist;
        // a Gemini key alone still lights up live analysis instead of the simulated placeholder.
        services.AddSingleton<ClaudeStreamClient>();
        services.AddSingleton<GeminiStreamClient>();
        services.AddSingleton<IModelStreamClient, ModelClientRouter>();
        services.AddSingleton<ISiemForwarder, SiemForwarder>();
        services.AddSingleton<IEdrIngestionBridge, EdrIngestionBridge>();

        // Infrastructure - Data & Audit & Semantic Memory & Merkle Compliance
        services.AddSingleton<SqliteStorageContext>();
        services.AddSingleton<IAuditLedger, SqliteChainedAuditLedger>();
        services.AddSingleton<ITemplateRegistry, SqliteTemplateRegistry>();
        services.AddSingleton<ISemanticMemoryIndex, SqliteSemanticMemoryIndex>();
        services.AddSingleton<IMerkleProofEngine, MerkleTreeEngine>();
        services.AddSingleton<IComplianceArchiveExporter, ComplianceArchiveExporter>();

        // Infrastructure - Identity & Zero-Trust Auth
        services.AddSingleton<ITokenValidator, JwtTokenValidator>();
        services.AddSingleton<IApiKeyValidator, ApiKeyValidator>();
        services.AddSingleton<ITokenLifecycleManager, TokenLifecycleManager>();
        services.AddSingleton<ICredentialSanitizer, PromptCredentialSanitizer>();
        services.AddSingleton<IIncidentRevocationManager, IncidentRevocationManager>();

        // Core Engine
        services.AddSingleton<IMissionExecutionEngine, MissionExecutionEngine>();

        // ViewModels
        services.AddSingleton<WelcomeOnboardingViewModel>();
        services.AddSingleton<QuickDiagnosticianViewModel>();
        services.AddSingleton<LiveMissionMonitorViewModel>();
        services.AddSingleton<TemplateCatalogViewModel>();
        services.AddSingleton<SecurityAuditViewModel>();
        services.AddSingleton<SemanticSearchViewModel>();
        services.AddSingleton<JailInspectorViewModel>();
        services.AddSingleton<SettingsViewModel>();

        Services = services.BuildServiceProvider();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        MainWindowInstance = new MainWindow();
        MainWindowInstance.Activate();
    }
}
