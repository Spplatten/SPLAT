using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using MissionController.Core;
using MissionController.Core.Brain;
using MissionController.Core.Crew;
using MissionController.Core.Interfaces;
using MissionController.Core.Workflow;
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
using MissionController.Infrastructure.Windows.Copilot;
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
        this.UnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        InitializeComponent();
        ConfigureServices();
    }

    /// <summary>
    /// Debug.WriteLine alone is invisible to anyone not attached to a debugger, which is how a
    /// startup exception presents as "the app does nothing when I open it" - the process dies with
    /// the only explanation written somewhere nobody can read. Every fatal path also lands in
    /// <see cref="FatalErrorLog"/> so a failed launch always leaves evidence on disk.
    /// </summary>
    private static void LogFatal(string source, object? detail)
    {
        System.Diagnostics.Debug.WriteLine($"[CRITICAL] {source}: {detail}");
        FatalErrorLog.Write(source, detail);
    }

    [System.Runtime.InteropServices.LibraryImport("user32.dll", EntryPoint = "MessageBoxW", StringMarshalling = System.Runtime.InteropServices.StringMarshalling.Utf16)]
    private static partial int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    private const uint MbIconError = 0x00000010;
    private const uint MbSystemModal = 0x00001000;

    /// <summary>
    /// Surfaces a fatal error to the person in front of the machine. A Win32 message box is used
    /// deliberately instead of a ContentDialog: a dialog needs a XamlRoot, and the failures worth
    /// reporting most are the ones that happen before any window exists.
    /// </summary>
    private static void ShowFatalDialog(string headline, object? detail)
    {
        try
        {
            string body =
                $"{headline}\n\n{detail}\n\nFull detail was written to:\n{FatalErrorLog.DefaultPath}";

            // Truncated because MessageBoxW silently fails to render very long strings, and a dialog
            // that does not appear puts us right back at "the app does nothing".
            if (body.Length > 1800)
            {
                body = body.Substring(0, 1800) + "\n…(truncated — see the log file)";
            }

            MessageBoxW(IntPtr.Zero, body, "SPLAT — Unrecoverable Error", MbIconError | MbSystemModal);
        }
        catch
        {
            // Never let the reporter become the failure.
        }
    }

    private void OnUnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        LogFatal("WinUI UnhandledException", e.Exception);

        // Startup failures used to be swallowed here. Handled=true kept the process alive with no
        // window, which is precisely how a XAML load error presented as "I double-click it and
        // nothing happens" - the app was running, just permanently invisible. If the main window
        // never came up there is nothing left to return to, so report and exit rather than idle
        // forever as an invisible process the user can only find in Task Manager.
        bool failedBeforeWindowExists = MainWindowInstance is null;

        ShowFatalDialog(
            failedBeforeWindowExists
                ? "SPLAT could not start. The error below stopped it before its window opened."
                : "SPLAT hit an unexpected error. The app will stay open, but this action did not complete.",
            e.Exception);

        e.Handled = true;

        if (failedBeforeWindowExists)
        {
            Environment.Exit(1);
        }
    }

    private void OnAppDomainUnhandledException(object sender, System.UnhandledExceptionEventArgs e)
    {
        LogFatal("AppDomain UnhandledException", e.ExceptionObject);
    }

    private void OnUnobservedTaskException(object? sender, System.Threading.Tasks.UnobservedTaskExceptionEventArgs e)
    {
        LogFatal("UnobservedTaskException", e.Exception);
        e.SetObserved();
    }

    private static void ConfigureServices()
    {
        var services = new ServiceCollection();

        // Infrastructure - Windows & Kernel Sandboxing
        // Ledger attribution. The Windows logon session is the operator: the OS has already
        // authenticated this principal, and a desktop console has no separate authority it could
        // add on top. This replaces the string literals each view model used to pass.
        services.AddSingleton<IOperatorIdentityProvider>(
            _ => new WindowsOperatorIdentityProvider("winui-console"));

        services.AddSingleton<IRestrictedTokenProvider, RestrictedTokenProvider>();
        services.AddSingleton<IJailManager, NtAclJailManager>();
        services.AddSingleton<IProcessLauncher, SuspendedProcessLauncher>();
        services.AddSingleton<ICredentialVault, DpapiCredentialVault>();
        services.AddSingleton<Func<string, IJobSandbox>>(_ => name => new Win32JobSandbox(name));
        services.AddSingleton<IRemediationEngine, SandboxedRemediationEngine>();
        services.AddSingleton<ICopilotSafetyPolicyEngine, CopilotSafetyPolicyEngine>();
        services.AddSingleton<ICopilotSafetySubstrate, CopilotSafetySubstrate>();

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
        // The console has no command line, so the operator's key file reaches it through this variable.
        // A variable naming a file that will not do stops the start rather than chaining unkeyed.
        services.AddSingleton<IAuditLedger>(sp => new SqliteChainedAuditLedger(
            sp.GetRequiredService<SqliteStorageContext>(),
            Environment.GetEnvironmentVariable(LedgerKeyFile.EnvironmentVariable) is { Length: > 0 } keyPath
                ? LedgerKeyFile.Read(keyPath)
                : null));
        services.AddSingleton<ITemplateRegistry, SqliteTemplateRegistry>();
        services.AddSingleton<IProjectTemplateRegistry, SqliteProjectTemplateRegistry>();
        services.AddSingleton<ISemanticMemoryIndex, SqliteSemanticMemoryIndex>();
        services.AddSingleton<IMerkleProofEngine, MerkleTreeEngine>();
        services.AddSingleton<IComplianceArchiveExporter, ComplianceArchiveExporter>();
        services.AddSingleton<IMissionRunRecordAssembler, MissionRunRecordAssembler>();

        // Infrastructure - Identity & Zero-Trust Auth
        services.AddSingleton<ITokenValidator, JwtTokenValidator>();
        services.AddSingleton<IApiKeyValidator, ApiKeyValidator>();
        services.AddSingleton<ITokenLifecycleManager, TokenLifecycleManager>();
        services.AddSingleton<ICredentialSanitizer, PromptCredentialSanitizer>();
        services.AddSingleton<IIncidentRevocationManager, IncidentRevocationManager>();

        // Core Engine & Cognitive Brain
        services.AddSingleton<IDiagnosticFindingsExtractor, JsonFindingsExtractor>();
        services.AddSingleton<ICognitiveGoalDecomposer, CognitiveGoalDecomposer>();
        services.AddSingleton<IAgentBrain, AgentBrainEngine>();
        services.AddSingleton<IMissionExecutionEngine, MissionExecutionEngine>();
        services.AddSingleton<IGovernedInvestigationLoop, GovernedInvestigationLoop>();
        services.AddSingleton<IProjectExecutionEngine, ProjectExecutionEngine>();
        services.AddSingleton<IGovernedCrewEngine, GovernedCrewEngine>();

        // The orchestrator. Registered here because until now it was not: the workflow engine was
        // constructed only by its own tests, so every guarantee it grew was a guarantee no shipped
        // code path could reach. Its mission engine and template registry are the SAME singletons
        // the single-mission UI uses - a workflow step is one governed mission, run by the one
        // engine that knows how, rather than a parallel execution tier that reimplements a subset.
        services.AddSingleton<IWorkflowExecutionEngine>(sp => new WorkflowExecutionEngine(
            dlpSanitizer: sp.GetRequiredService<IDataLossPreventionSanitizer>(),
            processLauncher: sp.GetRequiredService<IProcessLauncher>(),
            // Only the TransactionalScope node still launches directly; every other step goes
            // through the mission engine. Each scope gets its own named job object.
            sandboxFactory: () => sp.GetRequiredService<Func<string, IJobSandbox>>()(
                $"splat-workflow-{Guid.NewGuid():N}"),
            auditLedger: sp.GetRequiredService<IAuditLedger>(),
            modelClient: sp.GetRequiredService<IModelStreamClient>(),
            semanticMemoryIndex: sp.GetRequiredService<ISemanticMemoryIndex>(),
            missionEngine: sp.GetRequiredService<IMissionExecutionEngine>(),
            templateRegistry: sp.GetRequiredService<ITemplateRegistry>()));

        // ViewModels
        services.AddSingleton<WelcomeOnboardingViewModel>();
        services.AddSingleton<QuickDiagnosticianViewModel>();
        services.AddSingleton<LiveMissionMonitorViewModel>();
        services.AddSingleton<TemplateCatalogViewModel>();
        services.AddSingleton<ProjectStudioViewModel>();
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
