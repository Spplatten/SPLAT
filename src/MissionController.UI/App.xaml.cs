using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using MissionController.Core;
using MissionController.Core.Brain;
using MissionController.Core.Crew;
using MissionController.Core.Interfaces;
using MissionController.Core.Replay;
using MissionController.Core.Workflow;
using MissionController.Host;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Data.Templates;
using MissionController.Infrastructure.Data.Vector;
using MissionController.Infrastructure.Linux;
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

    /// <summary>The self-test the command line asked for, or null for a normal start. See <see cref="ConsoleSelfTest"/>.</summary>
    internal static ConsoleSelfTest? SelfTest { get; private set; }

    /// <summary>
    /// How long the splash stays up once the main window is up, and the point at which it gives up
    /// waiting for that. The minimum stops a fast machine turning the mark into a flicker; the
    /// maximum means a main window that never comes up cannot leave a borderless always-on-top
    /// window sitting over the desktop.
    /// </summary>
    private static readonly TimeSpan SplashMinimumVisible = TimeSpan.FromMilliseconds(1100);
    private static readonly TimeSpan SplashMaximumVisible = TimeSpan.FromSeconds(8);

    private SplashWindow? _splash;
    private DispatcherTimer? _splashTimer;
    private bool _mainWindowReady;

    public App()
    {
        this.UnhandledException += OnUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnAppDomainUnhandledException;
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        // Decided before anything is built: in a self-test nobody is there to close a dialog, so
        // every fatal path below has to know which kind of run this is.
        SelfTest = ConsoleSelfTest.FromCommandLine(Environment.GetCommandLineArgs());

        // Before the container builds anything that opens a file: an installed copy from before
        // 2026-09-25 kept its database and vault under %LOCALAPPDATA%\MissionController, and the one
        // data root moved them. Written to the startup log rather than passing silently - an operator
        // whose history looked as though it had vanished would have nothing else to read.
        foreach (string adopted in SplatDataRoot.AdoptLegacyHostLayout(SplatDataRoot.Current))
        {
            FatalErrorLog.Write("data root", adopted);
        }

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

        // Before anything else: the splash is always-on-top, and a startup failure hidden behind the
        // logo is exactly the "it does nothing when I open it" symptom this handler exists to end.
        DismissSplash();

        // A self-test reports instead of asking. With the window up, the failure belongs to the page
        // that was open and the run goes on to the next; before the window, the console did not start,
        // and the run ends with the code a normal start would give.
        if (SelfTest is { } selfTest)
        {
            e.Handled = true;
            if (MainWindowInstance is null)
            {
                selfTest.AbortForStartupFailure(e.Exception);
            }
            else
            {
                selfTest.RecordUnhandled(e.Exception);
            }

            return;
        }

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
        SelfTest?.NoteFatal(e.ExceptionObject);
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
        // The Missions row. Registered here rather than left to its default null, because the
        // retention sweep this app exposes erases three of that table's columns and had nothing to
        // erase: the sweep reported zeroes that read exactly like a clean result.
        services.AddSingleton<IMissionHistoryStore, SqliteMissionHistoryStore>();
        services.AddSingleton<IMerkleProofEngine, MerkleTreeEngine>();

        // The operator's run record signing key, named the same way as the ledger key. Without it the
        // console still exports bundles; they say they are unsigned. A variable naming a file that
        // will not do stops the start rather than exporting something that cannot be attributed.
        services.AddSingleton<IComplianceArchiveExporter>(sp => new ComplianceArchiveExporter(
            sp.GetRequiredService<IMerkleProofEngine>(),
            Environment.GetEnvironmentVariable(RunRecordKeyFile.EnvironmentVariable) is { Length: > 0 } signingKeyPath
                ? RunRecordKeyFile.Load(signingKeyPath)
                : null));
        services.AddSingleton<IMissionRunRecordAssembler, MissionRunRecordAssembler>();

        // Infrastructure - Identity & Zero-Trust Auth
        services.AddSingleton<ITokenValidator, JwtTokenValidator>();
        services.AddSingleton<IApiKeyValidator, ApiKeyValidator>();
        services.AddSingleton<ITokenLifecycleManager, TokenLifecycleManager>();
        services.AddSingleton<ICredentialSanitizer, PromptCredentialSanitizer>();
        services.AddSingleton<IRevocationStore, SqliteRevocationStore>();
        services.AddSingleton<IIncidentRevocationManager, IncidentRevocationManager>();

        // Infrastructure - the Linux lease, for the catalog templates whose tool names it. The
        // engine asks the selector for every mission; a Windows template gets null and runs as it
        // always has. A leased mission reaches the daemon the way run_command does, through the
        // same bridge, with its lease compiled from the template rather than authored by a caller.
        var managedBridge = ManagedBridgeClient.FromEnvironment();
        services.AddSingleton<ILeasedExecutor>(_ => managedBridge is not null ? managedBridge : new WslLeasedExecutor());
        services.AddSingleton<ITemplatePolicyCompiler, TemplatePolicyCompiler>();
        services.AddSingleton<IMissionSubstrateSelector, LinuxLeaseSubstrate>();
        // The same doctor, mount and unmount splat-mcp runs, so the console can install, check and remove
        // the daemon it leases through instead of trusting whatever answers on its port. An installed
        // console mounts the daemon shipped beside it; a developer build has none and builds it with cargo.
        services.AddSingleton(_ => new SubstrateLifecycle(
            daemonBinary: SubstrateLifecycle.DaemonBesideApp(AppContext.BaseDirectory),
            managedCheck: managedBridge is null ? null : managedBridge.CheckAsync));

        // Core Engine & Cognitive Brain
        services.AddSingleton<IDiagnosticFindingsExtractor, JsonFindingsExtractor>();
        // Every mission's post-tool path is written as a replay fixture when the operator names a
        // directory. Registered only then: the engine's recorder parameter is optional, and the
        // container passes null for an unregistered optional, so an unset variable records nothing.
        if (MissionFixtureDirectoryRecorder.FromEnvironment("console") is { } recorder)
        {
            services.AddSingleton<IMissionRecorder>(recorder);
        }
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
        services.AddSingleton<KernelLeaseViewModel>();
        services.AddSingleton<SettingsViewModel>();

        Services = services.BuildServiceProvider();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // Shown first and deliberately: constructing MainWindow parses the whole XAML tree and
        // resolves the composition root, and until now that interval was blank desktop. A self-test
        // gets none of it - it counts the console's own windows and drives them, and a second
        // always-on-top window is not something an unattended run should have to reason about.
        _splash = SelfTest is null ? SplashWindow.TryShow() : null;

        // No yield before MainWindow any more. The splash was a XAML window once, on this same UI
        // thread, and a thread building XAML is a thread not drawing - so it needed a moment to
        // paint before that work started. A layered window is already composited by the time
        // TryShow returns, and stays up while this thread is busy.
        StartMainWindow();
    }

    private void StartMainWindow()
    {
        var visible = System.Diagnostics.Stopwatch.StartNew();

        MainWindowInstance = new MainWindow();
        MainWindowInstance.Activated += OnMainWindowActivated;

        // Activation alone is not a reliable signal that the window is up. The splash is
        // always-on-top, so it keeps the foreground and SetForegroundWindow on the main window
        // fails: measured, the main window was visible from t+0.8s and never raised Activated, and
        // the splash stayed until the 8-second cap took it down. Loaded fires off the visual tree
        // rather than focus, and one of the two always arrives.
        if (MainWindowInstance.Content is FrameworkElement root)
        {
            root.Loaded += OnMainWindowContentLoaded;
        }

        MainWindowInstance.Activate();

        // The window is shown first, as in a normal start, so what the self-test opens is what an
        // operator would see. It exits the process itself when it is done.
        if (SelfTest is { } selfTest)
        {
            _ = selfTest.RunAsync((MainWindow)MainWindowInstance);
            return;
        }

        if (_splash is null)
        {
            return;
        }

        // Polled rather than chained off the readiness events alone, so the dismissal has one exit
        // the main window cannot fail to reach. A tick can only happen when the UI thread is free,
        // so the splash covers exactly the interval during which the console cannot draw.
        _splashTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(120) };
        _splashTimer.Tick += (_, _) =>
        {
            if ((_mainWindowReady && visible.Elapsed >= SplashMinimumVisible)
                || visible.Elapsed >= SplashMaximumVisible)
            {
                DismissSplash();
            }
        };
        _splashTimer.Start();
    }

    private void OnMainWindowActivated(object sender, WindowActivatedEventArgs e)
    {
        _mainWindowReady = true;

        if (MainWindowInstance is not null)
        {
            MainWindowInstance.Activated -= OnMainWindowActivated;
        }
    }

    private void OnMainWindowContentLoaded(object sender, RoutedEventArgs e)
    {
        _mainWindowReady = true;

        if (sender is FrameworkElement root)
        {
            root.Loaded -= OnMainWindowContentLoaded;
        }
    }

    /// <summary>Takes the splash down. Safe to call repeatedly, from any point in the launch.</summary>
    private void DismissSplash()
    {
        try
        {
            _splashTimer?.Stop();
            _splashTimer = null;
            _splash?.Dismiss();
            _splash = null;
        }
        catch (Exception)
        {
            // Nothing above this is load-bearing enough to take the app down for.
        }
    }
}
