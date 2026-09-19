using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Shapes;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.UI.Views;
using Windows.Graphics;

namespace MissionController.UI;

public sealed partial class MainWindow : Window
{
    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetForegroundWindow(IntPtr hWnd);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_RESTORE = 9;
    private bool _isNavigating;

    public MainWindow()
    {
        InitializeComponent();
        // Read from the runtime the app is on: typed into the XAML, it said ".NET 9" through the move to 10.
        RuntimeLabel.Text = $"GOVERNED APPLIANCE  ·  .NET {Environment.Version.Major}";
        ConfigureWindow();
        _ = RunSelfCheckAsync();
        NavigateTo(typeof(QuickDiagnosticianView), SlideNavigationTransitionEffect.FromRight);
    }

    /// <summary>
    /// The status bar used to be typed into the XAML: green lights reading JOB SANDBOX ENFORCED, ACL
    /// JAILS ISOLATED and SHA-256 LEDGER VERIFIED, and CONTROL PLANE ONLINE above them, which no code
    /// ever checked. The ledger's stayed green whether or not the chain verified. Each light is now a
    /// check run at start, on the same types a mission uses, and says what it found.
    /// </summary>
    private async Task RunSelfCheckAsync()
    {
        var checks = new (TextBlock Label, Ellipse Dot, string Passed, string Failed, Func<Task<bool>> Run)[]
        {
            (JobSandboxLabel, JobSandboxDot, "JOB SANDBOX READY", "JOB SANDBOX FAILED", () => Task.Run(() =>
            {
                using var job = new Win32JobSandbox($"splat-selfcheck-{Guid.NewGuid():N}");
                return true;
            })),
            (JailLabel, JailDot, "ACL JAIL READY", "ACL JAIL FAILED", () => Task.Run(async () =>
            {
                var jails = new NtAclJailManager();
                await jails.DrainAndCleanupJailAsync(await jails.ProvisionJailAsync(Guid.NewGuid()));
                return true;
            })),
            // Off the UI thread: Microsoft.Data.Sqlite's async calls run synchronously, over the whole chain.
            (LedgerLabel, LedgerDot, "LEDGER CHAIN VERIFIED", "LEDGER CHAIN FAILED",
                () => Task.Run(() => App.Services.GetRequiredService<IAuditLedger>().VerifyLedgerIntegrityAsync())),
        };

        int failed = 0;
        foreach (var check in checks)
        {
            bool passed;
            try
            {
                passed = await check.Run();
            }
            catch (Exception)
            {
                // A check that throws has not passed, and says FAILED rather than staying green.
                passed = false;
            }

            failed += passed ? 0 : 1;
            check.Label.Text = passed ? check.Passed : check.Failed;
            Paint(check.Dot, passed);
        }

        SelfCheckLabel.Text = failed == 0 ? "SELF-CHECK PASSED" : $"SELF-CHECK: {failed} FAILED";
        Paint(SelfCheckDot, failed == 0);
    }

    private static void Paint(Ellipse dot, bool passed)
    {
        if (Application.Current.Resources.TryGetValue(passed ? "SplatSuccessBrush" : "SplatDangerBrush", out object? brush)
            && brush is Brush fill)
        {
            dot.Fill = fill;
        }
    }

    private void ConfigureWindow()
    {
        IntPtr hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        WindowId windowId = Microsoft.UI.Win32Interop.GetWindowIdFromWindow(hwnd);
        AppWindow appWindow = AppWindow.GetFromWindowId(windowId);

        if (appWindow != null)
        {
            appWindow.Title = "SPLAT — Autonomous AI Agent Fleet & System Appliance";
            appWindow.Resize(new SizeInt32(1280, 840));

            // Center window on screen
            var displayArea = DisplayArea.GetFromWindowId(windowId, DisplayAreaFallback.Primary);
            if (displayArea != null)
            {
                var centeredPosition = new PointInt32(
                    (displayArea.WorkArea.Width - 1280) / 2,
                    (displayArea.WorkArea.Height - 840) / 2);
                appWindow.Move(centeredPosition);
            }
        }

        ShowWindow(hwnd, SW_RESTORE);
        SetForegroundWindow(hwnd);
    }

    public void NavigateTo(System.Type pageType, SlideNavigationTransitionEffect effect = SlideNavigationTransitionEffect.FromRight)
    {
        if (_isNavigating) return;

        try
        {
            _isNavigating = true;

            // Synchronize NavigationView SelectedItem to match the target page
            if (pageType == typeof(SettingsView))
            {
                NavView.SelectedItem = NavView.SettingsItem;
            }
            else
            {
                string? targetTag = GetTagForPage(pageType);
                if (targetTag != null)
                {
                    var item = NavView.MenuItems
                        .OfType<NavigationViewItem>()
                        .FirstOrDefault(i => string.Equals(i.Tag?.ToString(), targetTag, StringComparison.OrdinalIgnoreCase));

                    if (item != null)
                    {
                        NavView.SelectedItem = item;
                    }
                }
            }

            ContentFrame.Navigate(pageType, null, new SlideNavigationTransitionInfo { Effect = effect });
        }
        finally
        {
            _isNavigating = false;
        }
    }

    private static string? GetTagForPage(System.Type pageType)
    {
        if (pageType == typeof(QuickDiagnosticianView)) return "QuickSolve";
        if (pageType == typeof(WelcomeOnboardingView)) return "Onboarding";
        if (pageType == typeof(LiveMissionMonitorView)) return "Monitor";
        if (pageType == typeof(TemplateCatalogView)) return "Catalog";
        if (pageType == typeof(ProjectStudioView)) return "Projects";
        if (pageType == typeof(SecurityAuditView)) return "Audit";
        if (pageType == typeof(SemanticSearchView)) return "Memory";
        if (pageType == typeof(JailInspectorView)) return "Jail";
        return null;
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (_isNavigating) return;

        if (args.IsSettingsSelected)
        {
            ContentFrame.Navigate(typeof(SettingsView), null, new SlideNavigationTransitionInfo { Effect = SlideNavigationTransitionEffect.FromRight });
            return;
        }

        if (args.SelectedItemContainer is NavigationViewItem selectedItem)
        {
            System.Type? targetPage = selectedItem.Tag?.ToString() switch
            {
                "QuickSolve" => typeof(QuickDiagnosticianView),
                "Onboarding" => typeof(WelcomeOnboardingView),
                "Monitor" => typeof(LiveMissionMonitorView),
                "Catalog" => typeof(TemplateCatalogView),
                "Projects" => typeof(ProjectStudioView),
                "Audit" => typeof(SecurityAuditView),
                "Memory" => typeof(SemanticSearchView),
                "Jail" => typeof(JailInspectorView),
                _ => null
            };

            if (targetPage != null)
            {
                ContentFrame.Navigate(targetPage, null, new SlideNavigationTransitionInfo { Effect = SlideNavigationTransitionEffect.FromRight });
            }
        }
    }
}
