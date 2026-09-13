using System;
using System.Linq;
using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
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
        ConfigureWindow();
        NavigateTo(typeof(QuickDiagnosticianView), SlideNavigationTransitionEffect.FromRight);
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
