using System;
using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.Views;
using Windows.Graphics;

namespace MissionController.UI;

public sealed partial class MainWindow : Window
{
    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    private const int SW_RESTORE = 9;

    public MainWindow()
    {
        InitializeComponent();
        ConfigureWindow();
        NavigateTo(typeof(QuickDiagnosticianView));
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

    public void NavigateTo(System.Type pageType)
    {
        ContentFrame.Navigate(pageType);
    }

    private void NavView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.IsSettingsSelected)
        {
            ContentFrame.Navigate(typeof(SettingsView));
            return;
        }

        if (args.SelectedItemContainer is NavigationViewItem selectedItem)
        {
            switch (selectedItem.Tag?.ToString())
            {
                case "QuickSolve":
                    ContentFrame.Navigate(typeof(QuickDiagnosticianView));
                    break;
                case "Onboarding":
                    ContentFrame.Navigate(typeof(WelcomeOnboardingView));
                    break;
                case "Monitor":
                    ContentFrame.Navigate(typeof(LiveMissionMonitorView));
                    break;
                case "Catalog":
                    ContentFrame.Navigate(typeof(TemplateCatalogView));
                    break;
                case "Audit":
                    ContentFrame.Navigate(typeof(SecurityAuditView));
                    break;
                case "Memory":
                    ContentFrame.Navigate(typeof(SemanticSearchView));
                    break;
                case "Jail":
                    ContentFrame.Navigate(typeof(JailInspectorView));
                    break;
            }
        }
    }
}
