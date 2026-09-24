using System;
using System.Runtime.InteropServices;
using Microsoft.UI;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using MissionController.Core;
using Windows.Graphics;

namespace MissionController.UI;

/// <summary>
/// The borderless mark shown while the main window is being built.
///
/// An unpackaged WinUI application gets no platform splash screen, and building MainWindow is not
/// instant: the XAML tree, the design tokens and the composition root all resolve before anything
/// appears. That gap used to be blank desktop, which is the same thing a failed launch looks like.
///
/// Every step here is best-effort. A splash that throws would turn a cosmetic feature into a
/// startup crash, so construction is funnelled through <see cref="TryShow"/> and a failure leaves
/// the application running with no splash at all.
/// </summary>
public sealed partial class SplashWindow : Window
{
    // Device-independent pixels. AppWindow.Resize takes physical pixels, so these are scaled by the
    // display's DPI before use - at 150% a 460px window would otherwise clip its own content.
    private const int WidthDips = 460;
    private const int HeightDips = 392;

    [LibraryImport("user32.dll")]
    private static partial uint GetDpiForWindow(IntPtr hwnd);

    [StructLayout(LayoutKind.Sequential)]
    private struct Margins
    {
        public int Left;
        public int Right;
        public int Top;
        public int Bottom;
    }

    [LibraryImport("dwmapi.dll")]
    private static partial int DwmExtendFrameIntoClientArea(IntPtr hwnd, in Margins margins);

    private SplashWindow()
    {
        InitializeComponent();
        Configure();
    }

    /// <summary>
    /// Shows the splash, or returns null if it could not be shown. Never throws.
    /// </summary>
    public static SplashWindow? TryShow()
    {
        try
        {
            var splash = new SplashWindow();
            splash.Activate();
            return splash;
        }
        catch (Exception ex)
        {
            // Worth a line in the crash log - a missing splash is the visible symptom of a broken
            // asset copy - but never worth the launch.
            FatalErrorLog.Write("SplashWindow", ex);
            return null;
        }
    }

    /// <summary>Closes the splash. Safe to call more than once, and after the window is gone.</summary>
    public void Dismiss()
    {
        try
        {
            Close();
        }
        catch (Exception)
        {
            // The window is already gone; that is the outcome this method wanted.
        }
    }

    private void Configure()
    {
        IntPtr hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        WindowId windowId = Win32Interop.GetWindowIdFromWindow(hwnd);
        AppWindow appWindow = AppWindow.GetFromWindowId(windowId);

        if (appWindow is null)
        {
            return;
        }

        // Configured through the presenter the window already owns. A presenter built with
        // OverlappedPresenter.Create() and configured before SetPresenter loses the frame calls:
        // the splash came up with a full title bar, which is how this was found.
        appWindow.SetPresenter(AppWindowPresenterKind.Overlapped);
        if (appWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsResizable = false;
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
            // On top of the main window, which calls SetForegroundWindow on itself as it configures.
            presenter.IsAlwaysOnTop = true;
            presenter.SetBorderAndTitleBar(hasBorder: false, hasTitleBar: false);
        }

        // A splash in alt-tab and on the taskbar reads as a second application.
        appWindow.IsShownInSwitchers = false;

        // Per-pixel alpha. A WinUI window with a transparent root still composes onto its own
        // opaque surface, which is why "no background" renders black rather than see-through; this
        // SDK has MicaBackdrop and DesktopAcrylicBackdrop but no TransparentBackdrop, and both of
        // those are blur, not transparency. Extending the frame across the whole client area hands
        // the surface to DWM, which honours the alpha the XAML actually drew - so the marks float
        // over whatever is behind the window and the keyed-out backdrop stays keyed out.
        var sheetOfGlass = new Margins { Left = -1, Right = -1, Top = -1, Bottom = -1 };
        DwmExtendFrameIntoClientArea(hwnd, sheetOfGlass);

        uint dpi = GetDpiForWindow(hwnd);
        double scale = dpi == 0 ? 1.0 : dpi / 96.0;
        int width = (int)Math.Round(WidthDips * scale);
        int height = (int)Math.Round(HeightDips * scale);
        appWindow.Resize(new SizeInt32(width, height));

        // Centred on the work area of the display the window opened on, origin included: on a
        // secondary monitor an origin-less centring puts the splash on the wrong screen.
        DisplayArea display = DisplayArea.GetFromWindowId(windowId, DisplayAreaFallback.Primary);
        if (display is not null)
        {
            appWindow.Move(new PointInt32(
                display.WorkArea.X + (display.WorkArea.Width - width) / 2,
                display.WorkArea.Y + (display.WorkArea.Height - height) / 2));
        }
    }
}
