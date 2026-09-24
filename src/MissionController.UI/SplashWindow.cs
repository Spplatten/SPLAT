using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using MissionController.Core;

namespace MissionController.UI;

/// <summary>
/// The mark shown while the main window is being built - a layered Win32 window, not a XAML one.
///
/// It was a XAML window first, and could not be made transparent. A WinUI island composes onto its
/// own opaque surface: a transparent root renders black, DwmExtendFrameIntoClientArea fills the
/// client area with the system's glass (a near-white sheet on a light theme), and the undocumented
/// accent policy that is supposed to fix that erased the window's contents along with its
/// background. This SDK has MicaBackdrop and DesktopAcrylicBackdrop and no TransparentBackdrop, and
/// both of those are blur rather than transparency.
///
/// A layered window is the mechanism that does composite per-pixel alpha against the desktop, and
/// it takes one finished bitmap rather than a visual tree - so the whole splash, type included, is
/// composed by brand\build-brand-assets.py and shipped as premultiplied BGRA. That also takes the
/// splash off the XAML thread entirely: UpdateLayeredWindow hands DWM the pixels immediately, so
/// the mark is up and composited while that thread is busy building MainWindow, which is precisely
/// the interval it exists to cover.
///
/// Every step is best-effort. A splash that throws would turn a cosmetic feature into a startup
/// crash, so construction is funnelled through <see cref="TryShow"/> and a failure leaves the
/// application running with no splash at all.
/// </summary>
internal sealed partial class SplashWindow
{
    // Device-independent pixels; scaled by the display's DPI before the window is sized.
    private const int WidthDips = 460;
    private const int HeightDips = 392;

    private const string BitmapAsset = @"Assets\splat-splash.bgra.gz";

    private IntPtr _hwnd;

    private SplashWindow(IntPtr hwnd) => _hwnd = hwnd;

    /// <summary>Shows the splash, or returns null if it could not be shown. Never throws.</summary>
    public static SplashWindow? TryShow()
    {
        IntPtr hwnd = IntPtr.Zero;

        try
        {
            (int sourceWidth, int sourceHeight, byte[] source) = ReadBitmap();

            // WS_EX_NOACTIVATE so it never takes the foreground from the main window, and
            // WS_EX_TOOLWINDOW so it stays out of alt-tab and the taskbar. The predefined STATIC
            // class avoids registering a window class and a WndProc for a window that never
            // handles a message - the bitmap is pushed to DWM, not painted on demand.
            hwnd = CreateWindowExW(
                WsExLayered | WsExToolWindow | WsExTopMost | WsExNoActivate,
                "STATIC", null, WsPopup, 0, 0, 0, 0,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (hwnd == IntPtr.Zero)
            {
                return null;
            }

            uint dpi = GetDpiForWindow(hwnd);
            double scale = dpi == 0 ? 1.0 : dpi / 96.0;
            int width = (int)Math.Round(WidthDips * scale);
            int height = (int)Math.Round(HeightDips * scale);

            byte[] scaled = Resample(source, sourceWidth, sourceHeight, width, height);

            if (!Present(hwnd, scaled, width, height))
            {
                DestroyWindow(hwnd);
                return null;
            }

            ShowWindow(hwnd, SwShowNoActivate);
            return new SplashWindow(hwnd);
        }
        catch (Exception ex)
        {
            // Worth a line in the crash log - a missing splash is the visible symptom of a broken
            // asset copy - but never worth the launch.
            FatalErrorLog.Write("SplashWindow", ex);

            if (hwnd != IntPtr.Zero)
            {
                try
                {
                    DestroyWindow(hwnd);
                }
                catch (Exception)
                {
                    // Already gone, or never really there.
                }
            }

            return null;
        }
    }

    /// <summary>Closes the splash. Safe to call more than once, and after the window is gone.</summary>
    public void Dismiss()
    {
        IntPtr hwnd = _hwnd;
        _hwnd = IntPtr.Zero;

        if (hwnd == IntPtr.Zero)
        {
            return;
        }

        try
        {
            // Destroyed from the thread that created it, which is the launch thread in every path
            // that reaches here.
            DestroyWindow(hwnd);
        }
        catch (Exception)
        {
            // The window is already gone; that is the outcome this method wanted.
        }
    }

    /// <summary>
    /// Reads the shipped bitmap: a little-endian width and height, then premultiplied BGRA rows,
    /// top-down. Raw rather than PNG because this is exactly what UpdateLayeredWindow consumes -
    /// no decoder on the launch path, and nothing between the file and the DIB section.
    /// </summary>
    private static (int Width, int Height, byte[] Pixels) ReadBitmap()
    {
        string path = Path.Combine(AppContext.BaseDirectory, BitmapAsset);

        using var file = File.OpenRead(path);
        using var gzip = new GZipStream(file, CompressionMode.Decompress);
        using var buffer = new MemoryStream();
        gzip.CopyTo(buffer);

        byte[] raw = buffer.GetBuffer();
        int width = BitConverter.ToInt32(raw, 0);
        int height = BitConverter.ToInt32(raw, 4);
        int expected = width * height * 4;

        if (width <= 0 || height <= 0 || buffer.Length < 8 + expected)
        {
            throw new InvalidDataException(
                $"{BitmapAsset} declares {width}x{height} but carries {buffer.Length - 8} bytes of pixels.");
        }

        byte[] pixels = new byte[expected];
        Array.Copy(raw, 8, pixels, 0, expected);
        return (width, height, pixels);
    }

    /// <summary>
    /// Bilinear resample of premultiplied BGRA. Done here rather than with StretchBlt because
    /// GDI's stretch modes are defined for opaque bitmaps: HALFTONE mixes the alpha channel as if
    /// it were colour, and COLORONCOLOR drops rows outright, which on a 2x source means a mark
    /// with chewed edges. Premultiplied channels interpolate linearly, so this is the plain form.
    /// </summary>
    private static byte[] Resample(byte[] source, int sourceWidth, int sourceHeight, int width, int height)
    {
        if (sourceWidth == width && sourceHeight == height)
        {
            return source;
        }

        byte[] target = new byte[width * height * 4];
        double stepX = (double)sourceWidth / width;
        double stepY = (double)sourceHeight / height;

        for (int y = 0; y < height; y++)
        {
            double sourceY = ((y + 0.5) * stepY) - 0.5;
            int y0 = Math.Clamp((int)Math.Floor(sourceY), 0, sourceHeight - 1);
            int y1 = Math.Min(y0 + 1, sourceHeight - 1);
            double fy = Math.Clamp(sourceY - y0, 0.0, 1.0);

            for (int x = 0; x < width; x++)
            {
                double sourceX = ((x + 0.5) * stepX) - 0.5;
                int x0 = Math.Clamp((int)Math.Floor(sourceX), 0, sourceWidth - 1);
                int x1 = Math.Min(x0 + 1, sourceWidth - 1);
                double fx = Math.Clamp(sourceX - x0, 0.0, 1.0);

                int topLeft = ((y0 * sourceWidth) + x0) * 4;
                int topRight = ((y0 * sourceWidth) + x1) * 4;
                int bottomLeft = ((y1 * sourceWidth) + x0) * 4;
                int bottomRight = ((y1 * sourceWidth) + x1) * 4;
                int destination = ((y * width) + x) * 4;

                for (int channel = 0; channel < 4; channel++)
                {
                    double top = (source[topLeft + channel] * (1 - fx)) + (source[topRight + channel] * fx);
                    double bottom = (source[bottomLeft + channel] * (1 - fx)) + (source[bottomRight + channel] * fx);
                    target[destination + channel] = (byte)Math.Clamp(
                        Math.Round((top * (1 - fy)) + (bottom * fy)), 0, 255);
                }
            }
        }

        return target;
    }

    /// <summary>
    /// Hands the pixels to DWM and places the window centred on the primary work area. This is the
    /// call that makes the window transparent: ULW_ALPHA with AC_SRC_ALPHA composites the bitmap's
    /// own alpha against whatever is behind the window.
    /// </summary>
    private static bool Present(IntPtr hwnd, byte[] pixels, int width, int height)
    {
        IntPtr screen = GetDC(IntPtr.Zero);
        IntPtr memory = IntPtr.Zero;
        IntPtr bitmap = IntPtr.Zero;
        IntPtr previous = IntPtr.Zero;

        try
        {
            if (screen == IntPtr.Zero)
            {
                return false;
            }

            memory = CreateCompatibleDC(screen);
            if (memory == IntPtr.Zero)
            {
                return false;
            }

            var header = new BitmapInfoHeader
            {
                Size = (uint)Marshal.SizeOf<BitmapInfoHeader>(),
                Width = width,
                Height = -height,          // negative: top-down, matching the file's row order
                Planes = 1,
                BitCount = 32,
                Compression = 0,           // BI_RGB
            };

            bitmap = CreateDIBSection(memory, header, 0, out IntPtr bits, IntPtr.Zero, 0);
            if (bitmap == IntPtr.Zero || bits == IntPtr.Zero)
            {
                return false;
            }

            Marshal.Copy(pixels, 0, bits, width * height * 4);
            previous = SelectObject(memory, bitmap);

            var workArea = new Rect();
            var position = new Point();
            if (SystemParametersInfoW(SpiGetWorkArea, 0, ref workArea, 0))
            {
                // Primary work area: this runs before any XAML exists, so there is no window to ask
                // which display it opened on, and the main window centres on the primary too.
                position.X = workArea.Left + ((workArea.Right - workArea.Left - width) / 2);
                position.Y = workArea.Top + ((workArea.Bottom - workArea.Top - height) / 2);
            }

            var size = new Size { Cx = width, Cy = height };
            var origin = new Point();
            var blend = new BlendFunction
            {
                BlendOp = 0,               // AC_SRC_OVER
                BlendFlags = 0,
                SourceConstantAlpha = 255,
                AlphaFormat = 1,           // AC_SRC_ALPHA
            };

            return UpdateLayeredWindow(hwnd, screen, position, size, memory, origin, 0, blend, UlwAlpha);
        }
        finally
        {
            if (previous != IntPtr.Zero)
            {
                SelectObject(memory, previous);
            }

            if (bitmap != IntPtr.Zero)
            {
                DeleteObject(bitmap);
            }

            if (memory != IntPtr.Zero)
            {
                DeleteDC(memory);
            }

            if (screen != IntPtr.Zero)
            {
                ReleaseDC(IntPtr.Zero, screen);
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Win32
    // ---------------------------------------------------------------------------------------------
    private const uint WsPopup = 0x80000000;
    private const uint WsExLayered = 0x00080000;
    private const uint WsExToolWindow = 0x00000080;
    private const uint WsExTopMost = 0x00000008;
    private const uint WsExNoActivate = 0x08000000;
    private const uint UlwAlpha = 0x00000002;
    private const int SwShowNoActivate = 4;
    private const uint SpiGetWorkArea = 0x0030;

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Size
    {
        public int Cx;
        public int Cy;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BlendFunction
    {
        public byte BlendOp;
        public byte BlendFlags;
        public byte SourceConstantAlpha;
        public byte AlphaFormat;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BitmapInfoHeader
    {
        public uint Size;
        public int Width;
        public int Height;
        public ushort Planes;
        public ushort BitCount;
        public uint Compression;
        public uint SizeImage;
        public int XPelsPerMeter;
        public int YPelsPerMeter;
        public uint ClrUsed;
        public uint ClrImportant;
    }

    [LibraryImport("user32.dll", EntryPoint = "CreateWindowExW", StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr CreateWindowExW(
        uint exStyle, string className, string? windowName, uint style,
        int x, int y, int width, int height,
        IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyWindow(IntPtr hwnd);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ShowWindow(IntPtr hwnd, int command);

    [LibraryImport("user32.dll")]
    private static partial uint GetDpiForWindow(IntPtr hwnd);

    [LibraryImport("user32.dll")]
    private static partial IntPtr GetDC(IntPtr hwnd);

    [LibraryImport("user32.dll")]
    private static partial int ReleaseDC(IntPtr hwnd, IntPtr dc);

    [LibraryImport("user32.dll", EntryPoint = "SystemParametersInfoW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SystemParametersInfoW(uint action, uint param, ref Rect data, uint update);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool UpdateLayeredWindow(
        IntPtr hwnd, IntPtr destinationDc, in Point destination, in Size size,
        IntPtr sourceDc, in Point source, uint colorKey, in BlendFunction blend, uint flags);

    [LibraryImport("gdi32.dll")]
    private static partial IntPtr CreateCompatibleDC(IntPtr dc);

    [LibraryImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeleteDC(IntPtr dc);

    [LibraryImport("gdi32.dll")]
    private static partial IntPtr SelectObject(IntPtr dc, IntPtr handle);

    [LibraryImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DeleteObject(IntPtr handle);

    [LibraryImport("gdi32.dll")]
    private static partial IntPtr CreateDIBSection(
        IntPtr dc, in BitmapInfoHeader header, uint usage, out IntPtr bits, IntPtr section, uint offset);
}
