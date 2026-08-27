using System;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace MissionController.UI.Graphics;

/// <summary>
/// Owns the WinUI lifecycle around a native DXGI swap chain without owning the
/// D3D device or the COM reference represented by the swap-chain pointer.
/// </summary>
public sealed class SwapChainPanelHost : SwapChainPanel, ISwapChainRenderSurface, IDisposable
{
    private readonly ISwapChainPanelNativeBridge _nativeBridge;
    private ISwapChainRenderBackend? _backend;
    private SwapChainSurfaceMetrics _surfaceMetrics;
    private nint _swapChain;
    private bool _isNativeBindingActive;
    private bool _isBackendAttached;
    private bool _isLoaded;
    private bool _isDisposed;

    public SwapChainPanelHost()
        : this(new ComSwapChainPanelNativeBridge())
    {
    }

    // The bridge is injectable so lifecycle, device-loss, and unsupported-platform
    // paths can be exercised without constructing a D3D device in unit tests.
    public SwapChainPanelHost(ISwapChainPanelNativeBridge nativeBridge)
    {
        _nativeBridge = nativeBridge ?? throw new ArgumentNullException(nameof(nativeBridge));
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
        SizeChanged += OnSizeChanged;
        CompositionScaleChanged += OnCompositionScaleChanged;
        _surfaceMetrics = ReadSurfaceMetrics();
    }

    public event EventHandler<SwapChainSurfaceMetricsChangedEventArgs>? SurfaceMetricsChanged;

    public event EventHandler? BackendAttached;

    public event EventHandler? BackendDetached;

    public event EventHandler<SwapChainInteropErrorEventArgs>? InteropError;

    public ISwapChainRenderBackend? Backend => _backend;

    public SwapChainSurfaceMetrics SurfaceMetrics => _surfaceMetrics;

    public bool IsSurfaceLoaded => _isLoaded;

    public bool IsSwapChainBound => _isNativeBindingActive;

    public nint SwapChainPointer => _swapChain;

    SwapChainPanel ISwapChainRenderSurface.Panel => this;

    public void AttachBackend(ISwapChainRenderBackend backend)
    {
        ArgumentNullException.ThrowIfNull(backend);
        VerifyUiThread();
        ThrowIfDisposed();

        if (ReferenceEquals(_backend, backend))
        {
            return;
        }

        DetachBackend();
        _backend = backend;

        if (_isLoaded)
        {
            AttachBackendToSurface();
        }
    }

    public void DetachBackend()
    {
        VerifyUiThread();

        if (_backend is null)
        {
            return;
        }

        if (_isBackendAttached)
        {
            _backend.Detach();
            _isBackendAttached = false;
            BackendDetached?.Invoke(this, EventArgs.Empty);
        }

        _backend = null;
    }

    /// <summary>
    /// Stores and, when loaded, binds a borrowed IDXGISwapChain pointer. The
    /// backend remains responsible for keeping the COM object alive.
    /// </summary>
    public void SetSwapChain(nint swapChain)
    {
        VerifyUiThread();
        ThrowIfDisposed();

        // A failed native bind must remain retryable when the backend recovers
        // or replaces a transiently invalid device pointer.
        if (_swapChain == swapChain && (!_isLoaded || _isNativeBindingActive || swapChain == nint.Zero))
        {
            return;
        }

        _swapChain = swapChain;

        if (_isLoaded)
        {
            // Rebind on pointer replacement; SetSwapChain cannot atomically
            // replace an existing native target, so clear the old target first.
            if (_isNativeBindingActive)
            {
                TryUnbindSwapChain();
            }

            BindCurrentSwapChain();
        }
    }

    public void ClearSwapChain()
    {
        SetSwapChain(nint.Zero);
    }

    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        VerifyUiThread();
        _isDisposed = true;
        Loaded -= OnLoaded;
        Unloaded -= OnUnloaded;
        SizeChanged -= OnSizeChanged;
        CompositionScaleChanged -= OnCompositionScaleChanged;

        if (_isNativeBindingActive)
        {
            TryUnbindSwapChain();
        }

        if (_isBackendAttached)
        {
            _backend?.Detach();
            _isBackendAttached = false;
        }

        _backend = null;
        _swapChain = nint.Zero;
    }

    private void OnLoaded(object sender, RoutedEventArgs args)
    {
        if (_isDisposed)
        {
            return;
        }

        _isLoaded = true;
        UpdateSurfaceMetrics();
        BindCurrentSwapChain();
        AttachBackendToSurface();
    }

    private void OnUnloaded(object sender, RoutedEventArgs args)
    {
        if (_isDisposed)
        {
            return;
        }

        _isLoaded = false;

        // Stop the backend before releasing the panel's native binding. This
        // prevents a render thread from presenting into a detached XAML target.
        if (_isBackendAttached)
        {
            _backend?.Detach();
            _isBackendAttached = false;
            BackendDetached?.Invoke(this, EventArgs.Empty);
        }

        TryUnbindSwapChain();
    }

    private void OnSizeChanged(object sender, SizeChangedEventArgs args) => UpdateSurfaceMetrics();

    private void OnCompositionScaleChanged(SwapChainPanel sender, object args) => UpdateSurfaceMetrics();

    private void AttachBackendToSurface()
    {
        if (!_isLoaded || _isBackendAttached || _backend is null)
        {
            return;
        }

        _backend.Attach(this);
        _backend.Resize(_surfaceMetrics);
        _isBackendAttached = true;
        BackendAttached?.Invoke(this, EventArgs.Empty);
    }

    private void UpdateSurfaceMetrics()
    {
        var next = ReadSurfaceMetrics();
        if (next == _surfaceMetrics)
        {
            return;
        }

        var previous = _surfaceMetrics;
        _surfaceMetrics = next;
        if (_isBackendAttached)
        {
            _backend?.Resize(next);
        }

        SurfaceMetricsChanged?.Invoke(this, new SwapChainSurfaceMetricsChangedEventArgs(previous, next));
    }

    private SwapChainSurfaceMetrics ReadSurfaceMetrics()
    {
        var scaleX = Math.Max(CompositionScaleX, 0.01f);
        var scaleY = Math.Max(CompositionScaleY, 0.01f);
        var logicalWidth = Math.Max(ActualWidth, 0d);
        var logicalHeight = Math.Max(ActualHeight, 0d);
        return SwapChainSurfaceMetrics.FromLogicalSize(logicalWidth, logicalHeight, scaleX, scaleY);
    }

    private void BindCurrentSwapChain()
    {
        if (!_isLoaded || _isNativeBindingActive || _swapChain == nint.Zero)
        {
            return;
        }

        var hResult = _nativeBridge.SetSwapChain(this, _swapChain);
        if (hResult < 0)
        {
            InteropError?.Invoke(this, new SwapChainInteropErrorEventArgs(hResult, "SetSwapChain"));
            Marshal.ThrowExceptionForHR(hResult);
        }

        _isNativeBindingActive = true;
    }

    private void TryUnbindSwapChain()
    {
        if (!_isNativeBindingActive)
        {
            return;
        }

        var hResult = _nativeBridge.SetSwapChain(this, nint.Zero);
        _isNativeBindingActive = false;
        if (hResult < 0)
        {
            InteropError?.Invoke(this, new SwapChainInteropErrorEventArgs(hResult, "ClearSwapChain"));
        }
    }

    private void VerifyUiThread()
    {
        if (!DispatcherQueue.HasThreadAccess)
        {
            throw new InvalidOperationException("SwapChainPanelHost must be accessed from its UI thread.");
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_isDisposed, this);
    }
}

/// <summary>
/// Native backend contract. Implementations create/manage the D3D device,
/// swap chain, render thread, and shader resources; the host only coordinates
/// XAML attachment and surface lifetime.
/// </summary>
public interface ISwapChainRenderBackend
{
    void Attach(ISwapChainRenderSurface surface);

    void Resize(SwapChainSurfaceMetrics metrics);

    void Detach();
}

public interface ISwapChainRenderSurface
{
    SwapChainPanel Panel { get; }

    SwapChainSurfaceMetrics SurfaceMetrics { get; }

    bool IsSurfaceLoaded { get; }

    nint SwapChainPointer { get; }

    bool IsSwapChainBound { get; }

    void SetSwapChain(nint swapChain);

    void ClearSwapChain();
}

public readonly record struct SwapChainSurfaceMetrics(
    double LogicalWidth,
    double LogicalHeight,
    float CompositionScaleX,
    float CompositionScaleY,
    uint PixelWidth,
    uint PixelHeight)
{
    public static SwapChainSurfaceMetrics FromLogicalSize(
        double logicalWidth,
        double logicalHeight,
        float compositionScaleX,
        float compositionScaleY)
    {
        return new SwapChainSurfaceMetrics(
            logicalWidth,
            logicalHeight,
            compositionScaleX,
            compositionScaleY,
            ToPixelSize(logicalWidth, compositionScaleX),
            ToPixelSize(logicalHeight, compositionScaleY));
    }

    private static uint ToPixelSize(double logicalSize, float scale)
    {
        var pixels = Math.Ceiling(Math.Max(logicalSize, 0d) * Math.Max(scale, 0.01f));
        return pixels >= uint.MaxValue ? uint.MaxValue : (uint)pixels;
    }
}

public sealed class SwapChainSurfaceMetricsChangedEventArgs : EventArgs
{
    public SwapChainSurfaceMetricsChangedEventArgs(
        SwapChainSurfaceMetrics previous,
        SwapChainSurfaceMetrics current)
    {
        Previous = previous;
        Current = current;
    }

    public SwapChainSurfaceMetrics Previous { get; }

    public SwapChainSurfaceMetrics Current { get; }
}

public sealed class SwapChainInteropErrorEventArgs : EventArgs
{
    public SwapChainInteropErrorEventArgs(int hResult, string operation)
    {
        HResult = hResult;
        Operation = operation;
    }

    public int HResult { get; }

    public string Operation { get; }
}

public interface ISwapChainPanelNativeBridge
{
    int SetSwapChain(SwapChainPanel panel, nint swapChain);
}

/// <summary>
/// ABI adapter for the WinUI 3 SwapChainPanel native interface. The pointer is
/// borrowed: SetSwapChain does not transfer ownership to this adapter.
/// </summary>
public sealed class ComSwapChainPanelNativeBridge : ISwapChainPanelNativeBridge
{
    public int SetSwapChain(SwapChainPanel panel, nint swapChain)
    {
        ArgumentNullException.ThrowIfNull(panel);
        nint panelUnknown = nint.Zero;
        nint nativePanel = nint.Zero;
        try
        {
            // WinUI 3 projects a WinRT IInspectable; QueryInterface is the
            // stable ABI route to the Microsoft.UI.Xaml native companion.
            panelUnknown = Marshal.GetIUnknownForObject(panel);
            var interfaceId = typeof(ISwapChainPanelNative).GUID;
            var queryResult = Marshal.QueryInterface(panelUnknown, in interfaceId, out nativePanel);
            if (queryResult < 0)
            {
                return queryResult;
            }

            var native = (ISwapChainPanelNative)Marshal.GetObjectForIUnknown(nativePanel);
            return native.SetSwapChain(swapChain);
        }
        catch (InvalidCastException)
        {
            // Keep unsupported hosts on the HRESULT path so callers can select
            // a compositor/XAML fallback instead of crashing on a cast.
            return unchecked((int)0x80004002); // E_NOINTERFACE
        }
        finally
        {
            if (nativePanel != nint.Zero)
            {
                Marshal.Release(nativePanel);
            }

            if (panelUnknown != nint.Zero)
            {
                Marshal.Release(panelUnknown);
            }
        }
    }

    [ComImport]
    [Guid("63AAD0B8-7C24-40FF-85A8-640D944CC325")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface ISwapChainPanelNative
    {
        [PreserveSig]
        int SetSwapChain(nint swapChain);
    }
}
