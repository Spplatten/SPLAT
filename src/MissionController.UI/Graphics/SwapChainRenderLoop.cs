using System.Diagnostics;

namespace MissionController.UI.Graphics;

/// <summary>
/// The presentation contract shared by a D3D11/12 backend and the XAML host.
/// Keeping this value object independent of a specific native wrapper lets the
/// backend choose Vortice, C++/WinRT, or an existing engine without leaking
/// device types into the UI assembly.
/// </summary>
public enum SwapChainSwapEffect
{
    // Maps to DXGI_SWAP_EFFECT_FLIP_DISCARD in the native D3D backend.
    FlipDiscard
}

public readonly record struct SwapChainPresentationOptions(
    SwapChainSwapEffect SwapEffect,
    uint BufferCount,
    bool AllowTearing,
    int PresentInterval)
{
    public static SwapChainPresentationOptions FlipDiscard60Hz => new(
        SwapEffect: SwapChainSwapEffect.FlipDiscard,
        BufferCount: 2,
        AllowTearing: false,
        PresentInterval: 1);
}

public readonly record struct SwapChainRenderFrame(
    long FrameIndex,
    TimeSpan Elapsed,
    SwapChainSurfaceMetrics Surface,
    SwapChainPresentationOptions Presentation);

/// <summary>
/// Rendering work is deliberately supplied by the native backend. The loop
/// owns cadence and cancellation, while the renderer owns D3D device/context,
/// HLSL resources, Present, and device-loss recovery.
/// </summary>
public interface ISwapChainFrameRenderer
{
    void Render(in SwapChainRenderFrame frame);

    void OnDeviceLost(Exception error);
}

/// <summary>
/// Runs frame production away from the XAML thread and provides a stable seam
/// for a D3D11/12 implementation to create a flip-model swap chain and present
/// HLSL/compute passes. No native device is created by this managed host.
/// </summary>
public sealed class SwapChainRenderLoop : ISwapChainRenderBackend, IDisposable
{
    private readonly object _gate = new();
    private readonly ISwapChainFrameRenderer _renderer;
    private readonly SwapChainPresentationOptions _presentation;
    private readonly Stopwatch _clock = new();
    private TimeSpan _frameInterval = TimeSpan.FromMilliseconds(16.6667);
    private ISwapChainRenderSurface? _surface;
    private SwapChainSurfaceMetrics _metrics;
    private CancellationTokenSource? _cancellation;
    private Task? _renderTask;
    private long _frameIndex;
    private bool _disposed;

    public SwapChainRenderLoop(
        ISwapChainFrameRenderer renderer,
        SwapChainPresentationOptions? presentation = null)
    {
        _renderer = renderer ?? throw new ArgumentNullException(nameof(renderer));
        _presentation = presentation ?? SwapChainPresentationOptions.FlipDiscard60Hz;
        if (_presentation.BufferCount < 2)
        {
            throw new ArgumentOutOfRangeException(nameof(presentation), "Flip-model swap chains require at least two buffers.");
        }
    }

    public event EventHandler<SwapChainRenderLoopErrorEventArgs>? Error;

    public TimeSpan FrameInterval
    {
        get => _frameInterval;
        set
        {
            if (value < TimeSpan.FromMilliseconds(1))
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Frame interval must be at least one millisecond.");
            }

            _frameInterval = value;
        }
    }

    public bool IsRunning
    {
        get
        {
            lock (_gate)
            {
                return _renderTask is { IsCompleted: false };
            }
        }
    }

    public SwapChainPresentationOptions Presentation => _presentation;

    public void Attach(ISwapChainRenderSurface surface)
    {
        ArgumentNullException.ThrowIfNull(surface);
        lock (_gate)
        {
            ThrowIfDisposed();
            if (ReferenceEquals(_surface, surface) && _renderTask is { IsCompleted: false })
            {
                return;
            }

            if (_renderTask is { IsCompleted: true } completedTask)
            {
                var completedCancellation = _cancellation;
                _cancellation = null;
                _renderTask = null;
                _ = StopAsync(completedCancellation, completedTask);
            }

            _surface = surface;
            _metrics = surface.SurfaceMetrics;
            StartLocked();
        }
    }

    public void Resize(SwapChainSurfaceMetrics metrics)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            _metrics = metrics;
        }
    }

    public void Detach()
    {
        CancellationTokenSource? cancellation;
        Task? renderTask;

        lock (_gate)
        {
            cancellation = _cancellation;
            renderTask = _renderTask;
            _cancellation = null;
            _renderTask = null;
            _surface = null;
            _clock.Stop();
        }

        _ = StopAsync(cancellation, renderTask);
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
        }

        Detach();
    }

    private void StartLocked()
    {
        if (_renderTask is { IsCompleted: false })
        {
            return;
        }

        _cancellation = new CancellationTokenSource();
        _clock.Restart();
        _frameIndex = 0;
        var token = _cancellation.Token;
        _renderTask = Task.Run(() => RenderAsync(token), token);
    }

    private async Task RenderAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(FrameInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                SwapChainSurfaceMetrics metrics;
                lock (_gate)
                {
                    if (_surface is null || _disposed)
                    {
                        return;
                    }

                    metrics = _metrics;
                }

                var frame = new SwapChainRenderFrame(
                    FrameIndex: Interlocked.Increment(ref _frameIndex),
                    Elapsed: _clock.Elapsed,
                    Surface: metrics,
                    Presentation: _presentation);

                try
                {
                    _renderer.Render(in frame);
                }
                catch (Exception error)
                {
                    _renderer.OnDeviceLost(error);
                    Error?.Invoke(this, new SwapChainRenderLoopErrorEventArgs(frame, error));
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Detach is the normal lifecycle path; cancellation is not a render error.
        }
    }

    private static async Task StopAsync(
        CancellationTokenSource? cancellation,
        Task? renderTask)
    {
        if (cancellation is null)
        {
            return;
        }

        cancellation.Cancel();
        if (renderTask is not null)
        {
            try
            {
                await renderTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // The loop observes cancellation before the task completes.
            }
        }

        cancellation.Dispose();
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);
}

public sealed class SwapChainRenderLoopErrorEventArgs : EventArgs
{
    public SwapChainRenderLoopErrorEventArgs(SwapChainRenderFrame frame, Exception error)
    {
        Frame = frame;
        Error = error;
    }

    public SwapChainRenderFrame Frame { get; }

    public Exception Error { get; }
}
