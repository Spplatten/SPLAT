#if MISSIONCONTROLLER_WIN2D

using System.Diagnostics;
using System.Numerics;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Effects;
using Microsoft.Graphics.Canvas.UI;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace MissionController.UI.Effects.Win2D;

/// <summary>
/// Owns a source-free Win2D PixelShaderEffect and attaches it to a CanvasControl.
/// The project-level Win2D props file keeps this implementation behind an
/// explicit compile symbol so a compositor-only build can still be selected.
/// </summary>
public sealed class Win2DShaderCanvasRenderer : IDisposable
{
    private const double AnimationFrameMilliseconds = 16.0;

    private readonly CanvasControl _canvas;
    private readonly byte[] _shaderCode;
    private readonly Stopwatch _clock = new();
    private PixelShaderEffect? _effect;
    private DispatcherQueueTimer? _animationTimer;
    private ShaderFrame _frame = ShaderFrame.Default;
    private bool _disposed;

    public Win2DShaderCanvasRenderer(CanvasControl canvas, byte[] shaderCode)
    {
        ArgumentNullException.ThrowIfNull(canvas);
        ArgumentNullException.ThrowIfNull(shaderCode);
        if (shaderCode.Length == 0)
        {
            throw new ArgumentException("Shader bytecode cannot be empty.", nameof(shaderCode));
        }

        _canvas = canvas;
        _shaderCode = shaderCode.ToArray();
        _canvas.CreateResources += OnCreateResources;
        _canvas.Draw += OnDraw;
        _canvas.Unloaded += OnCanvasUnloaded;
    }

    public bool IsAvailable { get; private set; }

    public Exception? LastError { get; private set; }

    public ShaderFrame Frame => _frame;

    public static Win2DShaderCanvasRenderer FromFile(CanvasControl canvas, string relativePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(relativePath);
        var path = ResolveAssetPath(relativePath);
        return new Win2DShaderCanvasRenderer(canvas, File.ReadAllBytes(path));
    }

    public void SetFrame(ShaderFrame frame)
    {
        VerifyUiThread();
        ThrowIfDisposed();
        var suppliedWeights = frame.Weights;
        var weights = suppliedWeights is { Length: 8 }
            ? suppliedWeights.ToArray()
            : ShaderFrame.Default.EffectiveWeights.ToArray();

        _frame = frame with
        {
            Intensity = Math.Clamp(frame.Intensity, 0.0f, 1.0f),
            Radius = Math.Max(frame.Radius, 0.001f),
            Softness = Math.Max(frame.Softness, 0.001f),
                Color = new Vector4(
                    Math.Clamp(frame.Color.X, 0.0f, 1.0f),
                    Math.Clamp(frame.Color.Y, 0.0f, 1.0f),
                    Math.Clamp(frame.Color.Z, 0.0f, 1.0f),
                    Math.Clamp(frame.Color.W, 0.0f, 1.0f)),
            Weights = weights
        };
        _canvas.Invalidate();
    }

    public void SetNeuralWeights(ReadOnlySpan<float> weights)
    {
        if (weights.Length != 8)
        {
            throw new ArgumentException("The glow shader expects eight scalar style weights.", nameof(weights));
        }

        SetFrame(_frame with { Weights = weights.ToArray() });
    }

    public void StartAnimation()
    {
        VerifyUiThread();
        ThrowIfDisposed();
        if (_animationTimer is not null)
        {
            return;
        }

        _clock.Restart();
        _animationTimer = _canvas.DispatcherQueue.CreateTimer();
        _animationTimer.Interval = TimeSpan.FromMilliseconds(AnimationFrameMilliseconds);
        _animationTimer.IsRepeating = true;
        _animationTimer.Tick += OnAnimationTick;
        _animationTimer.Start();
    }

    public void StopAnimation()
    {
        VerifyUiThread();
        StopAnimationCore();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        StopAnimationCore();
        _canvas.CreateResources -= OnCreateResources;
        _canvas.Draw -= OnDraw;
        _canvas.Unloaded -= OnCanvasUnloaded;
        DisposeEffect();
    }

    private static string ResolveAssetPath(string relativePath)
    {
        if (Path.IsPathRooted(relativePath))
        {
            return relativePath;
        }

        return Path.Combine(AppContext.BaseDirectory, relativePath);
    }

    private void OnCreateResources(CanvasControl sender, CanvasCreateResourcesEventArgs args)
    {
        DisposeEffect();
        IsAvailable = false;
        LastError = null;

        try
        {
            var effect = new PixelShaderEffect(_shaderCode)
            {
                Name = "MissionControllerGlow",
                CacheOutput = false
            };

            if (!effect.IsSupported(sender.Device))
            {
                effect.Dispose();
                LastError = new NotSupportedException("The active CanvasDevice does not support the shader profile.");
                return;
            }

            _effect = effect;
            IsAvailable = true;
        }
        catch (Exception exception)
        {
            LastError = exception;
            DisposeEffect();
        }
    }

    private void OnDraw(CanvasControl sender, CanvasDrawEventArgs args)
    {
        if (_disposed || _effect is null || !IsAvailable || sender.Size.Width <= 0 || sender.Size.Height <= 0)
        {
            return;
        }

        var pixelWidth = Math.Max(1, sender.ConvertDipsToPixels((float)sender.Size.Width, CanvasDpiRounding.Round));
        var pixelHeight = Math.Max(1, sender.ConvertDipsToPixels((float)sender.Size.Height, CanvasDpiRounding.Round));
        var pixelResolution = new Vector2(pixelWidth, pixelHeight);

        // Scene position is expressed in physical pixels while CanvasControl
        // layout and DrawImage bounds are expressed in DIPs; keep that contract
        // explicit so press feedback stays correct on mixed-DPI monitors.
        _effect.Properties["resolution"] = pixelResolution;
        _effect.Properties["time"] = _frame.Time;
        _effect.Properties["intensity"] = _frame.Intensity;
        _effect.Properties["color"] = _frame.Color;
        _effect.Properties["pressOrigin"] = _frame.PressOrigin;
        _effect.Properties["radius"] = _frame.Radius * pixelResolution.X;
        _effect.Properties["softness"] = _frame.Softness * pixelResolution.X;
        _effect.Properties["weights"] = _frame.EffectiveWeights;

        // A source-free PixelShaderEffect derives its output bounds from the
        // current drawing session; this is the supported Win2D path for a
        // procedural image with D2D_INPUT_COUNT set to zero.
        args.DrawingSession.DrawImage(_effect);
    }

    private void OnAnimationTick(DispatcherQueueTimer sender, object args)
    {
        if (_disposed)
        {
            return;
        }

        _frame = _frame with { Time = (float)_clock.Elapsed.TotalSeconds };
        _canvas.Invalidate();
    }

    private void OnCanvasUnloaded(object sender, RoutedEventArgs args)
    {
        StopAnimationCore();
        DisposeEffect();
        IsAvailable = false;
    }

    private void StopAnimationCore()
    {
        if (_animationTimer is null)
        {
            return;
        }

        _animationTimer.Stop();
        _animationTimer.Tick -= OnAnimationTick;
        _animationTimer = null;
        _clock.Reset();
    }

    private void DisposeEffect()
    {
        _effect?.Dispose();
        _effect = null;
    }

    private void VerifyUiThread()
    {
        if (!_canvas.DispatcherQueue.HasThreadAccess)
        {
            throw new InvalidOperationException("Win2D shader state must be changed on the CanvasControl dispatcher thread.");
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}

public readonly record struct ShaderFrame(
    float Time,
    float Intensity,
    Vector4 Color,
    Vector2 PressOrigin,
    float Radius,
    float Softness,
    float[]? Weights = null)
{
    public float[] EffectiveWeights => Weights ?? DefaultWeights;

    private static float[] DefaultWeights => new[]
    {
        0.72f, 0.58f, 0.18f, 0.82f, 0.42f, 0.34f, 0.0f, 0.0f
    };

    public static ShaderFrame Default => new(
        Time: 0.0f,
        Intensity: 0.0f,
        Color: new Vector4(0.30f, 0.76f, 1.0f, 1.0f),
        PressOrigin: new Vector2(0.5f, 0.5f),
        Radius: 0.42f,
        Softness: 0.34f,
        // Eight scalar weights leave a small constant-buffer seam for a
        // learned style/material profile without forcing a neural pass on
        // every frame when the compositor fallback is sufficient.
        Weights: DefaultWeights);
}

#endif
