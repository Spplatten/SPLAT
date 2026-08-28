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

public enum ShaderEffectMode
{
    Glow = 0,
    Aurora = 1,
    ScanSweep = 2,
    GlassNoise = 3,
    RadarScan = 4,
    CyberGrid = 5,
    ElectricShield = 6,
    NeuralSynapse = 7
}

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
        for (var index = 0; index < weights.Length; index++)
        {
            weights[index] = ClampFinite(weights[index], -2.0f, 2.0f, 0.0f);
        }

        var primaryColor = ClampColor(frame.Color, ShaderFrame.DefaultColor);
        var secondaryColor = ClampColor(frame.AccentColor, ShaderFrame.DefaultAccentColor);

        _frame = frame with
        {
            Time = NormalizeTime(frame.Time),
            Mode = NormalizeMode(frame.Mode),
            Intensity = ClampFinite(frame.Intensity, 0.0f, 1.0f, 0.0f),
            Radius = ClampFinite(frame.Radius, 0.001f, 1.5f, 0.42f),
            Softness = ClampFinite(frame.Softness, 0.001f, 1.5f, 0.34f),
            PressOrigin = new Vector2(
                ClampFinite(frame.PressOrigin.X, 0.0f, 1.0f, 0.5f),
                ClampFinite(frame.PressOrigin.Y, 0.0f, 1.0f, 0.5f)),
            Color = primaryColor,
            AccentColor = secondaryColor,
            Weights = weights
        };
        _canvas.Invalidate();
    }

    public void SetMode(ShaderEffectMode mode)
    {
        SetFrame(_frame with { Mode = mode });
    }

    public void SetNeuralWeights(ReadOnlySpan<float> weights)
    {
        if (weights.Length != 8)
        {
            throw new ArgumentException("The appearance shader expects eight scalar style weights.", nameof(weights));
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
                Name = "MissionControllerAppearance",
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
        // The shader measures distance in normalized UV space, so radius and
        // softness remain resolution-independent on mixed-DPI monitors.
        _effect.Properties["radius"] = _frame.Radius;
        _effect.Properties["softness"] = _frame.Softness;
        _effect.Properties["mode"] = (int)_frame.Mode;
        _effect.Properties["accentColor"] = _frame.AccentColor;
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

    private static float NormalizeTime(float time)
    {
        if (!float.IsFinite(time))
        {
            return 0.0f;
        }

        var wrappedTime = time % 3600.0f;
        return wrappedTime < 0.0f ? wrappedTime + 3600.0f : wrappedTime;
    }

    private static Vector4 ClampColor(Vector4 color, Vector4 fallback)
    {
        if (!float.IsFinite(color.W) || color.W <= 0.0f)
        {
            color = fallback;
        }

        return new Vector4(
            ClampFinite(color.X, 0.0f, 1.0f, fallback.X),
            ClampFinite(color.Y, 0.0f, 1.0f, fallback.Y),
            ClampFinite(color.Z, 0.0f, 1.0f, fallback.Z),
            ClampFinite(color.W, 0.0f, 1.0f, fallback.W));
    }

    private static float ClampFinite(float value, float minimum, float maximum, float fallback)
    {
        return float.IsFinite(value) ? Math.Clamp(value, minimum, maximum) : fallback;
    }

    private static ShaderEffectMode NormalizeMode(ShaderEffectMode mode)
    {
        return Enum.IsDefined(typeof(ShaderEffectMode), mode) ? mode : ShaderEffectMode.Glow;
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
    float[]? Weights = null,
    Vector4 AccentColor = default,
    ShaderEffectMode Mode = ShaderEffectMode.Glow)
{
    public static readonly Vector4 DefaultColor = new(0.30f, 0.76f, 1.0f, 1.0f);

    public static readonly Vector4 DefaultAccentColor = new(0.82f, 0.34f, 1.0f, 1.0f);

    public float[] EffectiveWeights => Weights ?? DefaultWeights;

    private static float[] DefaultWeights => new[]
    {
        0.72f, 0.58f, 0.18f, 0.82f, 0.42f, 0.34f, 0.0f, 0.0f
    };

    public static ShaderFrame Default => new(
        Time: 0.0f,
        Intensity: 0.0f,
        Color: DefaultColor,
        PressOrigin: new Vector2(0.5f, 0.5f),
        Radius: 0.42f,
        Softness: 0.34f,
        // Eight scalar weights leave a small constant-buffer seam for a
        // learned style/material profile without forcing a neural pass on
        // every frame when the compositor fallback is sufficient.
        Weights: DefaultWeights,
        AccentColor: DefaultAccentColor,
        Mode: ShaderEffectMode.Glow);
}

#endif
