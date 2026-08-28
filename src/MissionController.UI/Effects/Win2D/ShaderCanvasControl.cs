#if MISSIONCONTROLLER_WIN2D

using System;
using System.Numerics;
using Microsoft.Graphics.Canvas.UI.Xaml;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.UI;

namespace MissionController.UI.Effects.Win2D;

/// <summary>
/// High-performance WinUI 3 control that hosts procedural HLSL custom shaders
/// (Radar, Cyberspace Grid, Electric Shield, Neural Synapse, Aurora, Glow) via Win2D.
/// </summary>
public sealed class ShaderCanvasControl : UserControl, IDisposable
{
    public static readonly DependencyProperty ModeProperty = DependencyProperty.Register(
        nameof(Mode),
        typeof(ShaderEffectMode),
        typeof(ShaderCanvasControl),
        new PropertyMetadata(ShaderEffectMode.Glow, OnPropertyChanged));

    public static readonly DependencyProperty IntensityProperty = DependencyProperty.Register(
        nameof(Intensity),
        typeof(double),
        typeof(ShaderCanvasControl),
        new PropertyMetadata(0.75, OnPropertyChanged));

    public static readonly DependencyProperty PrimaryColorProperty = DependencyProperty.Register(
        nameof(PrimaryColor),
        typeof(Color),
        typeof(ShaderCanvasControl),
        new PropertyMetadata(Color.FromArgb(255, 0, 229, 255), OnPropertyChanged));

    public static readonly DependencyProperty AccentColorProperty = DependencyProperty.Register(
        nameof(AccentColor),
        typeof(Color),
        typeof(ShaderCanvasControl),
        new PropertyMetadata(Color.FromArgb(255, 210, 155, 255), OnPropertyChanged));

    public static readonly DependencyProperty IsAnimatedProperty = DependencyProperty.Register(
        nameof(IsAnimated),
        typeof(bool),
        typeof(ShaderCanvasControl),
        new PropertyMetadata(true, OnIsAnimatedChanged));

    private readonly CanvasControl _canvas;
    private Win2DShaderCanvasRenderer? _renderer;
    private bool _isDisposed;

    public ShaderCanvasControl()
    {
        _canvas = new CanvasControl();
        Content = _canvas;

        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    public ShaderEffectMode Mode
    {
        get => (ShaderEffectMode)GetValue(ModeProperty);
        set => SetValue(ModeProperty, value);
    }

    public double Intensity
    {
        get => (double)GetValue(IntensityProperty);
        set => SetValue(IntensityProperty, value);
    }

    public Color PrimaryColor
    {
        get => (Color)GetValue(PrimaryColorProperty);
        set => SetValue(PrimaryColorProperty, value);
    }

    public Color AccentColor
    {
        get => (Color)GetValue(AccentColorProperty);
        set => SetValue(AccentColorProperty, value);
    }

    public bool IsAnimated
    {
        get => (bool)GetValue(IsAnimatedProperty);
        set => SetValue(IsAnimatedProperty, value);
    }

    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }

        _isDisposed = true;
        Loaded -= OnLoaded;
        Unloaded -= OnUnloaded;
        _renderer?.Dispose();
        _renderer = null;
        _canvas.RemoveFromVisualTree();
    }

    private void OnLoaded(object sender, RoutedEventArgs args)
    {
        InitializeRenderer();
        if (_renderer is not null && IsAnimated)
        {
            // Canvas controls can leave and re-enter the visual tree during
            // navigation; resume the renderer that Unloaded intentionally stopped.
            _renderer.StartAnimation();
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs args)
    {
        _renderer?.StopAnimation();
    }

    private void InitializeRenderer()
    {
        if (_renderer is not null || _isDisposed)
        {
            return;
        }

        try
        {
            var directory = System.IO.Path.Combine(AppContext.BaseDirectory, "Effects", "Win2D");
            var shaderPath = System.IO.Path.Combine(directory, ResolveShaderFileName(Mode));

            // Modes 0-3 live inside the Glow mega-shader and are selected by its "mode" constant, so
            // fall back to it whenever a dedicated shader is missing rather than rendering nothing.
            if (!System.IO.File.Exists(shaderPath))
            {
                shaderPath = System.IO.Path.Combine(directory, GlowShaderFileName);
            }

            if (!System.IO.File.Exists(shaderPath))
            {
                // No compiled bytecode at all. The build only produces it where the Windows SDK
                // shader compiler exists, so this stays a silent no-op rather than a hard failure.
                return;
            }

            _renderer = Win2DShaderCanvasRenderer.FromFile(_canvas, shaderPath);
            _loadedModeShader = shaderPath;

            UpdateShaderFrame();
        }
        catch
        {
            // Fail open on environments without compiled bytecode or unsupported GPU profiles
        }
    }

    private const string GlowShaderFileName = "MissionControllerGlow.bin";

    /// <summary>Bytecode currently bound, so a Mode change knows whether it must rebuild.</summary>
    private string? _loadedModeShader;

    /// <summary>
    /// Maps a mode to its dedicated bytecode. RadarScan, CyberGrid, ElectricShield and NeuralSynapse
    /// are standalone shaders; the remaining modes are branches inside the Glow mega-shader.
    /// </summary>
    private static string ResolveShaderFileName(ShaderEffectMode mode) => mode switch
    {
        ShaderEffectMode.RadarScan => "MissionControllerRadarScan.bin",
        ShaderEffectMode.CyberGrid => "MissionControllerCyberGrid.bin",
        ShaderEffectMode.ElectricShield => "MissionControllerElectricShield.bin",
        ShaderEffectMode.NeuralSynapse => "MissionControllerNeuralSynapse.bin",
        _ => GlowShaderFileName
    };

    /// <summary>
    /// Swapping mode can mean swapping bytecode, which the renderer takes at construction. Rebuild
    /// only when the target file actually changes so mode flips within the mega-shader stay cheap.
    /// </summary>
    private void ReloadRendererIfShaderChanged()
    {
        if (_isDisposed)
        {
            return;
        }

        var expected = System.IO.Path.Combine(AppContext.BaseDirectory, "Effects", "Win2D", ResolveShaderFileName(Mode));
        if (!System.IO.File.Exists(expected))
        {
            expected = System.IO.Path.Combine(AppContext.BaseDirectory, "Effects", "Win2D", GlowShaderFileName);
        }

        if (string.Equals(_loadedModeShader, expected, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        bool wasAnimating = IsAnimated;
        _renderer?.Dispose();
        _renderer = null;
        _loadedModeShader = null;

        InitializeRenderer();

        if (_renderer is not null && wasAnimating)
        {
            _renderer.StartAnimation();
        }
    }

    private void UpdateShaderFrame()
    {
        if (_renderer is null)
        {
            return;
        }

        var pCol = PrimaryColor;
        var aCol = AccentColor;

        var frame = _renderer.Frame with
        {
            Mode = Mode,
            Intensity = (float)Math.Clamp(Intensity, 0.0, 1.0),
            Color = new Vector4(pCol.R / 255f, pCol.G / 255f, pCol.B / 255f, pCol.A / 255f),
            AccentColor = new Vector4(aCol.R / 255f, aCol.G / 255f, aCol.B / 255f, aCol.A / 255f)
        };

        _renderer.SetFrame(frame);
    }

    private static void OnPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ShaderCanvasControl control)
        {
            // A Mode change may point at different bytecode, which is bound at renderer construction.
            if (e.Property == ModeProperty)
            {
                control.ReloadRendererIfShaderChanged();
            }

            control.UpdateShaderFrame();
        }
    }

    private static void OnIsAnimatedChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is ShaderCanvasControl control && control._renderer is not null)
        {
            if ((bool)e.NewValue)
            {
                control._renderer.StartAnimation();
            }
            else
            {
                control._renderer.StopAnimation();
            }
        }
    }
}

#endif
