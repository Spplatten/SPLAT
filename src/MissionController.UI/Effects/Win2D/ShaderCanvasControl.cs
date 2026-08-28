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
            var shaderPath = System.IO.Path.Combine(AppContext.BaseDirectory, "Effects", "Win2D", "MissionControllerGlow.bin");
            if (System.IO.File.Exists(shaderPath))
            {
                _renderer = Win2DShaderCanvasRenderer.FromFile(_canvas, shaderPath);
            }
            else
            {
                // Fallback: minimal dummy bytecode if .bin not compiled yet
                return;
            }

            UpdateShaderFrame();

        }
        catch
        {
            // Fail open on environments without compiled bytecode or unsupported GPU profiles
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
