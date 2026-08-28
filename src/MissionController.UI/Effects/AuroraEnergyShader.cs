using System;
using System.Collections.Generic;
using System.Numerics;
using Microsoft.Graphics.Canvas;
using Microsoft.Graphics.Canvas.Geometry;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace MissionController.UI.Effects;

/// <summary>
/// Travelling electric charge for the single most important button on a screen.
///
/// A band of blue light sweeps left to right with lightning arcing inside it. The glow and the bolts
/// live in ONE container visual whose offset is animated, so they travel together by construction -
/// animating them separately would let them drift out of phase, and a bolt trailing behind its own
/// glow reads as broken immediately.
///
/// Built on the Composition visual layer, with Win2D used only to build path geometry. The
/// Effects\Win2D HLSL pipeline is deliberately not used: it needs fxc.exe to produce bytecode, is
/// opt-in behind EnableMissionControllerWin2DShaderBuild, and silently renders nothing when that
/// bytecode is absent. Geometry and composition animations need no build-time toolchain.
/// </summary>
public static class AuroraEnergyShader
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled",
        typeof(bool),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(false, OnIsEnabledChanged));

    /// <summary>Hot core of the charge - the near-white crest at the centre of the band.</summary>
    public static readonly DependencyProperty CrestColorProperty = DependencyProperty.RegisterAttached(
        "CrestColor",
        typeof(Color),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(Color.FromArgb(255, 190, 248, 255)));

    /// <summary>Body of the charge - the saturated blue that gives the band its depth.</summary>
    public static readonly DependencyProperty DeepColorProperty = DependencyProperty.RegisterAttached(
        "DeepColor",
        typeof(Color),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(Color.FromArgb(255, 0, 132, 255)));

    /// <summary>Seconds for one full traversal of the button.</summary>
    public static readonly DependencyProperty SweepSecondsProperty = DependencyProperty.RegisterAttached(
        "SweepSeconds",
        typeof(double),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(2.4));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(ChargeController),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(null));

    public static bool GetIsEnabled(DependencyObject element) => (bool)element.GetValue(IsEnabledProperty);
    public static void SetIsEnabled(DependencyObject element, bool value) => element.SetValue(IsEnabledProperty, value);

    public static Color GetCrestColor(DependencyObject element) => (Color)element.GetValue(CrestColorProperty);
    public static void SetCrestColor(DependencyObject element, Color value) => element.SetValue(CrestColorProperty, value);

    public static Color GetDeepColor(DependencyObject element) => (Color)element.GetValue(DeepColorProperty);
    public static void SetDeepColor(DependencyObject element, Color value) => element.SetValue(DeepColorProperty, value);

    public static double GetSweepSeconds(DependencyObject element) => (double)element.GetValue(SweepSecondsProperty);
    public static void SetSweepSeconds(DependencyObject element, double value) => element.SetValue(SweepSecondsProperty, value);

    private static void OnIsEnabledChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        if (sender is not FrameworkElement element)
        {
            return;
        }

        if ((bool)args.NewValue)
        {
            if (element.GetValue(ControllerProperty) is null)
            {
                element.SetValue(ControllerProperty, new ChargeController(element));
            }
        }
        else if (element.GetValue(ControllerProperty) is ChargeController controller)
        {
            controller.Dispose();
            element.ClearValue(ControllerProperty);
        }
    }

    private sealed class ChargeController : IDisposable
    {
        private static readonly UISettings AccessibilitySettings = new();

        private readonly FrameworkElement _element;
        private ContainerVisual? _root;
        private ContainerVisual? _band;
        private CompositionRoundedRectangleGeometry? _clipGeometry;
        private float _builtForWidth;
        private float _builtForHeight;

        // The charge composites ABOVE the button content, so its resting alpha stays low enough that
        // the label underneath keeps its contrast. Pointer states lift it, they do not double it.
        private const float IdleOpacity = 0.62f;
        private const float HoverOpacity = 1.0f;
        private const float PressOpacity = 1.0f;

        // Band width as a fraction of button width. Narrow enough to read as a discrete charge
        // crossing the surface rather than a wash over the whole button.
        private const float BandWidthFactor = 0.42f;

        private const int BoltCount = 3;

        public ChargeController(FrameworkElement element)
        {
            _element = element;
            _element.Loaded += OnLoaded;
            _element.Unloaded += OnUnloaded;
            _element.SizeChanged += OnSizeChanged;
            _element.PointerEntered += OnPointerEntered;
            _element.PointerExited += OnPointerExited;
            _element.PointerPressed += OnPointerPressed;
            _element.PointerReleased += OnPointerReleased;

            if (_element.IsLoaded)
            {
                BuildScene();
            }
        }

        public void Dispose()
        {
            _element.Loaded -= OnLoaded;
            _element.Unloaded -= OnUnloaded;
            _element.SizeChanged -= OnSizeChanged;
            _element.PointerEntered -= OnPointerEntered;
            _element.PointerExited -= OnPointerExited;
            _element.PointerPressed -= OnPointerPressed;
            _element.PointerReleased -= OnPointerReleased;
            ReleaseScene();
        }

        private void OnLoaded(object sender, RoutedEventArgs args) => BuildScene();

        private void OnUnloaded(object sender, RoutedEventArgs args) => ReleaseScene();

        private void OnSizeChanged(object sender, SizeChangedEventArgs args) => BuildScene();

        private void OnPointerEntered(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(HoverOpacity, TimeSpan.FromMilliseconds(160));

        private void OnPointerExited(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(IdleOpacity, TimeSpan.FromMilliseconds(320));

        private void OnPointerPressed(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(PressOpacity, TimeSpan.FromMilliseconds(80));

        private void OnPointerReleased(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(HoverOpacity, TimeSpan.FromMilliseconds(200));

        /// <summary>
        /// Bolt geometry is built in pixels, so the scene is rebuilt when the button resizes rather
        /// than scaled - stretched lightning looks like a smear.
        /// </summary>
        private void BuildScene()
        {
            float width = (float)_element.ActualWidth;
            float height = (float)_element.ActualHeight;

            if (width <= 1 || height <= 1 || IsHighContrastEnabled())
            {
                return;
            }

            if (_root is not null &&
                Math.Abs(width - _builtForWidth) < 0.5f &&
                Math.Abs(height - _builtForHeight) < 0.5f)
            {
                return;
            }

            ReleaseScene();

            try
            {
                var hostVisual = ElementCompositionPreview.GetElementVisual(_element);
                var compositor = hostVisual?.Compositor;
                if (compositor is null)
                {
                    return;
                }

                var crest = GetCrestColor(_element);
                var deep = GetDeepColor(_element);
                float bandWidth = Math.Max(width * BandWidthFactor, 48f);

                _root = compositor.CreateContainerVisual();
                _root.Size = new Vector2(width, height);
                _root.Opacity = IdleOpacity;

                _band = compositor.CreateContainerVisual();
                _band.Size = new Vector2(bandWidth, height);
                _band.Children.InsertAtTop(CreateGlowSheet(compositor, bandWidth, height, crest, deep));

                // Bolt creation is isolated: it is the only part that depends on Win2D, and a
                // geometry failure must cost us the lightning, not the entire charge.
                try
                {
                    foreach (var bolt in CreateBolts(compositor, bandWidth, height, crest))
                    {
                        _band.Children.InsertAtTop(bolt);
                    }
                }
                catch (Exception boltEx)
                {
                    MissionController.Core.FatalErrorLog.Write("AuroraEnergyShader.CreateBolts", boltEx);
                }

                _root.Children.InsertAtTop(_band);

                if (AccessibilitySettings.AnimationsEnabled)
                {
                    // Travel the band as one unit. Starting fully off the left edge and ending fully
                    // off the right lets the charge enter and leave cleanly instead of popping into
                    // existence mid-button.
                    double seconds = Math.Clamp(GetSweepSeconds(_element), 0.4, 20.0);
                    var linear = compositor.CreateLinearEasingFunction();

                    var sweep = compositor.CreateVector3KeyFrameAnimation();
                    sweep.Duration = TimeSpan.FromSeconds(seconds);
                    sweep.IterationBehavior = AnimationIterationBehavior.Forever;
                    sweep.InsertKeyFrame(0.0f, new Vector3(-bandWidth, 0f, 0f), linear);
                    sweep.InsertKeyFrame(1.0f, new Vector3(width, 0f, 0f), linear);
                    _band.StartAnimation(nameof(_band.Offset), sweep);
                }
                else
                {
                    // Reduced motion: park the charge mid-button as a static highlight.
                    _band.Offset = new Vector3((width - bandWidth) * 0.5f, 0f, 0f);
                }

                _builtForWidth = width;
                _builtForHeight = height;

                UpdateClipGeometry(compositor, width, height);
                ElementCompositionPreview.SetElementChildVisual(_element, _root);
            }
            catch (Exception ex)
            {
                // Decoration must never take a screen down with it - but it must also not fail
                // silently, which is how this went unnoticed the first time. Debug.WriteLine is
                // invisible outside a debugger, so the reason goes to disk as well.
                MissionController.Core.FatalErrorLog.Write("AuroraEnergyShader.BuildScene", ex);
                ReleaseScene();
            }
        }

        /// <summary>The soft blue body of the charge, transparent at both edges so it has no hard seam.</summary>
        private static SpriteVisual CreateGlowSheet(
            Compositor compositor, float bandWidth, float height, Color crest, Color deep)
        {
            var brush = compositor.CreateLinearGradientBrush();
            brush.MappingMode = CompositionMappingMode.Relative;
            brush.StartPoint = new Vector2(0f, 0.5f);
            brush.EndPoint = new Vector2(1f, 0.5f);

            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.00f, Color.FromArgb(0, deep.R, deep.G, deep.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.28f, Color.FromArgb(110, deep.R, deep.G, deep.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.50f, Color.FromArgb(205, crest.R, crest.G, crest.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.72f, Color.FromArgb(110, deep.R, deep.G, deep.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(1.00f, Color.FromArgb(0, deep.R, deep.G, deep.B)));

            var sheet = compositor.CreateSpriteVisual();
            sheet.Size = new Vector2(bandWidth, height);
            sheet.Brush = brush;
            return sheet;
        }

        /// <summary>
        /// Lightning arcs riding inside the band. Each bolt is a jagged vertical polyline whose
        /// opacity stutters on its own period, which is what separates electricity from a glowing
        /// line - real arcs strike and die rather than fade smoothly.
        /// </summary>
        private static List<ShapeVisual> CreateBolts(
            Compositor compositor, float bandWidth, float height, Color crest)
        {
            var bolts = new List<ShapeVisual>(BoltCount);
            var device = CanvasDevice.GetSharedDevice();

            for (int i = 0; i < BoltCount; i++)
            {
                // Cluster the arcs around the middle of the band, where the glow is brightest.
                float centreX = bandWidth * (0.38f + (0.12f * i));
                var geometry = BuildBoltGeometry(device, centreX, height, seed: (i * 7) + 3);

                var pathGeometry = compositor.CreatePathGeometry(new CompositionPath(geometry));
                var shape = compositor.CreateSpriteShape(pathGeometry);
                shape.StrokeBrush = compositor.CreateColorBrush(Color.FromArgb(255, crest.R, crest.G, crest.B));
                shape.StrokeThickness = i == 0 ? 1.9f : 1.2f;
                shape.StrokeStartCap = CompositionStrokeCap.Round;
                shape.StrokeEndCap = CompositionStrokeCap.Round;

                var visual = compositor.CreateShapeVisual();
                visual.Size = new Vector2(bandWidth, height);
                visual.Shapes.Add(shape);
                visual.Opacity = 0f;

                if (AccessibilitySettings.AnimationsEnabled)
                {
                    // Step easing means no interpolation between on and off, so the arc snaps
                    // instead of breathing.
                    var step = compositor.CreateStepEasingFunction();
                    var flicker = compositor.CreateScalarKeyFrameAnimation();
                    flicker.Duration = TimeSpan.FromMilliseconds(260 + (i * 90));
                    flicker.IterationBehavior = AnimationIterationBehavior.Forever;
                    flicker.InsertKeyFrame(0.00f, 0.0f, step);
                    flicker.InsertKeyFrame(0.18f, 1.0f, step);
                    flicker.InsertKeyFrame(0.34f, 0.25f, step);
                    flicker.InsertKeyFrame(0.52f, 0.9f, step);
                    flicker.InsertKeyFrame(0.70f, 0.0f, step);
                    flicker.InsertKeyFrame(1.00f, 0.0f, step);
                    visual.StartAnimation(nameof(visual.Opacity), flicker);
                }
                else
                {
                    visual.Opacity = 0.5f;
                }

                bolts.Add(visual);
            }

            return bolts;
        }

        /// <summary>
        /// Deterministic zigzag down the band. A fixed seed keeps each bolt stable across rebuilds so
        /// a resize does not visibly reshuffle the arcs.
        /// </summary>
        private static CanvasGeometry BuildBoltGeometry(CanvasDevice device, float centreX, float height, int seed)
        {
            const int segments = 6;
            var random = new Random(seed);
            float amplitude = Math.Max(height * 0.16f, 3f);

            using var builder = new CanvasPathBuilder(device);
            builder.BeginFigure(centreX, 0f);

            for (int i = 1; i <= segments; i++)
            {
                float y = height * (i / (float)segments);
                float jitter = (float)((random.NextDouble() * 2.0) - 1.0) * amplitude;

                // Terminate on centre so the arc meets the far edge cleanly.
                if (i == segments)
                {
                    jitter = 0f;
                }

                builder.AddLine(centreX + jitter, y);
            }

            builder.EndFigure(CanvasFigureLoop.Open);
            return CanvasGeometry.CreatePath(builder);
        }

        /// <summary>
        /// Clips the charge to the rounded shape of the button. Without this the band paints square
        /// corners over a rounded button and spills past the edge on entry and exit.
        /// </summary>
        private void UpdateClipGeometry(Compositor compositor, float width, float height)
        {
            try
            {
                float radius = 8f;
                if (_element is Control control)
                {
                    radius = (float)Math.Max(control.CornerRadius.TopLeft, 0.0);
                }

                // Never exceed a true pill; an over-large radius renders as a distorted capsule.
                radius = Math.Min(radius, Math.Min(width, height) * 0.5f);

                _clipGeometry = compositor.CreateRoundedRectangleGeometry();
                _clipGeometry.Size = new Vector2(width, height);
                _clipGeometry.CornerRadius = new Vector2(radius, radius);

                if (_root is not null)
                {
                    _root.Clip = compositor.CreateGeometricClip(_clipGeometry);
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[AuroraEnergyShader] Ignored clip error: {ex.Message}");
            }
        }

        private void AnimateOpacity(float target, TimeSpan duration)
        {
            if (_root is null)
            {
                return;
            }

            if (!AccessibilitySettings.AnimationsEnabled)
            {
                _root.Opacity = target;
                return;
            }

            var compositor = _root.Compositor;
            var easing = compositor.CreateCubicBezierEasingFunction(
                new Vector2(0.22f, 0.0f),
                new Vector2(0.0f, 1.0f));

            var animation = compositor.CreateScalarKeyFrameAnimation();
            animation.Duration = duration;
            animation.InsertExpressionKeyFrame(0.0f, "this.StartingValue");
            animation.InsertKeyFrame(1.0f, target, easing);
            _root.StartAnimation(nameof(_root.Opacity), animation);
        }

        private static bool IsHighContrastEnabled()
        {
            try
            {
                return new AccessibilitySettings().HighContrast;
            }
            catch
            {
                return false;
            }
        }

        private void ReleaseScene()
        {
            try
            {
                if (_band is not null)
                {
                    _band.StopAnimation(nameof(_band.Offset));
                }

                if (_root is not null)
                {
                    _root.StopAnimation(nameof(_root.Opacity));
                    ElementCompositionPreview.SetElementChildVisual(_element, null);
                }
            }
            catch
            {
                // Teardown races during unload must not surface.
            }

            _root = null;
            _band = null;
            _clipGeometry = null;
            _builtForWidth = 0;
            _builtForHeight = 0;
        }
    }
}
