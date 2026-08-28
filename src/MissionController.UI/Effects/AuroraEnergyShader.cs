using System;
using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace MissionController.UI.Effects;

/// <summary>
/// Aurora energy glow for the single most important button on a screen.
///
/// This is deliberately the loudest effect in the app and is meant to be applied sparingly - one
/// primary action per view. Its whole job is to be the brightest thing on screen, which only works
/// if nothing around it is competing.
///
/// Built on the Composition visual layer rather than an HLSL pixel shader on purpose: the .hlsl
/// pipeline in Effects\Win2D needs fxc.exe from the Windows SDK to produce bytecode, is opt-in via
/// EnableMissionControllerWin2DShaderBuild, and silently renders nothing when the bytecode is
/// absent. Composition ships working animation on every machine with no build-time toolchain.
///
/// The aurora is two gradient bands drifting across each other at different speeds and angles. The
/// interference between them is what reads as an aurora rather than a plain sweep - a single band
/// looks like a loading shimmer, two out-of-phase bands look alive.
/// </summary>
public static class AuroraEnergyShader
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled",
        typeof(bool),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(false, OnIsEnabledChanged));

    /// <summary>Leading edge of the aurora - the bright cyan crest.</summary>
    public static readonly DependencyProperty CrestColorProperty = DependencyProperty.RegisterAttached(
        "CrestColor",
        typeof(Color),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(Color.FromArgb(255, 120, 240, 255)));

    /// <summary>Trailing body of the aurora - the deeper azure that gives it depth.</summary>
    public static readonly DependencyProperty DeepColorProperty = DependencyProperty.RegisterAttached(
        "DeepColor",
        typeof(Color),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(Color.FromArgb(255, 0, 110, 255)));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(AuroraController),
        typeof(AuroraEnergyShader),
        new PropertyMetadata(null));

    public static bool GetIsEnabled(DependencyObject element) => (bool)element.GetValue(IsEnabledProperty);
    public static void SetIsEnabled(DependencyObject element, bool value) => element.SetValue(IsEnabledProperty, value);

    public static Color GetCrestColor(DependencyObject element) => (Color)element.GetValue(CrestColorProperty);
    public static void SetCrestColor(DependencyObject element, Color value) => element.SetValue(CrestColorProperty, value);

    public static Color GetDeepColor(DependencyObject element) => (Color)element.GetValue(DeepColorProperty);
    public static void SetDeepColor(DependencyObject element, Color value) => element.SetValue(DeepColorProperty, value);

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
                element.SetValue(ControllerProperty, new AuroraController(element));
            }
        }
        else if (element.GetValue(ControllerProperty) is AuroraController controller)
        {
            controller.Dispose();
            element.ClearValue(ControllerProperty);
        }
    }

    private sealed class AuroraController : IDisposable
    {
        private static readonly UISettings AccessibilitySettings = new();

        private readonly FrameworkElement _element;
        private ContainerVisual? _root;
        private SpriteVisual? _bandA;
        private SpriteVisual? _bandB;
        private CompositionRoundedRectangleGeometry? _clipGeometry;

        // Idle alpha is kept low because the child visual composites ABOVE the button's content:
        // push it higher and the label underneath loses contrast, which is the one thing a primary
        // action button cannot afford.
        private const float IdleOpacity = 0.55f;
        private const float HoverOpacity = 0.95f;
        private const float PressOpacity = 1.0f;

        public AuroraController(FrameworkElement element)
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
                CreateVisuals();
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
            ReleaseVisuals();
        }

        private void OnLoaded(object sender, RoutedEventArgs args) => CreateVisuals();

        private void OnUnloaded(object sender, RoutedEventArgs args) => ReleaseVisuals();

        private void OnSizeChanged(object sender, SizeChangedEventArgs args) => UpdateClipGeometry();

        private void OnPointerEntered(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(HoverOpacity, TimeSpan.FromMilliseconds(160));

        private void OnPointerExited(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(IdleOpacity, TimeSpan.FromMilliseconds(320));

        private void OnPointerPressed(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(PressOpacity, TimeSpan.FromMilliseconds(80));

        private void OnPointerReleased(object sender, PointerRoutedEventArgs args) =>
            AnimateOpacity(HoverOpacity, TimeSpan.FromMilliseconds(200));

        private void CreateVisuals()
        {
            try
            {
                if (_root is not null || IsHighContrastEnabled())
                {
                    // High contrast users have explicitly asked the OS for flat, predictable colour.
                    return;
                }

                var hostVisual = ElementCompositionPreview.GetElementVisual(_element);
                var compositor = hostVisual?.Compositor;
                if (compositor is null)
                {
                    return;
                }

                var crest = GetCrestColor(_element);
                var deep = GetDeepColor(_element);

                _root = compositor.CreateContainerVisual();
                _root.RelativeSizeAdjustment = Vector2.One;

                // Two bands, different angles and periods. Their least common multiple is long
                // enough that the loop never reads as a loop.
                _bandA = CreateBand(
                    compositor,
                    new Vector2(-0.4f, 0.0f), new Vector2(0.35f, 1.0f),
                    crest, deep,
                    periodMs: 3600, reverse: false);

                _bandB = CreateBand(
                    compositor,
                    new Vector2(1.4f, 1.0f), new Vector2(0.65f, 0.0f),
                    deep, crest,
                    periodMs: 5900, reverse: true);

                _root.Children.InsertAtTop(_bandA);
                _root.Children.InsertAtTop(_bandB);
                _root.Opacity = IdleOpacity;

                UpdateClipGeometry();
                ElementCompositionPreview.SetElementChildVisual(_element, _root);
            }
            catch (Exception ex)
            {
                // Never let decoration break a screen. Matches the fail-open posture of the other effects.
                System.Diagnostics.Debug.WriteLine($"[AuroraEnergyShader] Ignored visual error: {ex.Message}");
                ReleaseVisuals();
            }
        }

        private SpriteVisual CreateBand(
            Compositor compositor,
            Vector2 start,
            Vector2 end,
            Color leading,
            Color trailing,
            int periodMs,
            bool reverse)
        {
            var brush = compositor.CreateLinearGradientBrush();
            brush.MappingMode = CompositionMappingMode.Relative;
            brush.StartPoint = start;
            brush.EndPoint = end;

            // Transparent at both ends so the band reads as a moving ribbon of light rather than a
            // hard-edged wipe across the button.
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.00f, Color.FromArgb(0, leading.R, leading.G, leading.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.35f, Color.FromArgb(90, trailing.R, trailing.G, trailing.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.50f, Color.FromArgb(170, leading.R, leading.G, leading.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.65f, Color.FromArgb(90, trailing.R, trailing.G, trailing.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(1.00f, Color.FromArgb(0, leading.R, leading.G, leading.B)));

            var band = compositor.CreateSpriteVisual();
            band.RelativeSizeAdjustment = Vector2.One;
            band.Brush = brush;

            if (AccessibilitySettings.AnimationsEnabled)
            {
                // Drift the gradient endpoints rather than the visual itself: moving the brush keeps
                // the sprite stationary, so nothing can spill outside the button's clip.
                float sweep = reverse ? -1.8f : 1.8f;

                var startAnim = compositor.CreateVector2KeyFrameAnimation();
                startAnim.Duration = TimeSpan.FromMilliseconds(periodMs);
                startAnim.IterationBehavior = AnimationIterationBehavior.Forever;
                startAnim.InsertKeyFrame(0.0f, start);
                startAnim.InsertKeyFrame(1.0f, new Vector2(start.X + sweep, start.Y));
                brush.StartAnimation(nameof(brush.StartPoint), startAnim);

                var endAnim = compositor.CreateVector2KeyFrameAnimation();
                endAnim.Duration = TimeSpan.FromMilliseconds(periodMs);
                endAnim.IterationBehavior = AnimationIterationBehavior.Forever;
                endAnim.InsertKeyFrame(0.0f, end);
                endAnim.InsertKeyFrame(1.0f, new Vector2(end.X + sweep, end.Y));
                brush.StartAnimation(nameof(brush.EndPoint), endAnim);
            }

            return band;
        }

        /// <summary>
        /// Clips the aurora to the button's rounded shape. Without this the bands paint square
        /// corners over a rounded button, which is immediately obvious at the corners.
        /// </summary>
        private void UpdateClipGeometry()
        {
            if (_root is null || _element.ActualWidth <= 0 || _element.ActualHeight <= 0)
            {
                return;
            }

            try
            {
                var compositor = _root.Compositor;
                float radius = 6f;
                if (_element is Control control)
                {
                    radius = (float)Math.Max(control.CornerRadius.TopLeft, 0.0);
                }

                _clipGeometry ??= compositor.CreateRoundedRectangleGeometry();
                _clipGeometry.Size = new Vector2((float)_element.ActualWidth, (float)_element.ActualHeight);
                _clipGeometry.CornerRadius = new Vector2(radius, radius);
                _root.Clip = compositor.CreateGeometricClip(_clipGeometry);
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

        private void ReleaseVisuals()
        {
            try
            {
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
            _bandA = null;
            _bandB = null;
            _clipGeometry = null;
        }
    }
}
