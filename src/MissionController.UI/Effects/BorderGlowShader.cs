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
/// Attached XAML property providing a reactive, pointer-tracking luminescent border glow
/// and ambient electric energy pulse powered directly by the Windows.UI.Composition Visual Layer.
/// </summary>
public static class BorderGlowShader
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled",
        typeof(bool),
        typeof(BorderGlowShader),
        new PropertyMetadata(false, OnIsEnabledChanged));

    public static readonly DependencyProperty GlowColorProperty = DependencyProperty.RegisterAttached(
        "GlowColor",
        typeof(Color),
        typeof(BorderGlowShader),
        new PropertyMetadata(Color.FromArgb(255, 0, 229, 255))); // Electric cyan default

    public static readonly DependencyProperty PulseIntensityProperty = DependencyProperty.RegisterAttached(
        "PulseIntensity",
        typeof(double),
        typeof(BorderGlowShader),
        new PropertyMetadata(0.85));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(BorderGlowController),
        typeof(BorderGlowShader),
        new PropertyMetadata(null));

    public static bool GetIsEnabled(DependencyObject element) => (bool)element.GetValue(IsEnabledProperty);
    public static void SetIsEnabled(DependencyObject element, bool value) => element.SetValue(IsEnabledProperty, value);

    public static Color GetGlowColor(DependencyObject element) => (Color)element.GetValue(GlowColorProperty);
    public static void SetGlowColor(DependencyObject element, Color value) => element.SetValue(GlowColorProperty, value);

    public static double GetPulseIntensity(DependencyObject element) => (double)element.GetValue(PulseIntensityProperty);
    public static void SetPulseIntensity(DependencyObject element, double value) => element.SetValue(PulseIntensityProperty, value);

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
                element.SetValue(ControllerProperty, new BorderGlowController(element));
            }
        }
        else if (element.GetValue(ControllerProperty) is BorderGlowController controller)
        {
            controller.Dispose();
            element.ClearValue(ControllerProperty);
        }
    }

    private sealed class BorderGlowController : IDisposable
    {
        private static readonly UISettings AccessibilitySettings = new();
        private readonly FrameworkElement _element;
        private SpriteVisual? _glowVisual;
        private CompositionRadialGradientBrush? _gradientBrush;
        private bool _isHovered;

        public BorderGlowController(FrameworkElement element)
        {
            _element = element;
            _element.Loaded += OnLoaded;
            _element.Unloaded += OnUnloaded;
            _element.PointerEntered += OnPointerEntered;
            _element.PointerMoved += OnPointerMoved;
            _element.PointerExited += OnPointerExited;

            if (_element.IsLoaded)
            {
                CreateGlowVisual();
            }
        }

        public void Dispose()
        {
            _element.Loaded -= OnLoaded;
            _element.Unloaded -= OnUnloaded;
            _element.PointerEntered -= OnPointerEntered;
            _element.PointerMoved -= OnPointerMoved;
            _element.PointerExited -= OnPointerExited;
            ReleaseGlowVisual();
        }

        private void OnLoaded(object sender, RoutedEventArgs args) => CreateGlowVisual();

        private void OnUnloaded(object sender, RoutedEventArgs args) => ReleaseGlowVisual();

        private void OnPointerEntered(object sender, PointerRoutedEventArgs args)
        {
            _isHovered = true;
            UpdatePointerPosition(args);
            AnimateOpacity(GetHoverOpacity(), TimeSpan.FromMilliseconds(120));
        }

        private void OnPointerMoved(object sender, PointerRoutedEventArgs args)
        {
            if (_isHovered)
            {
                UpdatePointerPosition(args);
            }
        }

        private void OnPointerExited(object sender, PointerRoutedEventArgs args)
        {
            _isHovered = false;
            if (_gradientBrush is not null)
            {
                _gradientBrush.EllipseCenter = new Vector2(0.5f, 0.5f);
            }
            AnimateOpacity(GetIdleOpacity(), TimeSpan.FromMilliseconds(250));
        }

        private void UpdatePointerPosition(PointerRoutedEventArgs args)
        {
            if (_gradientBrush is null || _element.ActualWidth <= 0 || _element.ActualHeight <= 0)
            {
                return;
            }

            var point = args.GetCurrentPoint(_element).Position;
            var relX = (float)Math.Clamp(point.X / _element.ActualWidth, 0.0, 1.0);
            var relY = (float)Math.Clamp(point.Y / _element.ActualHeight, 0.0, 1.0);
            _gradientBrush.EllipseCenter = new Vector2(relX, relY);
        }

        private void CreateGlowVisual()
        {
            try
            {
                if (_glowVisual is not null || IsHighContrastEnabled())
                {
                    return;
                }

                var visual = ElementCompositionPreview.GetElementVisual(_element);
                if (visual is null) return;
                var compositor = visual.Compositor;
                if (compositor is null) return;

                var glowColor = BorderGlowShader.GetGlowColor(_element);
                var intensity = GetNormalizedIntensity();

                _gradientBrush = compositor.CreateRadialGradientBrush();
                _gradientBrush.MappingMode = CompositionMappingMode.Relative;
                _gradientBrush.EllipseCenter = new Vector2(0.5f, 0.5f);
                _gradientBrush.EllipseRadius = new Vector2(0.85f, 0.85f);

                // The child visual sits above XAML content, so restrained alpha preserves text contrast.
                _gradientBrush.ColorStops.Append(compositor.CreateColorGradientStop(0.0f, Color.FromArgb(56, glowColor.R, glowColor.G, glowColor.B)));
                _gradientBrush.ColorStops.Append(compositor.CreateColorGradientStop(0.45f, Color.FromArgb(18, glowColor.R, glowColor.G, glowColor.B)));
                _gradientBrush.ColorStops.Append(compositor.CreateColorGradientStop(1.0f, Color.FromArgb(0, glowColor.R, glowColor.G, glowColor.B)));

                _glowVisual = compositor.CreateSpriteVisual();
                _glowVisual.RelativeSizeAdjustment = Vector2.One;
                _glowVisual.Brush = _gradientBrush;
                _glowVisual.Opacity = GetIdleOpacity();

                if (AccessibilitySettings.AnimationsEnabled)
                {
                    var clock = compositor.CreatePropertySet();
                    clock.InsertScalar("Progress", 0.0f);
                    clock.InsertScalar("Intensity", intensity);

                    var clockAnim = compositor.CreateScalarKeyFrameAnimation();
                    clockAnim.Duration = TimeSpan.FromMilliseconds(2400);
                    clockAnim.IterationBehavior = AnimationIterationBehavior.Forever;
                    clockAnim.InsertKeyFrame(0.0f, 0.0f);
                    clockAnim.InsertKeyFrame(1.0f, 1.0f);
                    clock.StartAnimation("Progress", clockAnim);

                    var pulseExpr = compositor.CreateExpressionAnimation(
                        "0.14 + 0.07 * clock.Intensity + 0.025 * clock.Intensity * Sin(clock.Progress * 6.2831855)");
                    pulseExpr.SetReferenceParameter("clock", clock);
                    _glowVisual.StartAnimation("Opacity", pulseExpr);
                }

                ElementCompositionPreview.SetElementChildVisual(_element, _glowVisual);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[BorderGlowShader] Ignored visual error: {ex.Message}");
                _glowVisual = null;
                _gradientBrush = null;
            }
        }

        private float GetNormalizedIntensity() =>
            (float)Math.Clamp(BorderGlowShader.GetPulseIntensity(_element), 0.0, 1.0);

        private float GetIdleOpacity() => 0.14f + (0.07f * GetNormalizedIntensity());

        private float GetHoverOpacity() => 0.32f + (0.16f * GetNormalizedIntensity());

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

        private void ReleaseGlowVisual()
        {
            if (_glowVisual is not null)
            {
                _glowVisual.StopAnimation("Opacity");
                ElementCompositionPreview.SetElementChildVisual(_element, null);
            }

            _glowVisual = null;
            _gradientBrush = null;
        }

        private void AnimateOpacity(float target, TimeSpan duration)
        {
            if (_glowVisual is null)
            {
                return;
            }

            if (!AccessibilitySettings.AnimationsEnabled)
            {
                _glowVisual.StopAnimation("Opacity");
                _glowVisual.Opacity = target;
                return;
            }

            var compositor = _glowVisual.Compositor;
            var easing = compositor.CreateCubicBezierEasingFunction(
                new Vector2(0.22f, 0.0f),
                new Vector2(0.0f, 1.0f));
            var animation = compositor.CreateScalarKeyFrameAnimation();
            animation.Duration = duration;
            animation.InsertExpressionKeyFrame(0.0f, "this.StartingValue");
            animation.InsertKeyFrame(1.0f, target, easing);
            _glowVisual.StartAnimation("Opacity", animation);
        }
    }
}
