using System;
using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace MissionController.UI.Effects;

/// <summary>
/// Provides the runtime-visible fallback for ambient shader surfaces when a
/// compiled Win2D/D3D effect is unavailable. The procedural gradient remains
/// compositor-owned and is disabled for high contrast or reduced motion.
/// </summary>
public static class AmbientSurfaceShader
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled",
        typeof(bool),
        typeof(AmbientSurfaceShader),
        new PropertyMetadata(false, OnIsEnabledChanged));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(AmbientSurfaceController),
        typeof(AmbientSurfaceShader),
        new PropertyMetadata(null));

    public static bool GetIsEnabled(DependencyObject element) => (bool)element.GetValue(IsEnabledProperty);

    public static void SetIsEnabled(DependencyObject element, bool value) => element.SetValue(IsEnabledProperty, value);

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
                element.SetValue(ControllerProperty, new AmbientSurfaceController(element));
            }
        }
        else if (element.GetValue(ControllerProperty) is AmbientSurfaceController controller)
        {
            controller.Dispose();
            element.ClearValue(ControllerProperty);
        }
    }

    private sealed class AmbientSurfaceController : IDisposable
    {
        private readonly FrameworkElement _element;
        private ContainerVisual? _root;
        private CompositionRadialGradientBrush? _cyanBrush;
        private CompositionRadialGradientBrush? _violetBrush;

        public AmbientSurfaceController(FrameworkElement element)
        {
            _element = element;
            _element.Loaded += OnLoaded;
            _element.Unloaded += OnUnloaded;
            if (_element.IsLoaded)
            {
                CreateVisual();
            }
        }

        public void Dispose()
        {
            _element.Loaded -= OnLoaded;
            _element.Unloaded -= OnUnloaded;
            ReleaseVisual();
        }

        private void OnLoaded(object sender, RoutedEventArgs args) => CreateVisual();

        private void OnUnloaded(object sender, RoutedEventArgs args) => ReleaseVisual();

        private void CreateVisual()
        {
            if (_root is not null || IsHighContrastEnabled())
            {
                return;
            }

            var compositor = ElementCompositionPreview.GetElementVisual(_element).Compositor;
            _root = compositor.CreateContainerVisual();
            _root.RelativeSizeAdjustment = Vector2.One;
            _root.Clip = compositor.CreateInsetClip();

            _cyanBrush = CreateGlowBrush(
                compositor,
                new Vector2(0.08f, 0.02f),
                new Vector2(0.58f, 0.78f),
                Color.FromArgb(72, 0, 200, 255));
            _violetBrush = CreateGlowBrush(
                compositor,
                new Vector2(0.94f, 0.18f),
                new Vector2(0.48f, 0.68f),
                Color.FromArgb(50, 144, 92, 255));

            _root.Children.InsertAtTop(CreateGlowVisual(compositor, _cyanBrush));
            _root.Children.InsertAtTop(CreateGlowVisual(compositor, _violetBrush));
            ElementCompositionPreview.SetElementChildVisual(_element, _root);

            if (AnimationsEnabled())
            {
                StartDrift(_cyanBrush, new Vector2(0.08f, 0.02f), new Vector2(0.28f, 0.20f), TimeSpan.FromSeconds(16));
                StartDrift(_violetBrush, new Vector2(0.94f, 0.18f), new Vector2(0.72f, 0.04f), TimeSpan.FromSeconds(19));
            }
        }

        private void ReleaseVisual()
        {
            _cyanBrush?.StopAnimation(nameof(CompositionRadialGradientBrush.EllipseCenter));
            _violetBrush?.StopAnimation(nameof(CompositionRadialGradientBrush.EllipseCenter));
            if (_root is not null)
            {
                ElementCompositionPreview.SetElementChildVisual(_element, null);
            }

            _root = null;
            _cyanBrush = null;
            _violetBrush = null;
        }

        private static SpriteVisual CreateGlowVisual(
            Compositor compositor,
            CompositionRadialGradientBrush brush)
        {
            var visual = compositor.CreateSpriteVisual();
            visual.RelativeSizeAdjustment = Vector2.One;
            visual.Brush = brush;
            return visual;
        }

        private static CompositionRadialGradientBrush CreateGlowBrush(
            Compositor compositor,
            Vector2 center,
            Vector2 radius,
            Color color)
        {
            var brush = compositor.CreateRadialGradientBrush();
            brush.MappingMode = CompositionMappingMode.Relative;
            brush.EllipseCenter = center;
            brush.EllipseRadius = radius;
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.0f, color));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(0.46f, Color.FromArgb((byte)(color.A / 2), color.R, color.G, color.B)));
            brush.ColorStops.Append(compositor.CreateColorGradientStop(1.0f, Color.FromArgb(0, color.R, color.G, color.B)));
            return brush;
        }

        private static void StartDrift(
            CompositionRadialGradientBrush brush,
            Vector2 origin,
            Vector2 destination,
            TimeSpan duration)
        {
            var animation = brush.Compositor.CreateVector2KeyFrameAnimation();
            animation.Duration = duration;
            animation.IterationBehavior = AnimationIterationBehavior.Forever;
            animation.InsertKeyFrame(0.0f, origin);
            animation.InsertKeyFrame(0.5f, destination);
            animation.InsertKeyFrame(1.0f, origin);
            brush.StartAnimation(nameof(CompositionRadialGradientBrush.EllipseCenter), animation);
        }

        private static bool AnimationsEnabled()
        {
            try
            {
                return new UISettings().AnimationsEnabled;
            }
            catch
            {
                return true;
            }
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
    }
}
