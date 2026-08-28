using System;
using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace MissionController.UI.Effects;

/// <summary>
/// Attached XAML effect providing subtle CRT phosphor scanlines and animated
/// telemetry cyber-flicker for live streaming logs, terminal output, and status panels.
/// </summary>
public static class TelemetryWaveformEffect
{
    public static readonly DependencyProperty IsScanlineActiveProperty = DependencyProperty.RegisterAttached(
        "IsScanlineActive",
        typeof(bool),
        typeof(TelemetryWaveformEffect),
        new PropertyMetadata(false, OnIsScanlineActiveChanged));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(TelemetryScanlineController),
        typeof(TelemetryWaveformEffect),
        new PropertyMetadata(null));

    public static bool GetIsScanlineActive(DependencyObject element) => (bool)element.GetValue(IsScanlineActiveProperty);
    public static void SetIsScanlineActive(DependencyObject element, bool value) => element.SetValue(IsScanlineActiveProperty, value);

    private static void OnIsScanlineActiveChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        if (sender is not FrameworkElement element)
        {
            return;
        }

        if ((bool)args.NewValue)
        {
            if (element.GetValue(ControllerProperty) is null)
            {
                element.SetValue(ControllerProperty, new TelemetryScanlineController(element));
            }
        }
        else if (element.GetValue(ControllerProperty) is TelemetryScanlineController controller)
        {
            controller.Dispose();
            element.ClearValue(ControllerProperty);
        }
    }

    private sealed class TelemetryScanlineController : IDisposable
    {
        private static readonly UISettings AccessibilitySettings = new();
        private readonly FrameworkElement _element;
        private SpriteVisual? _scanlineVisual;
        private CompositionLinearGradientBrush? _scanlineBrush;

        public TelemetryScanlineController(FrameworkElement element)
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
            if (_scanlineVisual is not null || IsHighContrastEnabled())
            {
                return;
            }

            var compositor = ElementCompositionPreview.GetElementVisual(_element).Compositor;

            _scanlineBrush = compositor.CreateLinearGradientBrush();
            _scanlineBrush.MappingMode = CompositionMappingMode.Relative;
            _scanlineBrush.StartPoint = new Vector2(0.0f, 0.0f);
            _scanlineBrush.EndPoint = new Vector2(0.0f, 1.0f);

            _scanlineBrush.ColorStops.Append(compositor.CreateColorGradientStop(0.0f, Color.FromArgb(12, 0, 229, 255)));
            _scanlineBrush.ColorStops.Append(compositor.CreateColorGradientStop(0.5f, Color.FromArgb(0, 0, 0, 0)));
            _scanlineBrush.ColorStops.Append(compositor.CreateColorGradientStop(1.0f, Color.FromArgb(8, 0, 229, 255)));

            _scanlineVisual = compositor.CreateSpriteVisual();
            _scanlineVisual.RelativeSizeAdjustment = Vector2.One;
            _scanlineVisual.Brush = _scanlineBrush;
            _scanlineVisual.Opacity = 0.65f;

            if (AccessibilitySettings.AnimationsEnabled)
            {
                var clock = compositor.CreatePropertySet();
                clock.InsertScalar("Sweep", 0.0f);

                var sweepAnim = compositor.CreateScalarKeyFrameAnimation();
                sweepAnim.Duration = TimeSpan.FromMilliseconds(3200);
                sweepAnim.IterationBehavior = AnimationIterationBehavior.Forever;
                sweepAnim.InsertKeyFrame(0.0f, 0.0f);
                sweepAnim.InsertKeyFrame(1.0f, 1.0f);
                clock.StartAnimation("Sweep", sweepAnim);

                var flickerExpr = compositor.CreateExpressionAnimation(
                    "0.45 + 0.15 * Sin(clock.Sweep * 6.2831855 * 2.0)");
                flickerExpr.SetReferenceParameter("clock", clock);
                _scanlineVisual.StartAnimation("Opacity", flickerExpr);
            }

            ElementCompositionPreview.SetElementChildVisual(_element, _scanlineVisual);
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

        private void ReleaseVisual()
        {
            if (_scanlineVisual is not null)
            {
                _scanlineVisual.StopAnimation("Opacity");
                ElementCompositionPreview.SetElementChildVisual(_element, null);
            }

            _scanlineVisual = null;
            _scanlineBrush = null;
        }
    }
}
