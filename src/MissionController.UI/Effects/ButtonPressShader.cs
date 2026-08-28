using System;
using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Windows.UI;
using Windows.UI.ViewManagement;

namespace MissionController.UI.Effects;

public static class ButtonPressShader
{
    public static readonly DependencyProperty IsEnabledProperty = DependencyProperty.RegisterAttached(
        "IsEnabled",
        typeof(bool),
        typeof(ButtonPressShader),
        new PropertyMetadata(false, OnIsEnabledChanged));

    private static readonly DependencyProperty ControllerProperty = DependencyProperty.RegisterAttached(
        "Controller",
        typeof(PressShaderController),
        typeof(ButtonPressShader),
        new PropertyMetadata(null));

    public static bool GetIsEnabled(DependencyObject element) => (bool)element.GetValue(IsEnabledProperty);

    public static void SetIsEnabled(DependencyObject element, bool value) => element.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        if (sender is not Button button)
        {
            return;
        }

        if ((bool)args.NewValue)
        {
            if (button.GetValue(ControllerProperty) is null)
            {
                button.SetValue(ControllerProperty, new PressShaderController(button));
            }
        }
        else if (button.GetValue(ControllerProperty) is PressShaderController controller)
        {
            controller.Dispose();
            button.ClearValue(ControllerProperty);
        }
    }

    private sealed class PressShaderController : IDisposable
    {
        private static readonly UISettings AccessibilitySettings = new();
        private static readonly TimeSpan IlluminateDuration = TimeSpan.FromMilliseconds(90);
        private static readonly TimeSpan DissolveDuration = TimeSpan.FromMilliseconds(220);
        private static readonly TimeSpan RippleDuration = TimeSpan.FromMilliseconds(280);
        private const float HoverOpacity = 0.10f;

        private readonly Button _button;
        private readonly long _isPressedCallbackToken;
        private SpriteVisual? _glowVisual;
        private CompositionRadialGradientBrush? _glowBrush;
        private bool _isPressed;
        private bool _isPointerOver;
        private bool _hasPointerOrigin;

        public PressShaderController(Button button)
        {
            _button = button;
            _button.Loaded += OnLoaded;
            _button.Unloaded += OnUnloaded;
            _button.PointerEntered += OnPointerEntered;
            _button.PointerExited += OnPointerExited;
            _button.PointerPressed += OnPointerPressed;
            _isPressedCallbackToken = _button.RegisterPropertyChangedCallback(
                ButtonBase.IsPressedProperty,
                OnIsPressedChanged);

            if (_button.IsLoaded)
            {
                CreateShaderVisual();
            }
        }

        public void Dispose()
        {
            _button.Loaded -= OnLoaded;
            _button.Unloaded -= OnUnloaded;
            _button.PointerEntered -= OnPointerEntered;
            _button.PointerExited -= OnPointerExited;
            _button.PointerPressed -= OnPointerPressed;
            _button.UnregisterPropertyChangedCallback(ButtonBase.IsPressedProperty, _isPressedCallbackToken);
            ReleaseShaderVisual();
        }

        private void OnLoaded(object sender, RoutedEventArgs args) => CreateShaderVisual();

        private void OnUnloaded(object sender, RoutedEventArgs args) => ReleaseShaderVisual();

        private void OnPointerEntered(object sender, PointerRoutedEventArgs args)
        {
            _isPointerOver = true;
            UpdatePointerOrigin(args);
            if (!_isPressed)
            {
                AnimateOpacity(HoverOpacity, IlluminateDuration);
            }
        }

        private void OnPointerExited(object sender, PointerRoutedEventArgs args)
        {
            _isPointerOver = false;
            if (!_isPressed)
            {
                AnimateOpacity(0.0f, DissolveDuration);
            }
        }

        private void OnPointerPressed(object sender, PointerRoutedEventArgs args) => UpdatePointerOrigin(args);

        private void UpdatePointerOrigin(PointerRoutedEventArgs args)
        {
            CreateShaderVisual();
            if (_glowBrush is null)
            {
                return;
            }

            var point = args.GetCurrentPoint(_button).Position;
            var width = Math.Max(_button.ActualWidth, 1.0);
            var height = Math.Max(_button.ActualHeight, 1.0);
            _glowBrush.EllipseCenter = new Vector2(
                Math.Clamp((float)(point.X / width), 0.04f, 0.96f),
                Math.Clamp((float)(point.Y / height), 0.08f, 0.92f));
            _hasPointerOrigin = true;
        }

        private void CreateShaderVisual()
        {
            try
            {
                if (_glowVisual is not null)
                {
                    return;
                }

                var visual = ElementCompositionPreview.GetElementVisual(_button);
                if (visual is null) return;
                var compositor = visual.Compositor;
                if (compositor is null) return;

                _glowBrush = compositor.CreateRadialGradientBrush();
                _glowBrush.MappingMode = CompositionMappingMode.Relative;
                _glowBrush.EllipseCenter = new Vector2(0.5f, 0.5f);
                _glowBrush.EllipseRadius = new Vector2(0.72f, 1.35f);
                _glowBrush.ColorStops.Append(compositor.CreateColorGradientStop(0.0f, Color.FromArgb(150, 255, 255, 255)));
                _glowBrush.ColorStops.Append(compositor.CreateColorGradientStop(0.34f, Color.FromArgb(72, 76, 194, 255)));
                _glowBrush.ColorStops.Append(compositor.CreateColorGradientStop(1.0f, Color.FromArgb(0, 76, 194, 255)));

                _glowVisual = compositor.CreateSpriteVisual();
                _glowVisual.RelativeSizeAdjustment = Vector2.One;
                _glowVisual.Brush = _glowBrush;
                _glowVisual.Clip = compositor.CreateInsetClip();
                _glowVisual.Opacity = 0.0f;

                ElementCompositionPreview.SetElementChildVisual(_button, _glowVisual);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ButtonPressShader] Ignored visual error: {ex.Message}");
                _glowVisual = null;
                _glowBrush = null;
            }
        }

        private void ReleaseShaderVisual()
        {
            _isPressed = false;
            _isPointerOver = false;
            _hasPointerOrigin = false;
            if (_glowVisual is not null)
            {
                _glowVisual.StopAnimation("Opacity");
                ElementCompositionPreview.SetElementChildVisual(_button, null);
            }

            _glowVisual = null;
            _glowBrush = null;
        }

        private void OnIsPressedChanged(DependencyObject sender, DependencyProperty property)
        {
            if (_button.IsPressed)
            {
                Illuminate();
            }
            else
            {
                Dissolve();
            }
        }

        private void Illuminate()
        {
            CreateShaderVisual();
            if (_glowVisual is null || _glowBrush is null)
            {
                return;
            }

            _isPressed = true;
            if (!_hasPointerOrigin)
            {
                _glowBrush.EllipseCenter = new Vector2(0.5f, 0.5f);
            }

            AnimateRipple();
            AnimateOpacity(0.82f, IlluminateDuration);
        }

        private void Dissolve()
        {
            if (!_isPressed)
            {
                return;
            }

            _isPressed = false;
            _hasPointerOrigin = false;
            AnimateOpacity(_isPointerOver ? HoverOpacity : 0.0f, DissolveDuration);
        }

        private void AnimateRipple()
        {
            if (_glowBrush is null)
            {
                return;
            }

            _glowBrush.StopAnimation(nameof(CompositionRadialGradientBrush.EllipseRadius));
            if (!AccessibilitySettings.AnimationsEnabled)
            {
                _glowBrush.EllipseRadius = new Vector2(0.72f, 1.35f);
                return;
            }

            var compositor = _glowBrush.Compositor;
            var easing = compositor.CreateCubicBezierEasingFunction(
                new Vector2(0.16f, 1.0f),
                new Vector2(0.3f, 1.0f));
            var animation = compositor.CreateVector2KeyFrameAnimation();
            animation.Duration = RippleDuration;
            animation.InsertKeyFrame(0.0f, new Vector2(0.14f, 0.24f));
            animation.InsertKeyFrame(1.0f, new Vector2(0.72f, 1.35f), easing);
            _glowBrush.StartAnimation(nameof(CompositionRadialGradientBrush.EllipseRadius), animation);
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
