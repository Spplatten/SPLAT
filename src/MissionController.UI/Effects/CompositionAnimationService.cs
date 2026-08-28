using System;
using System.Numerics;
using System.Runtime.InteropServices;
using Microsoft.UI.Composition;
using Windows.UI.ViewManagement;

namespace MissionController.UI.Effects;

/// <summary>
/// Describes a compositor-owned transition. Null values leave the matching
/// property untouched and a missing "from" value preserves the current
/// compositor value, which keeps interrupted transitions visually continuous.
/// </summary>
public sealed class CompositionTransitionSpec
{
    public CompositionTransitionSpec(TimeSpan duration)
    {
        Duration = duration;
    }

    public TimeSpan Duration { get; }

    public float? FromOpacity { get; init; }

    public float? ToOpacity { get; init; }

    public Vector3? FromOffset { get; init; }

    public Vector3? ToOffset { get; init; }

    public Vector3? FromScale { get; init; }

    public Vector3? ToScale { get; init; }

    public CompositionEasingFunction? EasingFunction { get; init; }

    internal bool HasChanges => ToOpacity.HasValue || ToOffset.HasValue || ToScale.HasValue;
}

/// <summary>
/// Small, reusable facade over the WinUI Visual Layer. Animation work is
/// submitted to the Compositor, so the UI thread only authors the transition;
/// the compositor owns frame-by-frame interpolation and expression evaluation.
/// </summary>
public sealed class CompositionAnimationService
{
    private const float TwoPi = 6.2831855f;
    private readonly Compositor _compositor;
    private readonly bool? _animationsEnabledOverride;
    private UISettings? _uiSettings;

    public CompositionAnimationService(Compositor compositor, bool? animationsEnabledOverride = null)
    {
        _compositor = compositor ?? throw new ArgumentNullException(nameof(compositor));
        _animationsEnabledOverride = animationsEnabledOverride;
    }

    /// <summary>
    /// Mirrors the Windows motion preference. The override is intended for
    /// deterministic tests and for an app-level reduced-motion setting.
    /// </summary>
    public bool AnimationsEnabled
    {
        get
        {
            if (_animationsEnabledOverride is bool overrideValue)
            {
                return overrideValue;
            }

            try
            {
                // UISettings is created lazily because Composition services are
                // often constructed before the first visual is loaded.
                _uiSettings ??= new UISettings();
                return _uiSettings.AnimationsEnabled;
            }
            catch (COMException)
            {
                // Rendering can still proceed in a non-XAML test host; fail
                // open here and let callers explicitly opt into reduced motion.
                return true;
            }
        }
    }

    /// <summary>
    /// Runs a transition as one CompositionScopedBatch. Completion therefore
    /// means all requested properties reached their final keyframes, rather
    /// than merely meaning that the UI callback returned.
    /// </summary>
    public CompositionScopedBatch? Start(
        Visual visual,
        CompositionTransitionSpec spec,
        Action? completed = null)
    {
        ArgumentNullException.ThrowIfNull(visual);
        ArgumentNullException.ThrowIfNull(spec);

        if (!spec.HasChanges)
        {
            completed?.Invoke();
            return null;
        }

        if (!AnimationsEnabled || spec.Duration <= TimeSpan.Zero)
        {
            ApplyFinalValue(visual, spec);
            completed?.Invoke();
            return null;
        }

        var easing = spec.EasingFunction ?? _compositor.CreateCubicBezierEasingFunction(
            new Vector2(0.22f, 0.0f),
            new Vector2(0.0f, 1.0f));
        var batch = _compositor.CreateScopedBatch(CompositionBatchTypes.Animation);

        if (completed is not null)
        {
            batch.Completed += (_, _) => completed();
        }

        try
        {
            if (spec.ToOpacity is float toOpacity)
            {
                StartOpacity(visual, spec.FromOpacity, ClampOpacity(toOpacity), spec.Duration, easing);
            }

            if (spec.ToOffset is Vector3 toOffset)
            {
                StartOffset(visual, spec.FromOffset, toOffset, spec.Duration, easing);
            }

            if (spec.ToScale is Vector3 toScale)
            {
                StartScale(visual, spec.FromScale, toScale, spec.Duration, easing);
            }

            batch.End();
            return batch;
        }
        catch
        {
            if (!batch.IsEnded)
            {
                batch.End();
            }

            throw;
        }
    }

    public CompositionScopedBatch? FadeTo(
        Visual visual,
        float targetOpacity,
        TimeSpan duration,
        Action? completed = null)
    {
        return Start(
            visual,
            new CompositionTransitionSpec(duration)
            {
                ToOpacity = targetOpacity
            },
            completed);
    }

    public CompositionScopedBatch? MoveTo(
        Visual visual,
        Vector3 targetOffset,
        TimeSpan duration,
        Action? completed = null)
    {
        return Start(
            visual,
            new CompositionTransitionSpec(duration)
            {
                ToOffset = targetOffset
            },
            completed);
    }

    public CompositionScopedBatch? ScaleTo(
        Visual visual,
        Vector3 targetScale,
        TimeSpan duration,
        Action? completed = null)
    {
        return Start(
            visual,
            new CompositionTransitionSpec(duration)
            {
                ToScale = targetScale
            },
            completed);
    }

    /// <summary>
    /// Creates an entrance using one batch so offset and opacity settle
    /// together. This is suitable for page/card loading transitions.
    /// </summary>
    public CompositionScopedBatch? Entrance(
        Visual visual,
        Vector3 fromOffset,
        Vector3 toOffset,
        TimeSpan duration,
        Action? completed = null)
    {
        return Start(
            visual,
            new CompositionTransitionSpec(duration)
            {
                FromOpacity = 0.0f,
                ToOpacity = 1.0f,
                FromOffset = fromOffset,
                ToOffset = toOffset
            },
            completed);
    }

    /// <summary>
    /// Creates the small scale response used by press feedback while keeping
    /// the control's XAML input and accessibility surface unchanged.
    /// </summary>
    public CompositionScopedBatch? Press(
        Visual visual,
        float pressedScale = 0.97f,
        TimeSpan? duration = null,
        Action? completed = null)
    {
        var targetScale = new Vector3(pressedScale, pressedScale, 1.0f);
        return ScaleTo(visual, targetScale, duration ?? TimeSpan.FromMilliseconds(90), completed);
    }

    /// <summary>
    /// Starts a compositor-only pulse for loading or ambient status visuals.
    /// The finite property-set clock is intentionally owned by the returned
    /// handle so a view can stop it on Unloaded and avoid a forever animation.
    /// </summary>
    public CompositionAnimationHandle? StartPulse(
        Visual visual,
        float baseOpacity = 0.75f,
        float amplitude = 0.15f,
        TimeSpan? period = null)
    {
        ArgumentNullException.ThrowIfNull(visual);

        baseOpacity = ClampOpacity(baseOpacity);
        amplitude = Math.Clamp(Math.Abs(amplitude), 0.0f, Math.Min(baseOpacity, 1.0f - baseOpacity));

        if (!AnimationsEnabled)
        {
            visual.StopAnimation(nameof(Visual.Opacity));
            visual.Opacity = baseOpacity;
            return null;
        }

        var pulsePeriod = period.GetValueOrDefault(TimeSpan.FromMilliseconds(1200));
        if (pulsePeriod < TimeSpan.FromMilliseconds(16))
        {
            pulsePeriod = TimeSpan.FromMilliseconds(16);
        }

        var clock = _compositor.CreatePropertySet();
        clock.InsertScalar("Phase", 0.0f);

        var clockAnimation = _compositor.CreateScalarKeyFrameAnimation();
        clockAnimation.Duration = pulsePeriod;
        clockAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
        clockAnimation.InsertKeyFrame(0.0f, 0.0f);
        clockAnimation.InsertKeyFrame(1.0f, 1.0f);
        clock.StartAnimation("Phase", clockAnimation);

        var expression = _compositor.CreateExpressionAnimation(
            $"baseOpacity + amplitude * Sin(clock.Phase * {TwoPi.ToString(System.Globalization.CultureInfo.InvariantCulture)})");
        expression.SetReferenceParameter("clock", clock);
        expression.SetScalarParameter("baseOpacity", baseOpacity);
        expression.SetScalarParameter("amplitude", amplitude);

        visual.StopAnimation(nameof(Visual.Opacity));
        visual.StartAnimation(nameof(Visual.Opacity), expression);

        return new CompositionAnimationHandle(visual, nameof(Visual.Opacity), clock, "Phase", baseOpacity);
    }

    /// <summary>
    /// Starts a breathing scale/opacity animation for high-priority action buttons and indicators.
    /// </summary>
    public CompositionAnimationHandle? StartBreathing(
        Visual visual,
        float baseScale = 1.0f,
        float scaleDelta = 0.03f,
        TimeSpan? period = null)
    {
        ArgumentNullException.ThrowIfNull(visual);

        if (!AnimationsEnabled)
        {
            visual.StopAnimation(nameof(Visual.Scale));
            visual.Scale = new Vector3(baseScale, baseScale, 1.0f);
            return null;
        }

        var breathingPeriod = period.GetValueOrDefault(TimeSpan.FromMilliseconds(1800));
        var clock = _compositor.CreatePropertySet();
        clock.InsertScalar("Phase", 0.0f);

        var clockAnim = _compositor.CreateScalarKeyFrameAnimation();
        clockAnim.Duration = breathingPeriod;
        clockAnim.IterationBehavior = AnimationIterationBehavior.Forever;
        clockAnim.InsertKeyFrame(0.0f, 0.0f);
        clockAnim.InsertKeyFrame(1.0f, 1.0f);
        clock.StartAnimation("Phase", clockAnim);

        var expr = _compositor.CreateExpressionAnimation(
            $"Vector3(baseScale + scaleDelta * Sin(clock.Phase * {TwoPi.ToString(System.Globalization.CultureInfo.InvariantCulture)}), baseScale + scaleDelta * Sin(clock.Phase * {TwoPi.ToString(System.Globalization.CultureInfo.InvariantCulture)}), 1.0)");
        expr.SetReferenceParameter("clock", clock);
        expr.SetScalarParameter("baseScale", baseScale);
        expr.SetScalarParameter("scaleDelta", scaleDelta);

        visual.StopAnimation(nameof(Visual.Scale));
        visual.StartAnimation(nameof(Visual.Scale), expr);

        return new CompositionAnimationHandle(visual, nameof(Visual.Scale), clock, "Phase");
    }

    /// <summary>
    /// Starts a linear shimmer sweep across a visual surface.
    /// </summary>
    public CompositionAnimationHandle? StartShimmer(
        CompositionLinearGradientBrush gradientBrush,
        TimeSpan? period = null)
    {
        ArgumentNullException.ThrowIfNull(gradientBrush);

        if (!AnimationsEnabled)
        {
            gradientBrush.StartPoint = new Vector2(0.0f, 0.0f);
            gradientBrush.EndPoint = new Vector2(1.0f, 1.0f);
            return null;
        }

        var shimmerPeriod = period.GetValueOrDefault(TimeSpan.FromMilliseconds(2000));
        var clock = _compositor.CreatePropertySet();
        clock.InsertScalar("Progress", 0.0f);

        var clockAnim = _compositor.CreateScalarKeyFrameAnimation();
        clockAnim.Duration = shimmerPeriod;
        clockAnim.IterationBehavior = AnimationIterationBehavior.Forever;
        clockAnim.InsertKeyFrame(0.0f, 0.0f);
        clockAnim.InsertKeyFrame(1.0f, 1.0f);
        clock.StartAnimation("Progress", clockAnim);

        var startExpr = _compositor.CreateExpressionAnimation("Vector2(clock.Progress * 2.0 - 1.0, 0.0)");
        startExpr.SetReferenceParameter("clock", clock);
        var endExpr = _compositor.CreateExpressionAnimation("Vector2(clock.Progress * 2.0, 1.0)");
        endExpr.SetReferenceParameter("clock", clock);

        gradientBrush.StartAnimation(nameof(CompositionLinearGradientBrush.StartPoint), startExpr);
        gradientBrush.StartAnimation(nameof(CompositionLinearGradientBrush.EndPoint), endExpr);

        return new CompositionAnimationHandle(gradientBrush, nameof(CompositionLinearGradientBrush.StartPoint), clock, "Progress");
    }

    /// <summary>
    /// Produces an expression animation for a relation between composition
    /// objects. The returned animation is not started until the caller binds
    /// it to a target property, making parameter setup explicit and reusable.
    /// </summary>
    public ExpressionAnimation CreateExpressionAnimation(
        string expression,
        Action<ExpressionAnimation>? configure = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expression);
        var animation = _compositor.CreateExpressionAnimation(expression);
        configure?.Invoke(animation);
        return animation;
    }

    /// <summary>
    /// Binds a follower offset to a source offset on the compositor thread.
    /// Reduced motion receives a single resolved value and no live animation.
    /// </summary>
    public void BindOffset(Visual follower, Visual source, Vector3 delta = default)
    {
        ArgumentNullException.ThrowIfNull(follower);
        ArgumentNullException.ThrowIfNull(source);

        follower.StopAnimation(nameof(Visual.Offset));
        if (!AnimationsEnabled)
        {
            follower.Offset = source.Offset + delta;
            return;
        }

        var expression = _compositor.CreateExpressionAnimation("source.Offset + delta");
        expression.SetReferenceParameter("source", source);
        expression.SetVector3Parameter("delta", delta);
        follower.StartAnimation(nameof(Visual.Offset), expression);
    }

    private static void StartOpacity(
        Visual visual,
        float? from,
        float to,
        TimeSpan duration,
        CompositionEasingFunction easing)
    {
        visual.StopAnimation(nameof(Visual.Opacity));
        if (from is float fromOpacity)
        {
            visual.Opacity = ClampOpacity(fromOpacity);
        }

        var animation = visual.Compositor.CreateScalarKeyFrameAnimation();
        animation.Duration = duration;
        if (from is float explicitFrom)
        {
            animation.InsertKeyFrame(0.0f, ClampOpacity(explicitFrom));
        }
        else
        {
            animation.InsertExpressionKeyFrame(0.0f, "this.StartingValue");
        }

        animation.InsertKeyFrame(1.0f, to, easing);
        visual.StartAnimation(nameof(Visual.Opacity), animation);
    }

    private static void StartOffset(
        Visual visual,
        Vector3? from,
        Vector3 to,
        TimeSpan duration,
        CompositionEasingFunction easing)
    {
        visual.StopAnimation(nameof(Visual.Offset));
        if (from is Vector3 explicitFrom)
        {
            visual.Offset = explicitFrom;
        }

        var animation = visual.Compositor.CreateVector3KeyFrameAnimation();
        animation.Duration = duration;
        if (from is Vector3 explicitOffset)
        {
            animation.InsertKeyFrame(0.0f, explicitOffset);
        }
        else
        {
            animation.InsertExpressionKeyFrame(0.0f, "this.StartingValue");
        }

        animation.InsertKeyFrame(1.0f, to, easing);
        visual.StartAnimation(nameof(Visual.Offset), animation);
    }

    private static void StartScale(
        Visual visual,
        Vector3? from,
        Vector3 to,
        TimeSpan duration,
        CompositionEasingFunction easing)
    {
        visual.StopAnimation(nameof(Visual.Scale));
        if (from is Vector3 explicitFrom)
        {
            visual.Scale = explicitFrom;
        }

        var animation = visual.Compositor.CreateVector3KeyFrameAnimation();
        animation.Duration = duration;
        if (from is Vector3 explicitScale)
        {
            animation.InsertKeyFrame(0.0f, explicitScale);
        }
        else
        {
            animation.InsertExpressionKeyFrame(0.0f, "this.StartingValue");
        }

        animation.InsertKeyFrame(1.0f, to, easing);
        visual.StartAnimation(nameof(Visual.Scale), animation);
    }

    private static void ApplyFinalValue(Visual visual, CompositionTransitionSpec spec)
    {
        visual.StopAnimation(nameof(Visual.Opacity));
        visual.StopAnimation(nameof(Visual.Offset));
        visual.StopAnimation(nameof(Visual.Scale));

        if (spec.ToOpacity is float opacity)
        {
            visual.Opacity = ClampOpacity(opacity);
        }

        if (spec.ToOffset is Vector3 offset)
        {
            visual.Offset = offset;
        }

        if (spec.ToScale is Vector3 scale)
        {
            visual.Scale = scale;
        }
    }

    private static float ClampOpacity(float value) => Math.Clamp(value, 0.0f, 1.0f);
}

/// <summary>
/// Owns the resources behind a long-lived composition animation. Disposing
/// stops both the target property and any private clock used to drive it.
/// </summary>
public sealed class CompositionAnimationHandle : IDisposable
{
    private readonly CompositionObject _target;
    private readonly string _targetProperty;
    private readonly CompositionObject? _clock;
    private readonly string? _clockProperty;
    private readonly float? _finalOpacity;
    private int _disposed;

    internal CompositionAnimationHandle(
        CompositionObject target,
        string targetProperty,
        CompositionObject? clock = null,
        string? clockProperty = null,
        float? finalOpacity = null)
    {
        _target = target;
        _targetProperty = targetProperty;
        _clock = clock;
        _clockProperty = clockProperty;
        _finalOpacity = finalOpacity;
    }

    public bool IsDisposed => _disposed != 0;

    public void Dispose()
    {
        if (System.Threading.Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _target.StopAnimation(_targetProperty);
        if (_finalOpacity is float finalOpacity && _target is Visual visual)
        {
            visual.Opacity = finalOpacity;
        }

        if (_clock is not null && _clockProperty is not null)
        {
            _clock.StopAnimation(_clockProperty);
        }
    }
}
