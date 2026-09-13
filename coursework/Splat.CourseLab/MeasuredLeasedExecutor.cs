using System.Diagnostics;
using MissionController.Core.Interfaces;

namespace Splat.CourseLab;

// This decorator observes the existing seam. The inner executor still owns admission,
// process lifetime, output, and enforcement; a span cannot establish any of those.
public sealed class MeasuredLeasedExecutor : ILeasedExecutor
{
    private readonly ILeasedExecutor _inner;
    private readonly ActivitySource _source;

    public MeasuredLeasedExecutor(ILeasedExecutor inner, ActivitySource source)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _source = source ?? throw new ArgumentNullException(nameof(source));
    }

    public async Task<ProcessExecutionResult> ExecuteLeasedAsync(
        LeaseSpec lease,
        string command,
        IReadOnlyList<string> argv,
        IProgress<string>? stdout = null,
        IProgress<string>? stderr = null,
        IProgress<LeaseViolationEvent>? violations = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        using var activity = _source.StartActivity("splat.course.execute");
        activity?.SetTag("splat.mission_id", lease.MissionId.ToString("D"));
        var started = Stopwatch.GetTimestamp();

        try
        {
            var result = await _inner.ExecuteLeasedAsync(
                lease, command, argv, stdout, stderr, violations, ct).ConfigureAwait(false);
            // An exit code is an observation, not an attestation that containment worked.
            activity?.SetTag("splat.exit_code", result.ExitCode);
            activity?.SetTag("splat.timed_out", result.TimedOut);
            activity?.SetTag("splat.outcome", result.TimedOut ? "timeout" :
                result.ExitCode == 0 ? "success" : "failure");
            activity?.SetStatus(result.TimedOut || result.ExitCode != 0
                ? ActivityStatusCode.Error : ActivityStatusCode.Ok);
            return result;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            activity?.SetTag("splat.outcome", "cancelled");
            throw;
        }
        catch
        {
            // Exception messages, argv, paths and tool output can contain credentials.
            // Record a bounded category; leave the original exception for the caller.
            activity?.SetTag("splat.outcome", "exception");
            activity?.SetStatus(ActivityStatusCode.Error);
            throw;
        }
        finally
        {
            // Wall time includes scheduling and I/O waits. Never report it as CPU usage.
            activity?.SetTag("splat.wall_ms", Stopwatch.GetElapsedTime(started).TotalMilliseconds);
        }
    }
}
