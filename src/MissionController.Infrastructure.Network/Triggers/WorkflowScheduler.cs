using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Workflow;

namespace MissionController.Infrastructure.Network.Triggers;

public sealed class WorkflowScheduler : IDisposable
{
    /// <summary>
    /// A timer plus the re-entrancy gate that keeps one tick from starting while the previous tick
    /// is still running. The gate travels with the timer because it is per-workflow, not global:
    /// a slow nightly report must not block a fast health check scheduled alongside it.
    /// </summary>
    private sealed class ScheduledWorkflow : IDisposable
    {
        public Timer? Timer;
        private int _running;

        /// <summary>Returns false when the previous tick has not finished yet.</summary>
        public bool TryEnter() => Interlocked.CompareExchange(ref _running, 1, 0) == 0;
        public void Exit() => Volatile.Write(ref _running, 0);
        public void Dispose() => Timer?.Dispose();
    }

    private readonly IWorkflowExecutionEngine _engine;
    private readonly Action<string, Exception>? _onFailure;
    private readonly ConcurrentDictionary<string, ScheduledWorkflow> _scheduled;

    /// <param name="onFailure">
    /// Where a failed scheduled run is reported, as (workflowId, error). Optional only because this
    /// type has no logging dependency to fall back on - but a scheduler that drops its failures is
    /// indistinguishable from one that never ran, so callers that care should always pass this.
    /// <see cref="LastFailure"/> holds the most recent error for callers that prefer to poll.
    /// </param>
    public WorkflowScheduler(IWorkflowExecutionEngine engine, Action<string, Exception>? onFailure = null)
    {
        _engine = engine;
        _onFailure = onFailure;
        _scheduled = new ConcurrentDictionary<string, ScheduledWorkflow>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>The most recent scheduled-run failure, or null if none has occurred.</summary>
    public (string WorkflowId, Exception Error)? LastFailure { get; private set; }

    /// <summary>Ticks skipped because the previous run of the same workflow was still in flight.</summary>
    public long OverlappedTicksSkipped => Interlocked.Read(ref _overlappedTicksSkipped);

    private long _overlappedTicksSkipped;

    public void ScheduleRecurringWorkflow(
        WorkflowGraph graph,
        TimeSpan interval,
        string operatorIdentity = "SchedulerService")
    {
        graph.Validate();
        CancelSchedule(graph.WorkflowId);

        var entry = new ScheduledWorkflow();

        // The callback is necessarily async void - TimerCallback returns void - so every exception
        // has to be caught here or it reaches the finalizer thread and takes the process down. What
        // it must NOT do is vanish: a scheduled workflow that has been failing since Tuesday and a
        // scheduled workflow that is running fine look identical from the outside otherwise.
        entry.Timer = new Timer(async _ =>
        {
            // A run that outlasts its interval would otherwise stack: the same graph executing two
            // and three times concurrently, each opening its own sandbox and writing its own ledger
            // rows. Skipping the tick is the honest behaviour - the next one is already scheduled.
            if (!entry.TryEnter())
            {
                Interlocked.Increment(ref _overlappedTicksSkipped);
                return;
            }

            try
            {
                var payload = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "trigger", "schedule" },
                    { "executedAt", DateTime.UtcNow.ToString("o") }
                };

                await _engine.ExecuteAsync(graph, payload, operatorIdentity);
            }
            catch (Exception ex)
            {
                LastFailure = (graph.WorkflowId, ex);

                // The reporting sink is caller-supplied and therefore untrusted: if it throws, the
                // timer thread must still survive to attempt the next tick.
                try { _onFailure?.Invoke(graph.WorkflowId, ex); } catch { }
            }
            finally
            {
                entry.Exit();
            }
        }, null, interval, interval);

        _scheduled[graph.WorkflowId] = entry;
    }

    public void CancelSchedule(string workflowId)
    {
        if (_scheduled.TryRemove(workflowId, out var entry))
        {
            entry.Dispose();
        }
    }

    public void Dispose()
    {
        // Snapshot-and-remove rather than iterate-then-clear: ScheduleRecurringWorkflow can be
        // racing this, and disposing an entry that a concurrent call has already replaced would
        // leak the replacement's timer.
        foreach (var workflowId in _scheduled.Keys)
        {
            CancelSchedule(workflowId);
        }
    }
}
