using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Workflow;

namespace MissionController.Infrastructure.Network.Triggers;

public sealed class WorkflowScheduler : IDisposable
{
    private readonly IWorkflowExecutionEngine _engine;
    private readonly ConcurrentDictionary<string, Timer> _scheduledTimers;

    public WorkflowScheduler(IWorkflowExecutionEngine engine)
    {
        _engine = engine;
        _scheduledTimers = new ConcurrentDictionary<string, Timer>(StringComparer.OrdinalIgnoreCase);
    }

    public void ScheduleRecurringWorkflow(
        WorkflowGraph graph,
        TimeSpan interval,
        string operatorIdentity = "SchedulerService")
    {
        graph.Validate();
        CancelSchedule(graph.WorkflowId);

        var timer = new Timer(async _ =>
        {
            try
            {
                var payload = new System.Collections.Generic.Dictionary<string, string>
                {
                    { "trigger", "schedule" },
                    { "executedAt", DateTime.UtcNow.ToString("o") }
                };

                await _engine.ExecuteAsync(graph, payload, operatorIdentity);
            }
            catch { }
        }, null, interval, interval);

        _scheduledTimers[graph.WorkflowId] = timer;
    }

    public void CancelSchedule(string workflowId)
    {
        if (_scheduledTimers.TryRemove(workflowId, out var timer))
        {
            timer.Dispose();
        }
    }

    public void Dispose()
    {
        foreach (var timer in _scheduledTimers.Values)
        {
            timer.Dispose();
        }
        _scheduledTimers.Clear();
    }
}
