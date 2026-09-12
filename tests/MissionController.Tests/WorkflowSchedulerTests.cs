using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Models;
using MissionController.Core.Workflow;
using MissionController.Infrastructure.Network.Triggers;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The scheduler used to wrap every tick in <c>catch { }</c>. A scheduled workflow that had been
/// failing for a week and one running perfectly produced identical observable output - nothing -
/// which is the one thing a governance product cannot ship. It also had no re-entrancy guard, so a
/// run that outlasted its interval stacked concurrent copies of itself.
/// </summary>
public sealed class WorkflowSchedulerTests
{
    private static WorkflowGraph Graph(string id) => new(
        WorkflowId: id,
        Name: "Scheduled",
        Description: "Exercises the recurring-trigger path.",
        Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
        Nodes: new List<WorkflowNode>
        {
            new("probe", "Probe", WorkflowNodeType.AgentReasoning,
                new Dictionary<string, string> { { "Prompt", "Report status." } },
                TargetModel: "claude-sonnet-5")
        },
        Edges: new List<WorkflowEdge>());

    /// <summary>Engine stub whose every run throws, or blocks until released.</summary>
    private sealed class StubEngine : IWorkflowExecutionEngine
    {
        public Func<Task<WorkflowExecutionResult>>? Behaviour;
        public int Started;

        public Task<WorkflowExecutionResult> ExecuteAsync(
            WorkflowGraph graph, IReadOnlyDictionary<string, string> triggerPayload, string operatorIdentity,
            IProgress<string>? progress = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Started);
            return Behaviour!();
        }

        public IAsyncEnumerable<MissionChunk> ExecuteStreamingAsync(
            WorkflowGraph graph, IReadOnlyDictionary<string, string> triggerPayload, string operatorIdentity,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
    }

    [Fact]
    public async Task AFailedScheduledRun_IsReportedRatherThanSwallowed()
    {
        var engine = new StubEngine { Behaviour = () => throw new InvalidOperationException("sandbox unavailable") };
        var reported = new TaskCompletionSource<(string WorkflowId, Exception Error)>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        using var scheduler = new WorkflowScheduler(engine, (id, ex) => reported.TrySetResult((id, ex)));
        scheduler.ScheduleRecurringWorkflow(Graph("flow-fails"), TimeSpan.FromMilliseconds(50));

        var completed = await Task.WhenAny(reported.Task, Task.Delay(TimeSpan.FromSeconds(10)));
        Assert.True(completed == reported.Task, "The scheduler swallowed a failed run instead of reporting it.");

        var (workflowId, error) = await reported.Task;
        Assert.Equal("flow-fails", workflowId);
        Assert.Contains("sandbox unavailable", error.Message);
        Assert.Equal("flow-fails", scheduler.LastFailure!.Value.WorkflowId);
    }

    [Fact]
    public async Task ARunThatOutlastsItsInterval_DoesNotStackConcurrentCopies()
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var engine = new StubEngine
        {
            Behaviour = async () =>
            {
                await release.Task;
                return new WorkflowExecutionResult(
                    "flow-slow", Guid.NewGuid(), true,
                    new Dictionary<string, string>(), new List<string>(),
                    DateTime.UtcNow, DateTime.UtcNow);
            }
        };

        using var scheduler = new WorkflowScheduler(engine);
        // Ticks far faster than the run can finish: without the gate this stacks a new execution
        // every 20ms for as long as the first one is blocked.
        scheduler.ScheduleRecurringWorkflow(Graph("flow-slow"), TimeSpan.FromMilliseconds(20));

        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (scheduler.OverlappedTicksSkipped < 3 && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }

        Assert.Equal(1, Volatile.Read(ref engine.Started));
        Assert.True(scheduler.OverlappedTicksSkipped >= 3,
            $"Expected ticks to be skipped while the first run was in flight; skipped {scheduler.OverlappedTicksSkipped}.");

        release.SetResult();
    }
}
