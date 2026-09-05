using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core.Workflow;

public sealed class InMemoryWorkflowRegistry : IWorkflowRegistry
{
    private readonly ConcurrentDictionary<string, WorkflowGraph> _workflows =
        new(StringComparer.OrdinalIgnoreCase);

    public Task<IReadOnlyList<WorkflowGraph>> GetAllWorkflowsAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<WorkflowGraph> list = _workflows.Values.ToList();
        return Task.FromResult(list);
    }

    public Task<WorkflowGraph?> GetWorkflowByIdAsync(string workflowId, CancellationToken cancellationToken = default)
    {
        _workflows.TryGetValue(workflowId, out var graph);
        return Task.FromResult(graph);
    }

    public Task RegisterWorkflowAsync(WorkflowGraph workflow, CancellationToken cancellationToken = default)
    {
        workflow.Validate();
        _workflows[workflow.WorkflowId] = workflow;
        return Task.CompletedTask;
    }

    public Task<bool> DeleteWorkflowAsync(string workflowId, CancellationToken cancellationToken = default)
    {
        bool removed = _workflows.TryRemove(workflowId, out _);
        return Task.FromResult(removed);
    }
}
