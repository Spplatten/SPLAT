using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Models;

namespace MissionController.Core.Workflow;

public interface IWorkflowExecutionEngine
{
    Task<WorkflowExecutionResult> ExecuteAsync(
        WorkflowGraph graph,
        IReadOnlyDictionary<string, string> triggerPayload,
        string operatorIdentity,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<MissionChunk> ExecuteStreamingAsync(
        WorkflowGraph graph,
        IReadOnlyDictionary<string, string> triggerPayload,
        string operatorIdentity,
        CancellationToken cancellationToken = default);
}

public interface IWorkflowSynthesizer
{
    Task<WorkflowGraph> SynthesizeFromNaturalLanguageAsync(
        string prompt,
        CancellationToken cancellationToken = default);
}

public interface IWorkflowRegistry
{
    Task<IReadOnlyList<WorkflowGraph>> GetAllWorkflowsAsync(CancellationToken cancellationToken = default);
    Task<WorkflowGraph?> GetWorkflowByIdAsync(string workflowId, CancellationToken cancellationToken = default);
    Task RegisterWorkflowAsync(WorkflowGraph workflow, CancellationToken cancellationToken = default);
    Task<bool> DeleteWorkflowAsync(string workflowId, CancellationToken cancellationToken = default);
}
