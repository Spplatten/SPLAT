using System;
using System.Collections.Generic;
using System.Linq;

namespace MissionController.Core.Workflow;

public enum WorkflowTriggerType
{
    Manual,
    Webhook,
    OAuthCallback,
    Schedule,
    FileWatch
}

public enum WorkflowNodeType
{
    Trigger,

    /// <summary>
    /// One governed template, run as a complete 1:1:1 mission through
    /// <see cref="MissionController.Core.Interfaces.IMissionExecutionEngine"/>.
    ///
    /// This is what a workflow step IS. A node names a template from the governed catalogue and
    /// supplies its declared parameters; the mission engine then does what it always does - ACL
    /// jail, job object, restricted token, AppContainer network denial, validated argument binding,
    /// DLP on the way out, and its own row in the audit ledger. The workflow contributes ordering
    /// and nothing else, which is the only arrangement in which "governed workflow" means anything.
    /// </summary>
    GovernedMission,

    /// <summary>
    /// Free-form shell, executed outside the mission engine. REFUSED - see
    /// <see cref="MissionController.Core.Workflow.WorkflowExecutionEngine"/>.
    /// </summary>
    SandboxedScript,
    AgentReasoning,
    OAuthExchange,
    GovernedHttp,
    Condition,
    ReActAgent,
    MemoryStore,
    MemoryRecall,
    TransactionalScope
}

public record WorkflowTriggerConfig(
    WorkflowTriggerType Type,
    string? EndpointOrPath = null,
    string? CronOrInterval = null,
    string? SecretToken = null);

public record WorkflowNode(
    string NodeId,
    string Name,
    WorkflowNodeType NodeType,
    IReadOnlyDictionary<string, string> Configuration,
    string? TargetModel = null,
    string? ScriptCommand = null,
    string? AllowedEgressFqdn = null)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(NodeId))
            throw new InvalidOperationException("NodeId must not be empty.");
        if (string.IsNullOrWhiteSpace(Name))
            throw new InvalidOperationException($"Node '{NodeId}' must have a valid Name.");
    }
}

public record WorkflowEdge(
    string SourceNodeId,
    string TargetNodeId,
    string? ConditionBranch = null);

public record WorkflowGraph(
    string WorkflowId,
    string Name,
    string Description,
    WorkflowTriggerConfig Trigger,
    IReadOnlyList<WorkflowNode> Nodes,
    IReadOnlyList<WorkflowEdge> Edges,
    IReadOnlyDictionary<string, string>? Metadata = null)
{
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(WorkflowId))
            throw new InvalidOperationException("WorkflowId must not be empty.");
        if (string.IsNullOrWhiteSpace(Name))
            throw new InvalidOperationException("Workflow Name must not be empty.");
        if (Nodes == null || Nodes.Count == 0)
            throw new InvalidOperationException("Workflow must contain at least one node.");

        var duplicateIds = Nodes
            .GroupBy(n => n.NodeId, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateIds.Count > 0)
            throw new InvalidOperationException($"Duplicate node IDs detected in workflow: {string.Join(", ", duplicateIds)}");

        foreach (var node in Nodes)
        {
            node.Validate();
        }

        var nodeSet = new HashSet<string>(Nodes.Select(n => n.NodeId), StringComparer.OrdinalIgnoreCase);

        if (Edges != null)
        {
            foreach (var edge in Edges)
            {
                if (!nodeSet.Contains(edge.SourceNodeId))
                    throw new InvalidOperationException($"Edge source '{edge.SourceNodeId}' does not exist in workflow nodes.");
                if (!nodeSet.Contains(edge.TargetNodeId))
                    throw new InvalidOperationException($"Edge target '{edge.TargetNodeId}' does not exist in workflow nodes.");
            }

            // Cycle detection
            DetectCycles();
        }
    }

    private void DetectCycles()
    {
        var inDegree = Nodes.ToDictionary(n => n.NodeId, _ => 0, StringComparer.OrdinalIgnoreCase);
        var adj = Nodes.ToDictionary(n => n.NodeId, _ => new List<string>(), StringComparer.OrdinalIgnoreCase);

        foreach (var edge in Edges)
        {
            adj[edge.SourceNodeId].Add(edge.TargetNodeId);
            inDegree[edge.TargetNodeId]++;
        }

        var queue = new Queue<string>(inDegree.Where(kvp => kvp.Value == 0).Select(kvp => kvp.Key));
        int visitedCount = 0;

        while (queue.Count > 0)
        {
            var curr = queue.Dequeue();
            visitedCount++;

            foreach (var neighbor in adj[curr])
            {
                inDegree[neighbor]--;
                if (inDegree[neighbor] == 0)
                {
                    queue.Enqueue(neighbor);
                }
            }
        }

        if (visitedCount != Nodes.Count)
        {
            throw new InvalidOperationException("Workflow graph contains a cycle. SPLAT workflows must be directed acyclic graphs (DAGs).");
        }
    }

    public IReadOnlyList<WorkflowNode> GetTopologicalOrder()
    {
        Validate();
        var inDegree = Nodes.ToDictionary(n => n.NodeId, _ => 0, StringComparer.OrdinalIgnoreCase);
        var adj = Nodes.ToDictionary(n => n.NodeId, _ => new List<string>(), StringComparer.OrdinalIgnoreCase);

        foreach (var edge in Edges)
        {
            adj[edge.SourceNodeId].Add(edge.TargetNodeId);
            inDegree[edge.TargetNodeId]++;
        }

        var queue = new Queue<string>(inDegree.Where(kvp => kvp.Value == 0).Select(kvp => kvp.Key));
        var order = new List<WorkflowNode>();
        var nodeDict = Nodes.ToDictionary(n => n.NodeId, n => n, StringComparer.OrdinalIgnoreCase);

        while (queue.Count > 0)
        {
            var currId = queue.Dequeue();
            order.Add(nodeDict[currId]);

            foreach (var neighbor in adj[currId])
            {
                inDegree[neighbor]--;
                if (inDegree[neighbor] == 0)
                {
                    queue.Enqueue(neighbor);
                }
            }
        }

        return order;
    }
}

/// <summary>
/// Raised when a node cannot complete. The run stops here rather than continuing on a node's
/// unusable output: a workflow that reports success its own audit ledger contradicts is worth less
/// than one that reports the failure.
/// </summary>
public sealed class WorkflowNodeFailedException : Exception
{
    public string NodeId { get; }

    /// <summary>
    /// Whatever the node produced before it failed. Carried on the exception because the failing
    /// node's output is the first thing an operator needs, and the run is abandoned before the
    /// normal output-recording path is reached.
    /// </summary>
    public string? NodeOutput { get; }

    public WorkflowNodeFailedException(string nodeId, string reason, string? nodeOutput = null)
        : base($"Node '{nodeId}' failed: {reason}")
    {
        NodeId = nodeId;
        NodeOutput = nodeOutput;
    }
}

public record WorkflowExecutionResult(
    string WorkflowId,
    Guid ExecutionId,
    bool Success,
    IReadOnlyDictionary<string, string> NodeOutputs,
    IReadOnlyList<string> ExecutionLogs,
    DateTime StartedUtc,
    DateTime CompletedUtc,
    string? FailureReason = null);
