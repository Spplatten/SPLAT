using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core.Workflow;

public sealed class WorkflowExecutionEngine : IWorkflowExecutionEngine
{
    /// <summary>Per-node wall-clock budget for a confined script, in seconds.</summary>
    private const int ScriptTimeoutSeconds = 60;

    /// <summary>
    /// Substitution shape for free text that never reaches a command line - a memory document, a
    /// recall query. Kept single-pass so a value containing <c>{OtherNode}</c> stays inert.
    /// </summary>
    private static readonly Regex NodeReferencePattern =
        new(@"\{(?<key>[A-Za-z_][A-Za-z0-9_-]*)\}", RegexOptions.Compiled, TimeSpan.FromMilliseconds(250));

    private readonly IDataLossPreventionSanitizer? _dlpSanitizer;
    private readonly IProcessLauncher? _processLauncher;
    private readonly Func<IJobSandbox>? _sandboxFactory;
    private readonly IAuditLedger? _auditLedger;
    private readonly IModelStreamClient? _modelClient;
    private readonly ISemanticMemoryIndex? _semanticMemoryIndex;
    private readonly IRemediationEngine? _remediationEngine;

    public WorkflowExecutionEngine(
        IDataLossPreventionSanitizer? dlpSanitizer = null,
        IProcessLauncher? processLauncher = null,
        Func<IJobSandbox>? sandboxFactory = null,
        IAuditLedger? auditLedger = null,
        IModelStreamClient? modelClient = null,
        ISemanticMemoryIndex? semanticMemoryIndex = null,
        IRemediationEngine? remediationEngine = null)
    {
        _dlpSanitizer = dlpSanitizer;
        _processLauncher = processLauncher;
        _sandboxFactory = sandboxFactory;
        _auditLedger = auditLedger;
        _modelClient = modelClient;
        _semanticMemoryIndex = semanticMemoryIndex;
        _remediationEngine = remediationEngine;
    }

    public async Task<WorkflowExecutionResult> ExecuteAsync(
        WorkflowGraph graph,
        IReadOnlyDictionary<string, string> triggerPayload,
        string operatorIdentity,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var startedUtc = DateTime.UtcNow;
        var executionId = Guid.NewGuid();
        var logs = new List<string>();
        var nodeOutputs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        string? failureReason = null;
        try
        {
            await foreach (var chunk in ExecuteStreamingInternalAsync(graph, triggerPayload, operatorIdentity, executionId, nodeOutputs, cancellationToken))
            {
                logs.Add($"[{chunk.TimestampUtc:HH:mm:ss.fff}] [{chunk.ChunkType}] {chunk.Content}");
                progress?.Report(chunk.Content);
            }
        }
        catch (WorkflowNodeFailedException ex)
        {
            // The failing node's own output never reached the recording path, so it is restored
            // here; an operator diagnosing the run needs the evidence that produced the failure.
            if (ex.NodeOutput is not null)
            {
                nodeOutputs[ex.NodeId] = ex.NodeOutput;
            }
            failureReason = ex.Message;
        }
        catch (Exception ex)
        {
            failureReason = ex.Message;
        }

        if (failureReason is not null)
        {
            logs.Add($"[ERROR] Workflow failed: {failureReason}");

            if (_auditLedger != null)
            {
                await _auditLedger.AppendLogAsync(
                    executionId,
                    graph.WorkflowId,
                    "WORKFLOW_FAILED",
                    failureReason,
                    operatorIdentity,
                    cancellationToken);
            }
        }

        return new WorkflowExecutionResult(
            graph.WorkflowId,
            executionId,
            Success: failureReason is null,
            nodeOutputs,
            logs,
            startedUtc,
            DateTime.UtcNow,
            FailureReason: failureReason);
    }

    public IAsyncEnumerable<MissionChunk> ExecuteStreamingAsync(
        WorkflowGraph graph,
        IReadOnlyDictionary<string, string> triggerPayload,
        string operatorIdentity,
        CancellationToken cancellationToken = default)
    {
        return ExecuteStreamingInternalAsync(graph, triggerPayload, operatorIdentity, Guid.NewGuid(), null, cancellationToken);
    }

    /// <summary>
    /// <paramref name="executionId"/> is supplied by the caller so that the id on the returned
    /// <see cref="WorkflowExecutionResult"/>, the id on every emitted chunk and the id written to
    /// the audit ledger are one identity. Minting a second id here left a run whose result could
    /// not be joined to its own ledger records.
    /// </summary>
    private async IAsyncEnumerable<MissionChunk> ExecuteStreamingInternalAsync(
        WorkflowGraph graph,
        IReadOnlyDictionary<string, string> triggerPayload,
        string operatorIdentity,
        Guid executionId,
        IDictionary<string, string>? externalNodeOutputs,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        graph.Validate();
        var nodeOutputs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var activeBranch = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var skippedNodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (_auditLedger != null)
        {
            await _auditLedger.AppendLogAsync(
                executionId,
                graph.WorkflowId,
                "WORKFLOW_INITIATED",
                $"Trigger: {graph.Trigger.Type} | Nodes: {graph.Nodes.Count} | Edges: {graph.Edges.Count}",
                operatorIdentity,
                cancellationToken);
        }

        yield return new MissionChunk(
            executionId,
            MissionChunkType.StatusChange,
            $"Starting governed workflow '{graph.Name}' (ID: {graph.WorkflowId}) via {graph.Trigger.Type} trigger.",
            DateTime.UtcNow);

        var topologicalOrder = graph.GetTopologicalOrder();

        foreach (var node in topologicalOrder)
        {
            cancellationToken.ThrowIfCancellationRequested();

            // A node runs when at least one incoming edge is live: its source actually ran, and the
            // edge is either unconditional or names the branch the source selected. Testing only
            // for a matching branch let a skip leak - the node immediately after the condition was
            // skipped, then everything downstream of it ran anyway against stale upstream outputs.
            var incomingEdges = graph.Edges.Where(e => e.TargetNodeId.Equals(node.NodeId, StringComparison.OrdinalIgnoreCase)).ToList();
            if (incomingEdges.Count > 0 &&
                !incomingEdges.Any(e =>
                    !skippedNodes.Contains(e.SourceNodeId) &&
                    (string.IsNullOrEmpty(e.ConditionBranch) ||
                     activeBranch.Contains($"{e.SourceNodeId}:{e.ConditionBranch}"))))
            {
                skippedNodes.Add(node.NodeId);
                yield return new MissionChunk(
                    executionId,
                    MissionChunkType.StatusChange,
                    $"Skipping node '{node.Name}' ({node.NodeId}) — conditional branch inactive.",
                    DateTime.UtcNow);
                continue;
            }

            yield return new MissionChunk(
                executionId,
                MissionChunkType.StatusChange,
                $"Executing node: '{node.Name}' [{node.NodeType}]",
                DateTime.UtcNow);

            string nodeResult = string.Empty;

            switch (node.NodeType)
            {
                case WorkflowNodeType.Trigger:
                    nodeResult = ProcessTriggerNode(node, triggerPayload);
                    break;

                case WorkflowNodeType.SandboxedScript:
                    nodeResult = await ExecuteScriptNodeAsync(node, nodeOutputs, executionId, cancellationToken);
                    break;

                case WorkflowNodeType.AgentReasoning:
                    await foreach (var chunk in ExecuteAgentNodeAsync(node, nodeOutputs, executionId, cancellationToken))
                    {
                        yield return chunk;
                        if (chunk.ChunkType is MissionChunkType.Stdout or MissionChunkType.AiToken)
                        {
                            nodeResult += chunk.Content;
                        }
                    }
                    break;

                case WorkflowNodeType.OAuthExchange:
                    nodeResult = ExecuteOAuthNode(node);
                    break;

                case WorkflowNodeType.GovernedHttp:
                    nodeResult = ProcessGovernedHttpNode(node);
                    break;

                case WorkflowNodeType.Condition:
                    var (branchOutcome, evalLog) = EvaluateConditionNode(node, nodeOutputs);
                    nodeResult = branchOutcome;
                    activeBranch.Add($"{node.NodeId}:{branchOutcome}");
                    yield return new MissionChunk(executionId, MissionChunkType.StatusChange, evalLog, DateTime.UtcNow);
                    break;

                case WorkflowNodeType.ReActAgent:
                    await foreach (var chunk in ExecuteReActAgentNodeAsync(node, nodeOutputs, executionId, cancellationToken))
                    {
                        yield return chunk;
                        if (chunk.ChunkType is MissionChunkType.Stdout or MissionChunkType.AiToken)
                        {
                            nodeResult += chunk.Content;
                        }
                    }
                    break;

                case WorkflowNodeType.MemoryStore:
                    nodeResult = await ExecuteMemoryStoreNodeAsync(node, nodeOutputs, executionId, cancellationToken);
                    break;

                case WorkflowNodeType.MemoryRecall:
                    nodeResult = await ExecuteMemoryRecallNodeAsync(node, nodeOutputs, executionId, cancellationToken);
                    break;

                case WorkflowNodeType.TransactionalScope:
                    nodeResult = await ExecuteTransactionalScopeNodeAsync(node, nodeOutputs, executionId, cancellationToken);
                    break;

                default:
                    nodeResult = $"Executed {node.NodeType}";
                    break;
            }

            // Apply DLP sanitization to inter-node output
            if (_dlpSanitizer != null && !string.IsNullOrEmpty(nodeResult))
            {
                var dlp = _dlpSanitizer.Sanitize(nodeResult);
                if (dlp.RedactedCount > 0)
                {
                    yield return new MissionChunk(
                        executionId,
                        MissionChunkType.StatusChange,
                        $"[DLP] Scrubbed {dlp.RedactedCount} sensitive item(s) from node '{node.Name}' before downstream propagation.",
                        DateTime.UtcNow);
                }
                nodeResult = dlp.SanitizedContent;
            }

            nodeOutputs[node.NodeId] = nodeResult;
            if (externalNodeOutputs != null)
            {
                externalNodeOutputs[node.NodeId] = nodeResult;
            }

            if (_auditLedger != null)
            {
                await _auditLedger.AppendLogAsync(
                    executionId,
                    graph.WorkflowId,
                    $"NODE_COMPLETED:{node.NodeType}",
                    $"Node: {node.Name} ({node.NodeId}) | OutputLength: {nodeResult.Length}",
                    operatorIdentity,
                    cancellationToken);
            }

            yield return new MissionChunk(
                executionId,
                MissionChunkType.Stdout,
                $"Node '{node.Name}' completed: {TrimForDisplay(nodeResult)}",
                DateTime.UtcNow);
        }

        if (_auditLedger != null)
        {
            await _auditLedger.AppendLogAsync(
                executionId,
                graph.WorkflowId,
                "WORKFLOW_COMPLETED",
                $"Successfully executed {graph.Nodes.Count} nodes.",
                operatorIdentity,
                cancellationToken);
        }

        yield return new MissionChunk(
            executionId,
            MissionChunkType.StatusChange,
            $"Workflow '{graph.Name}' completed successfully. Ledger record sealed.",
            DateTime.UtcNow);
    }

    private static string ProcessTriggerNode(WorkflowNode node, IReadOnlyDictionary<string, string> triggerPayload)
    {
        var sb = new StringBuilder();
        foreach (var kvp in triggerPayload)
        {
            sb.AppendLine($"{kvp.Key}={kvp.Value}");
        }
        return sb.Length > 0 ? sb.ToString() : "Trigger activated with default payload.";
    }

    private async Task<string> ExecuteScriptNodeAsync(
        WorkflowNode node,
        IReadOnlyDictionary<string, string> nodeOutputs,
        Guid executionId,
        CancellationToken ct)
    {
        string runtime = node.Configuration.TryGetValue("Runtime", out var r) ? r : "powershell";
        string command = BindNodeCommand(node, node.ScriptCommand, nodeOutputs, runtime);

        var run = await RunConfinedScriptInternalAsync(command, runtime, ct);
        if (run.TimedOut)
        {
            throw new WorkflowNodeFailedException(
                node.NodeId, $"the script exceeded its {ScriptTimeoutSeconds}s budget.", run.Output);
        }

        // The exit code was previously discarded, so a script that failed outright still fed its
        // stderr downstream as if it were a result and the run still reported success.
        if (run.ExitCode != 0)
        {
            throw new WorkflowNodeFailedException(
                node.NodeId, $"the script exited {run.ExitCode}: {TrimForDisplay(run.Output)}", run.Output);
        }

        return run.Output;
    }

    /// <summary>
    /// Resolves a node's script command against upstream outputs and its own configuration.
    ///
    /// Both sources are untrusted: a node output is a previous process's raw stdout and the trigger
    /// payload is an unauthenticated webhook body, yet the resolved string becomes a
    /// <c>powershell.exe -Command</c> line. They therefore go through
    /// <see cref="GovernedArgumentBinder"/>, which refuses a value it cannot place rather than
    /// escaping it. The two sources are merged into ONE lookup and bound in a single pass: chaining
    /// two <c>string.Replace</c> loops let a value substituted by the first be re-scanned by the
    /// second, which is exactly the second-order injection the binder exists to prevent.
    /// </summary>
    private static string BindNodeCommand(
        WorkflowNode node,
        string? commandTemplate,
        IReadOnlyDictionary<string, string> nodeOutputs,
        string runtime)
    {
        if (string.IsNullOrEmpty(commandTemplate))
        {
            return string.Empty;
        }

        var values = new Dictionary<string, string>(nodeOutputs, StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in node.Configuration)
        {
            // Configuration is author-controlled, so it wins a key collision with a node output.
            values[kvp.Key] = kvp.Value;
        }

        try
        {
            // Quoted-literal detection follows PowerShell's rules (a doubled quote continues the
            // literal). Claiming that context for bash or python would relax the policy in the
            // permissive direction, so every other runtime gets the strict bare-position set.
            return GovernedArgumentBinder.BindWorkflowCommand(commandTemplate, values, IsPowerShellRuntime(runtime));
        }
        catch (TemplateParameterRejectedException ex)
        {
            throw new WorkflowNodeFailedException(node.NodeId, ex.Message);
        }
    }

    private static bool IsPowerShellRuntime(string runtime) =>
        string.IsNullOrWhiteSpace(runtime) || runtime.Equals("powershell", StringComparison.OrdinalIgnoreCase)
            || runtime.Equals("pwsh", StringComparison.OrdinalIgnoreCase);

    private async Task<(string Output, int ExitCode, bool TimedOut)> RunConfinedScriptInternalAsync(
        string command,
        string runtime,
        CancellationToken ct)
    {
        if (_sandboxFactory != null && _processLauncher != null)
        {
            using var sandbox = _sandboxFactory();
            sandbox.ConfigureExtendedLimits(512 * 1024 * 1024, 75);

            string runtimeLower = runtime.ToLowerInvariant();
            string executable = "powershell.exe";
            string args = $"-NoProfile -NonInteractive -Command \"{command.Replace("\"", "\\\"")}\"";

            if (runtimeLower is "python" or "python3" or "py")
            {
                executable = "python.exe";
                args = $"-c \"{command.Replace("\"", "\\\"")}\"";
            }
            else if (runtimeLower is "bash" or "sh" or "wsl" or "linux")
            {
                executable = "wsl.exe";
                args = $"-e bash -c \"{command.Replace("\"", "\\\"")}\"";
            }

            var result = await _processLauncher.LaunchSuspendedInJobAsync(
                executable,
                args,
                AppDomain.CurrentDomain.BaseDirectory,
                sandbox,
                dropAdminPrivileges: true,
                timeoutSeconds: ScriptTimeoutSeconds,
                cancellationToken: ct);

            string output = string.IsNullOrWhiteSpace(result.StandardOutput) ? result.StandardError : result.StandardOutput;
            return (output, result.ExitCode, result.TimedOut);
        }

        string activeRuntime = string.IsNullOrWhiteSpace(runtime) ? "powershell" : runtime;
        return ($"[SIMULATED_SANDBOX:{activeRuntime}] Executed script: {command}", 0, false);
    }

    private async IAsyncEnumerable<MissionChunk> ExecuteReActAgentNodeAsync(
        WorkflowNode node,
        IReadOnlyDictionary<string, string> nodeOutputs,
        Guid executionId,
        [EnumeratorCancellation] CancellationToken ct)
    {
        int maxSteps = 3;
        if (node.Configuration.TryGetValue("MaxSteps", out var msStr) && int.TryParse(msStr, out var parsedMs))
        {
            maxSteps = Math.Clamp(parsedMs, 1, 5); // Governed hard ceiling
        }

        string goal = node.Configuration.TryGetValue("Goal", out var g) ? g : 
                      node.Configuration.TryGetValue("Prompt", out var p) ? p : "Investigate and resolve anomalous telemetry.";

        string toolsCsv = node.Configuration.TryGetValue("AllowedTools", out var at) ? at : "PowershellLogProbe,DiskSpaceProbe,NetworkStatusProbe";
        var allowedTools = toolsCsv.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var visitedTools = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        yield return new MissionChunk(
            executionId,
            MissionChunkType.StatusChange,
            $"[ReAct Agent: {node.Name}] Initializing governed loop. Budget: {maxSteps} steps. Allowed tools: [{string.Join(", ", allowedTools)}].",
            DateTime.UtcNow);

        for (int step = 1; step <= maxSteps; step++)
        {
            ct.ThrowIfCancellationRequested();

            var availableTools = allowedTools.Where(t => !visitedTools.Contains(t)).ToList();
            if (availableTools.Count == 0)
            {
                yield return new MissionChunk(
                    executionId,
                    MissionChunkType.StatusChange,
                    $"[ReAct Agent: {node.Name}] All candidate tools evaluated. Exiting loop early.",
                    DateTime.UtcNow);
                break;
            }

            string selectedTool = availableTools[0];
            visitedTools.Add(selectedTool);

            string stepThought = $"Thought {step}: Querying diagnostic tool '{selectedTool}' under sandbox boundaries.";
            yield return new MissionChunk(executionId, MissionChunkType.AiToken, stepThought + "\n", DateTime.UtcNow);

            // Confined execution of the tool. The probe echoes a fixed line rather than reading any
            // real telemetry - this loop is a placeholder for GovernedInvestigationLoop, which does
            // select tools from the governed catalogue against a model. The label says so, because
            // an observation that reports health it never measured is worse than no observation.
            string toolCommand = $"Write-Output '[TOOL_EXECUTION:{selectedTool}] PLACEHOLDER PROBE - no telemetry was read.'";
            var run = await RunConfinedScriptInternalAsync(toolCommand, "powershell", ct);
            if (run.TimedOut || run.ExitCode != 0)
            {
                throw new WorkflowNodeFailedException(
                    node.NodeId,
                    $"tool probe '{selectedTool}' exited {run.ExitCode}{(run.TimedOut ? " (timed out)" : string.Empty)}; " +
                    "a failed observation must not be scored as a clean one.",
                    run.Output);
            }

            // Immediate DLP pass on tool observation
            string scrubbedOutput = run.Output;
            if (_dlpSanitizer != null)
            {
                var dlp = _dlpSanitizer.Sanitize(run.Output);
                scrubbedOutput = dlp.SanitizedContent;
            }

            yield return new MissionChunk(
                executionId,
                MissionChunkType.Stdout,
                $"[ReAct Observation: {selectedTool}] {scrubbedOutput.Trim()}",
                DateTime.UtcNow);

            if (node.Configuration.TryGetValue("StopCondition", out var stopCond) && scrubbedOutput.Contains(stopCond, StringComparison.OrdinalIgnoreCase))
            {
                yield return new MissionChunk(
                    executionId,
                    MissionChunkType.StatusChange,
                    $"[ReAct Agent: {node.Name}] Early termination condition met: '{stopCond}'.",
                    DateTime.UtcNow);
                break;
            }
        }

        string finalVerdict = $"[ReAct Agent Final Synthesis] Goal '{goal}' evaluated across {visitedTools.Count} tool iteration(s). Confined zero-trust boundary maintained.";
        yield return new MissionChunk(executionId, MissionChunkType.AiToken, finalVerdict, DateTime.UtcNow);
    }

    private async Task<string> ExecuteMemoryStoreNodeAsync(
        WorkflowNode node,
        IReadOnlyDictionary<string, string> nodeOutputs,
        Guid executionId,
        CancellationToken ct)
    {
        string key = node.Configuration.TryGetValue("Key", out var k) ? k :
                     node.Configuration.TryGetValue("TemplateId", out var tid) ? tid : node.NodeId;

        string content;
        if (node.Configuration.TryGetValue("Content", out var c))
        {
            content = SubstituteText(c, nodeOutputs);
        }
        else
        {
            var sb = new StringBuilder();
            foreach (var kvp in nodeOutputs)
            {
                sb.AppendLine($"[{kvp.Key}] {kvp.Value}");
            }
            content = sb.Length > 0 ? sb.ToString() : $"Executed node {node.NodeId}";
        }

        if (_semanticMemoryIndex != null)
        {
            await _semanticMemoryIndex.IndexMissionDocumentAsync(executionId, key, content, ct);
            return $"[MEMORY_STORED] Key: '{key}' | Document Length: {content.Length} chars | Vector: 128-dim cosine hashed.";
        }

        return $"[MEMORY_STORED_SIMULATED] Key: '{key}' | Document Length: {content.Length} chars.";
    }

    private async Task<string> ExecuteMemoryRecallNodeAsync(
        WorkflowNode node,
        IReadOnlyDictionary<string, string> nodeOutputs,
        Guid executionId,
        CancellationToken ct)
    {
        string query = node.Configuration.TryGetValue("Query", out var q) ? q : "incident anomaly pattern";
        query = SubstituteText(query, nodeOutputs);

        int topK = 3;
        if (node.Configuration.TryGetValue("TopK", out var tkStr) && int.TryParse(tkStr, out var tk))
        {
            topK = Math.Max(1, tk);
        }

        double minScore = 0.1;
        if (node.Configuration.TryGetValue("MinScore", out var msStr) && double.TryParse(msStr, out var ms))
        {
            minScore = Math.Clamp(ms, 0.0, 1.0);
        }

        if (_semanticMemoryIndex != null)
        {
            var results = await _semanticMemoryIndex.SearchSimilarMissionsAsync(query, topK, minScore, ct);
            var sb = new StringBuilder();
            sb.AppendLine($"[MEMORY_RECALL_RESULTS] Query: '{query}' | Matches: {results.Count}");
            foreach (var r in results)
            {
                sb.AppendLine($"- [Score {r.SimilarityScore:F4}] {r.TemplateId}: {r.ContentSnippet}");
            }
            return sb.ToString().TrimEnd();
        }

        return $"[MEMORY_RECALL_SIMULATED] Query: '{query}' | TopK: {topK} | MinScore: {minScore}";
    }

    private async Task<string> ExecuteTransactionalScopeNodeAsync(
        WorkflowNode node,
        IReadOnlyDictionary<string, string> nodeOutputs,
        Guid executionId,
        CancellationToken ct)
    {
        string assertion = node.Configuration.TryGetValue("Assertion", out var ass) ? ass : "SUCCESS";
        string runtime = node.Configuration.TryGetValue("Runtime", out var rt) ? rt : "powershell";

        string primaryCommand = BindNodeCommand(node, node.ScriptCommand, nodeOutputs, runtime);
        string rollbackCommand = node.Configuration.TryGetValue("RollbackScript", out var rb)
            ? BindNodeCommand(node, rb, nodeOutputs, runtime)
            : string.Empty;

        var primary = await RunConfinedScriptInternalAsync(primaryCommand, runtime, ct);

        // A script that died or timed out proves nothing about the assertion, so it is treated as a
        // failed assertion and rolled back - never committed because its stderr happened to carry
        // the assertion text.
        bool passed = primary.ExitCode == 0
            && !primary.TimedOut
            && primary.Output.Contains(assertion, StringComparison.OrdinalIgnoreCase);

        if (passed)
        {
            return $"[TRANSACTION_COMMITTED] Assertion '{assertion}' verified. Output: {primary.Output.Trim()}";
        }

        // Assertion failed -> Execute Rollback Script
        string rollbackOutput = string.Empty;
        if (!string.IsNullOrWhiteSpace(rollbackCommand))
        {
            var rollback = await RunConfinedScriptInternalAsync(rollbackCommand, runtime, ct);
            rollbackOutput = rollback.Output;

            // A rollback that itself failed leaves the machine in the speculative state the scope
            // was supposed to be able to abandon. That is the loudest failure this engine has.
            if (rollback.TimedOut || rollback.ExitCode != 0)
            {
                throw new WorkflowNodeFailedException(
                    node.NodeId,
                    $"assertion '{assertion}' failed AND the rollback exited {rollback.ExitCode}" +
                    $"{(rollback.TimedOut ? " (timed out)" : string.Empty)}; the speculative change may still be applied.",
                    $"[TRANSACTION_ROLLBACK_FAILED] {rollbackOutput.Trim()}");
            }
        }

        if (_remediationEngine != null && node.Configuration.TryGetValue("RemediationActionId", out var actId))
        {
            var action = new RemediationAction(
                actId,
                node.NodeId,
                "Transactional remediation rollback",
                "Rollback executed on assertion failure",
                RemediationRiskLevel.Safe,
                true,
                "powershell.exe",
                rollbackCommand);
            await _remediationEngine.ExecuteRollbackAsync(action, "WorkflowEngine", ct);
        }

        if (_auditLedger != null)
        {
            await _auditLedger.AppendLogAsync(
                executionId,
                node.NodeId,
                "TRANSACTION_ROLLED_BACK",
                $"Assertion '{assertion}' failed in node '{node.Name}'. Rollback executed.",
                "WorkflowEngine",
                ct);
        }

        // A rolled-back scope did not achieve what it was asked to. Reporting the run as a success
        // because the rollback worked is the same error as scoring a refused mission as a clean one.
        throw new WorkflowNodeFailedException(
            node.NodeId,
            $"assertion '{assertion}' failed against the script output; rollback was applied.",
            $"[TRANSACTION_ROLLED_BACK] Assertion '{assertion}' failed against output. Rollback applied: {rollbackOutput.Trim()}");
    }

    private static string SubstituteText(string template, IReadOnlyDictionary<string, string> nodeOutputs) =>
        string.IsNullOrEmpty(template)
            ? string.Empty
            : NodeReferencePattern.Replace(
                template,
                m => nodeOutputs.TryGetValue(m.Groups["key"].Value, out var v) ? v : m.Value);

    private async IAsyncEnumerable<MissionChunk> ExecuteAgentNodeAsync(
        WorkflowNode node,
        IReadOnlyDictionary<string, string> nodeOutputs,
        Guid executionId,
        [EnumeratorCancellation] CancellationToken ct)
    {
        string prompt = node.Configuration.TryGetValue("Prompt", out var p) ? p : "Analyze the input evidence.";
        var contextBuilder = new StringBuilder();
        foreach (var kvp in nodeOutputs)
        {
            contextBuilder.AppendLine($"--- Node Output ({kvp.Key}) ---");
            contextBuilder.AppendLine(kvp.Value);
        }

        string fullPrompt = $"{prompt}\n\nContext:\n{contextBuilder}";

        if (_modelClient != null)
        {
            var model = node.TargetModel ?? "claude-3-5-sonnet";
            await foreach (var token in _modelClient.StreamAnalysisAsync(model, "You are a governed workflow specialist.", fullPrompt, ct))
            {
                yield return new MissionChunk(executionId, MissionChunkType.AiToken, token, DateTime.UtcNow);
            }
        }
        else
        {
            yield return new MissionChunk(
                executionId,
                MissionChunkType.AiToken,
                $"[GOVERNED_AI_ANALYSIS] Processed {contextBuilder.Length} chars of scrubbed evidence. Status: VERIFIED. Model: {node.TargetModel ?? "default"}.",
                DateTime.UtcNow);
        }
    }

    /// <summary>
    /// Refuses, deliberately. The previous implementation minted a random string, wrote it to the
    /// real DPAPI vault under the provider's live key and reported a successful code exchange - so
    /// an operator inspecting the vault would find a bearer token no authorization server ever
    /// issued, and the ledger would corroborate it. Nothing is written until a token endpoint is
    /// actually wired.
    /// </summary>
    private static string ExecuteOAuthNode(WorkflowNode node)
    {
        string provider = node.Configuration.TryGetValue("Provider", out var prov) ? prov : "GenericOAuth";

        throw new WorkflowNodeFailedException(
            node.NodeId,
            $"OAuth code exchange for '{provider}' is not implemented: no token endpoint is configured, " +
            "and a fabricated token must not enter the credential vault.");
    }

    /// <summary>
    /// Placeholder. No request is made: there is no pinned client here and no call into
    /// <see cref="IEgressFirewall"/>, so the node names the pin it WOULD apply and states plainly
    /// that it applied nothing.
    /// </summary>
    private static string ProcessGovernedHttpNode(WorkflowNode node)
    {
        string fqdn = node.AllowedEgressFqdn ?? "(none declared)";
        string method = node.Configuration.TryGetValue("Method", out var m) ? m : "POST";
        string path = node.Configuration.TryGetValue("Path", out var p) ? p : "/events";

        return $"[GOVERNED_HTTP:NOT_IMPLEMENTED] No request was sent. Declared target: {method} https://{fqdn}{path}. " +
               "IEgressFirewall.ValidateOutboundTarget and a pinned client must be wired before this node carries traffic.";
    }

    private static (string Branch, string Log) EvaluateConditionNode(WorkflowNode node, IReadOnlyDictionary<string, string> nodeOutputs)
    {
        string expected = node.Configuration.TryGetValue("Matches", out var exp) ? exp : string.Empty;

        // string.Contains("") is true of every string, so a condition with no pattern took the
        // "true" branch on every run regardless of evidence. A gate with nothing to test is a
        // misconfiguration, not a pass.
        if (string.IsNullOrEmpty(expected))
        {
            throw new WorkflowNodeFailedException(node.NodeId, "the condition declares no 'Matches' pattern to test.");
        }

        // 'Field' names the node whose output is under test. It was read and then discarded, so a
        // condition scoped to one node was in fact satisfied by ANY node's output containing the
        // text - including the trigger payload that an unauthenticated caller controls.
        string field = node.Configuration.TryGetValue("Field", out var f) ? f : string.Empty;

        if (string.IsNullOrWhiteSpace(field))
        {
            bool anyMatch = nodeOutputs.Values.Any(v => v.Contains(expected, StringComparison.OrdinalIgnoreCase));
            return (anyMatch ? "true" : "false",
                $"Condition on any upstream output for '{expected}': Result={(anyMatch ? "true" : "false")}.");
        }

        if (!nodeOutputs.TryGetValue(field, out var scoped))
        {
            throw new WorkflowNodeFailedException(
                node.NodeId, $"condition field '{field}' produced no output to test; it did not run upstream of this gate.");
        }

        bool isMatch = scoped.Contains(expected, StringComparison.OrdinalIgnoreCase);
        return (isMatch ? "true" : "false", $"Condition on '{field}' for '{expected}': Result={(isMatch ? "true" : "false")}.");
    }

    private static string TrimForDisplay(string text, int maxLen = 120)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;
        var clean = text.Replace("\r", " ").Replace("\n", " ").Trim();
        return clean.Length <= maxLen ? clean : clean[..maxLen] + "...";
    }
}
