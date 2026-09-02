using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core.Crew;

/// <summary>
/// Production-hardened Governed Multi-Agent Crew Orchestration Engine for SPLAT.
/// Enforces kernel-sandboxed tool execution, anti-deadlock cycle detection, in-memory DLP sanitization,
/// and SHA-256 chained cryptographic audit ledgers across multi-agent teams.
/// </summary>
public sealed class GovernedCrewEngine : IGovernedCrewEngine
{
    private const int MaxContextCharacters = 16000;
    private readonly IMissionExecutionEngine _missionEngine;
    private readonly ITemplateRegistry _templateRegistry;
    private readonly IAuditLedger _auditLedger;
    private readonly IDataLossPreventionSanitizer? _dlpSanitizer;
    private readonly ISemanticMemoryIndex? _semanticMemoryIndex;
    private readonly IDiagnosticFindingsExtractor _findingsExtractor;
    private readonly IModelStreamClient? _modelClient;

    public GovernedCrewEngine(
        IMissionExecutionEngine missionEngine,
        ITemplateRegistry templateRegistry,
        IAuditLedger auditLedger,
        IDataLossPreventionSanitizer? dlpSanitizer = null,
        ISemanticMemoryIndex? semanticMemoryIndex = null,
        IDiagnosticFindingsExtractor? findingsExtractor = null,
        IModelStreamClient? modelClient = null)
    {
        _missionEngine = missionEngine ?? throw new ArgumentNullException(nameof(missionEngine));
        _templateRegistry = templateRegistry ?? throw new ArgumentNullException(nameof(templateRegistry));
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _dlpSanitizer = dlpSanitizer;
        _semanticMemoryIndex = semanticMemoryIndex;
        _findingsExtractor = findingsExtractor ?? new JsonFindingsExtractor();
        _modelClient = modelClient;
    }

    public IAsyncEnumerable<MissionChunk> ExecuteCrewAsync(
        GovernedCrewDefinition crew,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        CancellationToken cancellationToken = default)
        // Streaming-only callers get a throwaway accumulator; RunCrewAsync passes its own so
        // per-task results survive the iterator instead of dying inside it.
        => ExecuteCrewCoreAsync(crew, parameters, operatorIdentity, new CrewRunAccumulator(), cancellationToken);

    private async IAsyncEnumerable<MissionChunk> ExecuteCrewCoreAsync(
        GovernedCrewDefinition crew,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        CrewRunAccumulator accumulator,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        crew.Validate();
        var crewMissionId = Guid.NewGuid();
        var stopwatch = Stopwatch.StartNew();

        await _auditLedger.AppendLogAsync(
            crewMissionId,
            crew.CrewId,
            "CREW_ORCHESTRATION_INITIATED",
            $"Process: {crew.ProcessType} | Agents: {crew.Agents.Count} | Tasks: {crew.Tasks.Count} | Operator: {operatorIdentity}",
            operatorIdentity,
            cancellationToken);

        yield return new MissionChunk(
            crewMissionId,
            MissionChunkType.StatusChange,
            $"👥 [Governed Crew Initialized] '{crew.Name}' (Process: {crew.ProcessType}, Agents: {crew.Agents.Count}, Tasks: {crew.Tasks.Count})",
            DateTime.UtcNow);

        if (crew.ProcessType == CrewProcessType.Sequential)
        {
            await foreach (var chunk in ExecuteSequentialAsync(crew, crewMissionId, parameters, operatorIdentity, accumulator, cancellationToken))
            {
                yield return chunk;
            }
        }
        else
        {
            await foreach (var chunk in ExecuteHierarchicalAsync(crew, crewMissionId, parameters, operatorIdentity, accumulator, cancellationToken))
            {
                yield return chunk;
            }
        }

        stopwatch.Stop();
        yield return new MissionChunk(
            crewMissionId,
            MissionChunkType.Completed,
            $"✅ [Governed Crew Completed] '{crew.Name}' finished in {stopwatch.ElapsedMilliseconds}ms.",
            DateTime.UtcNow);
    }

    private async IAsyncEnumerable<MissionChunk> ExecuteSequentialAsync(
        GovernedCrewDefinition crew,
        Guid crewMissionId,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        CrewRunAccumulator accumulator,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var taskResults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < crew.Tasks.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var task = crew.Tasks[i];
            var agent = crew.Agents.FirstOrDefault(a => string.Equals(a.AgentId, task.AssignedAgentId, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException($"Assigned agent '{task.AssignedAgentId}' not found in crew.");

            yield return new MissionChunk(
                crewMissionId,
                MissionChunkType.StatusChange,
                $"🎯 [Task {i + 1}/{crew.Tasks.Count}] '{task.TaskId}': Assigned to Agent '{agent.Role}' ({agent.AgentId})",
                DateTime.UtcNow);

            // 1. Resolve Upstream Context Dependencies
            var contextBuilder = new StringBuilder();
            if (task.ContextTaskIds != null && task.ContextTaskIds.Count > 0)
            {
                foreach (var depId in task.ContextTaskIds)
                {
                    if (taskResults.TryGetValue(depId, out var depOutput))
                    {
                        contextBuilder.AppendLine($"--- [Context from Task '{depId}'] ---");
                        contextBuilder.AppendLine(depOutput);
                    }
                }
            }

            // 2. DLP Sanitization on Context
            var rawContext = contextBuilder.ToString();
            var sanitizedContext = _dlpSanitizer != null ? _dlpSanitizer.Sanitize(rawContext).SanitizedContent : rawContext;
            if (sanitizedContext.Length > MaxContextCharacters)
            {
                sanitizedContext = sanitizedContext.Substring(0, MaxContextCharacters) + "... [Context Truncated for Token Economy]";
            }

            // 3. Resolve Governed Tool Template
            var templateId = task.TemplateId ?? agent.AssignedTemplateIds?.FirstOrDefault();
            SingleToolTemplate? template = null;
            if (!string.IsNullOrEmpty(templateId))
            {
                template = await _templateRegistry.GetTemplateByIdAsync(templateId, cancellationToken);
            }

            var taskStopwatch = Stopwatch.StartNew();
            var taskEvidence = new StringBuilder();
            var taskSuccess = true;

            if (template != null)
            {
                // Execute via SPLAT IMissionExecutionEngine (Job Sandbox + Restricted Token + ACL Jail)
                var stageParams = new Dictionary<string, string>(parameters, StringComparer.OrdinalIgnoreCase)
                {
                    ["TaskDescription"] = task.Description,
                    ["ExpectedOutput"] = task.ExpectedOutput,
                    ["AgentSystemPrompt"] = agent.BuildSystemPrompt(),
                    ["UpstreamContext"] = sanitizedContext
                };

                await foreach (var chunk in _missionEngine.ExecuteMissionAsync(template, stageParams, operatorIdentity, cancellationToken))
                {
                    yield return chunk;
                    if (chunk.ChunkType is MissionChunkType.Stdout or MissionChunkType.AiToken)
                    {
                        taskEvidence.Append(chunk.Content);
                    }
                    else if (chunk.ChunkType is MissionChunkType.Stderr)
                    {
                        taskSuccess = false;
                    }
                }
            }
            else if (_modelClient != null)
            {
                // Analytical execution without dedicated native tool. The agent prompt travels in
                // the system slot only - duplicating it into the user prompt doubles token spend.
                var prompt = $"TASK: {task.Description}\nEXPECTED OUTPUT: {task.ExpectedOutput}\n\nCONTEXT:\n{sanitizedContext}";
                await foreach (var token in _modelClient.StreamAnalysisAsync(agent.TargetModel, agent.BuildSystemPrompt(), prompt, cancellationToken))
                {
                    taskEvidence.Append(token);
                    yield return new MissionChunk(crewMissionId, MissionChunkType.AiToken, token, DateTime.UtcNow);
                }
            }
            else
            {
                // No governed template and no model client: fabricating a success string here would
                // flow a forged completed-work entry into the non-repudiation ledger. Record the
                // task as unexecutable instead.
                taskSuccess = false;
                yield return new MissionChunk(
                    crewMissionId,
                    MissionChunkType.Stderr,
                    $"⛔ [Task Unexecutable] '{task.TaskId}' has no resolvable governed template and no model client is configured.",
                    DateTime.UtcNow);
            }

            taskStopwatch.Stop();
            var taskResult = RecordTaskResult(
                accumulator, task, agent, taskEvidence.ToString(), taskSuccess, taskStopwatch.ElapsedMilliseconds, template);
            taskResults[task.TaskId] = taskResult.SanitizedOutput;

            // Audit Ledger Record per Task
            await _auditLedger.AppendLogAsync(
                crewMissionId,
                template?.TemplateId ?? "analytical-task",
                "CREW_TASK_COMPLETED",
                $"Task '{task.TaskId}' completed by Agent '{agent.AgentId}' (Status: {taskResult.ExtractedFindings?.OverallStatus}, Success: {taskSuccess}, Duration: {taskStopwatch.ElapsedMilliseconds}ms)",
                operatorIdentity,
                cancellationToken);

            // Index in semantic memory if enabled
            if (crew.EnableSemanticMemory && _semanticMemoryIndex != null && !string.IsNullOrWhiteSpace(taskResult.SanitizedOutput))
            {
                try
                {
                    await _semanticMemoryIndex.IndexMissionDocumentAsync(
                        crewMissionId,
                        template?.TemplateId ?? task.TaskId,
                        $"[Crew: {crew.Name} | Task: {task.TaskId} | Agent: {agent.Role}]\n{taskResult.SanitizedOutput}",
                        cancellationToken);
                }
                catch
                {
                    // Non-blocking memory indexing
                }
            }

            if (!taskSuccess && !task.ContinueOnFailure)
            {
                yield return new MissionChunk(
                    crewMissionId,
                    MissionChunkType.Stderr,
                    $"⛔ [Crew Execution Aborted] Task '{task.TaskId}' failed and ContinueOnFailure is false.",
                    DateTime.UtcNow);
                yield break;
            }
        }
    }

    private async IAsyncEnumerable<MissionChunk> ExecuteHierarchicalAsync(
        GovernedCrewDefinition crew,
        Guid crewMissionId,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        CrewRunAccumulator accumulator,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var manager = crew.ManagerAgent ?? throw new InvalidOperationException("ManagerAgent is required for hierarchical process.");

        // Anti-livelock budget: each (task, agent) pair may be dispatched at most twice - the
        // initial attempt plus one retry after failure. The manager (model-driven or deterministic)
        // never gets a third dispatch of the same pair, so a persistently failing task cannot burn
        // the iteration budget in a retry livelock.
        const int MaxDispatchesPerPair = 2;
        var dispatchCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var settledTaskIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CrewTaskResult? lastResult = null;
        var iteration = 0;
        bool managerIsModelDriven = _modelClient != null;

        yield return new MissionChunk(
            crewMissionId,
            MissionChunkType.StatusChange,
            managerIsModelDriven
                ? $"👑 [Manager Dispatch] Manager Agent '{manager.Role}' selecting tasks via {manager.TargetModel}. Max iterations: {crew.MaxCrewIterations}"
                : $"👑 [Manager Dispatch] No model client configured; manager '{manager.Role}' dispatching tasks in declared order. Max iterations: {crew.MaxCrewIterations}",
            DateTime.UtcNow);

        while (iteration < crew.MaxCrewIterations)
        {
            iteration++;
            cancellationToken.ThrowIfCancellationRequested();

            // Successful tasks and skipped continuable failures leave the pending pool; failed
            // non-continuable tasks stay in it so the manager may retry them within the budget.
            var pendingTasks = crew.Tasks.Where(t => !settledTaskIds.Contains(t.TaskId)).ToList();
            if (pendingTasks.Count == 0) break;

            GovernedCrewTask selectedTask;
            string selectionReason;
            if (managerIsModelDriven)
            {
                var decision = await ManagerDecideAsync(crew, manager, pendingTasks, lastResult, cancellationToken);
                var chosen = decision.TemplateId is null
                    ? null
                    : pendingTasks.FirstOrDefault(t => string.Equals(t.TaskId, decision.TemplateId, StringComparison.OrdinalIgnoreCase));

                if (!decision.ShouldContinue || chosen is null)
                {
                    await _auditLedger.AppendLogAsync(
                        crewMissionId,
                        "manager-core",
                        "CREW_MANAGER_CONCLUDED",
                        $"Manager stopped dispatching after {iteration - 1} turn(s): {decision.Reason}",
                        operatorIdentity,
                        cancellationToken);

                    yield return new MissionChunk(
                        crewMissionId,
                        MissionChunkType.StatusChange,
                        $"👑 [Manager Concluded] {decision.Reason}",
                        DateTime.UtcNow);
                    break;
                }

                selectedTask = chosen;
                selectionReason = decision.Reason;
            }
            else
            {
                selectedTask = pendingTasks[0];
                selectionReason = "Deterministic declared-order dispatch (no model client configured).";
            }

            var targetAgent = crew.Agents.FirstOrDefault(a => string.Equals(a.AgentId, selectedTask.AssignedAgentId, StringComparison.OrdinalIgnoreCase))
                ?? (string.Equals(manager.AgentId, selectedTask.AssignedAgentId, StringComparison.OrdinalIgnoreCase)
                    ? manager
                    : throw new InvalidOperationException($"Assigned agent '{selectedTask.AssignedAgentId}' not found in crew."));

            var dispatchKey = $"{selectedTask.TaskId}->{targetAgent.AgentId}";
            var priorDispatches = dispatchCounts.GetValueOrDefault(dispatchKey);
            if (priorDispatches >= MaxDispatchesPerPair)
            {
                accumulator.CycleHalted = true;

                yield return new MissionChunk(
                    crewMissionId,
                    MissionChunkType.Stderr,
                    $"⚠️ [Anti-Livelock Halt] Task '{selectedTask.TaskId}' has already been dispatched to Agent '{targetAgent.AgentId}' {priorDispatches} times without settling. Halting delegation to prevent a retry livelock.",
                    DateTime.UtcNow);

                await _auditLedger.AppendLogAsync(
                    crewMissionId,
                    "manager-core",
                    "CREW_DELEGATION_CYCLE_HALTED",
                    $"Repeat dispatch refused for Task '{selectedTask.TaskId}' -> Agent '{targetAgent.AgentId}' (Iteration {iteration}, prior dispatches: {priorDispatches})",
                    operatorIdentity,
                    cancellationToken);
                break;
            }

            dispatchCounts[dispatchKey] = priorDispatches + 1;

            yield return new MissionChunk(
                crewMissionId,
                MissionChunkType.StatusChange,
                $"👑 [Manager Delegation] Turn {iteration}: Dispatching Task '{selectedTask.TaskId}' to '{targetAgent.Role}' — {selectionReason}",
                DateTime.UtcNow);

            // Execute subtask with target agent
            var templateId = selectedTask.TemplateId ?? targetAgent.AssignedTemplateIds?.FirstOrDefault();
            SingleToolTemplate? template = null;
            if (!string.IsNullOrEmpty(templateId))
            {
                template = await _templateRegistry.GetTemplateByIdAsync(templateId, cancellationToken);
            }

            var taskStopwatch = Stopwatch.StartNew();
            var taskEvidence = new StringBuilder();
            var taskSuccess = true;

            if (template != null)
            {
                var stageParams = new Dictionary<string, string>(parameters, StringComparer.OrdinalIgnoreCase)
                {
                    ["TaskDescription"] = selectedTask.Description,
                    ["ExpectedOutput"] = selectedTask.ExpectedOutput,
                    ["AgentSystemPrompt"] = targetAgent.BuildSystemPrompt()
                };

                await foreach (var chunk in _missionEngine.ExecuteMissionAsync(template, stageParams, operatorIdentity, cancellationToken))
                {
                    yield return chunk;
                    if (chunk.ChunkType is MissionChunkType.Stdout or MissionChunkType.AiToken)
                    {
                        taskEvidence.Append(chunk.Content);
                    }
                    else if (chunk.ChunkType is MissionChunkType.Stderr)
                    {
                        taskSuccess = false;
                    }
                }
            }
            else if (_modelClient != null)
            {
                var prompt = $"TASK: {selectedTask.Description}\nEXPECTED OUTPUT: {selectedTask.ExpectedOutput}";
                await foreach (var token in _modelClient.StreamAnalysisAsync(targetAgent.TargetModel, targetAgent.BuildSystemPrompt(), prompt, cancellationToken))
                {
                    taskEvidence.Append(token);
                    yield return new MissionChunk(crewMissionId, MissionChunkType.AiToken, token, DateTime.UtcNow);
                }
            }
            else
            {
                // No governed template and no model client: fabricating a "Completed task" string
                // here would forge a completed-work entry into the non-repudiation ledger. Record
                // the task as unexecutable instead.
                taskSuccess = false;
                yield return new MissionChunk(
                    crewMissionId,
                    MissionChunkType.Stderr,
                    $"⛔ [Task Unexecutable] '{selectedTask.TaskId}' has no resolvable governed template and no model client is configured.",
                    DateTime.UtcNow);
            }

            taskStopwatch.Stop();
            lastResult = RecordTaskResult(
                accumulator, selectedTask, targetAgent, taskEvidence.ToString(), taskSuccess, taskStopwatch.ElapsedMilliseconds, template);

            if (taskSuccess || selectedTask.ContinueOnFailure)
            {
                settledTaskIds.Add(selectedTask.TaskId);
            }

            await _auditLedger.AppendLogAsync(
                crewMissionId,
                template?.TemplateId ?? "manager-hierarchical-dispatch",
                "CREW_HIERARCHICAL_TASK_DISPATCHED",
                $"Manager assigned '{selectedTask.TaskId}' to '{targetAgent.AgentId}' (Iteration {iteration}, Success: {taskSuccess}, Status: {lastResult.ExtractedFindings?.OverallStatus}). Reason: {selectionReason}",
                operatorIdentity,
                cancellationToken);
        }
    }

    public async Task<CrewExecutionResult> RunCrewAsync(
        GovernedCrewDefinition crew,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        IProgress<MissionChunk>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var accumulator = new CrewRunAccumulator();
        var summaryBuilder = new StringBuilder();
        var stopwatch = Stopwatch.StartNew();
        var missionId = Guid.Empty;

        await foreach (var chunk in ExecuteCrewCoreAsync(crew, parameters, operatorIdentity, accumulator, cancellationToken))
        {
            if (missionId == Guid.Empty) missionId = chunk.MissionId;
            progress?.Report(chunk);

            if (chunk.ChunkType == MissionChunkType.Stdout || chunk.ChunkType == MissionChunkType.AiToken)
            {
                summaryBuilder.Append(chunk.Content);
            }
        }

        stopwatch.Stop();

        // Aggregate from recorded task results rather than scraped chunk text. A crew that
        // dispatched nothing proved nothing, so it reports Unknown rather than Healthy.
        var overallStatus = accumulator.TaskResults.Count > 0
            ? DiagnosticHealthStatus.Healthy
            : DiagnosticHealthStatus.Unknown;

        foreach (var task in accumulator.TaskResults)
        {
            if (task.ExtractedFindings != null)
            {
                overallStatus = EscalateStatus(overallStatus, task.ExtractedFindings.OverallStatus);
            }

            if (!task.Success)
            {
                overallStatus = EscalateStatus(overallStatus, DiagnosticHealthStatus.Warning);
            }
        }

        if (accumulator.CycleHalted)
        {
            overallStatus = EscalateStatus(overallStatus, DiagnosticHealthStatus.Warning);
        }

        int succeededTasks = accumulator.TaskResults.Count(t => t.Success);
        return new CrewExecutionResult(
            missionId != Guid.Empty ? missionId : Guid.NewGuid(),
            crew.CrewId,
            overallStatus,
            summaryBuilder.Length > 0
                ? summaryBuilder.ToString()
                : $"Crew '{crew.Name}': {succeededTasks}/{accumulator.TaskResults.Count} dispatched task(s) succeeded.",
            accumulator.TaskResults,
            null,
            stopwatch.ElapsedMilliseconds,
            accumulator.CycleHalted,
            DateTime.UtcNow);
    }

    /// <summary>
    /// Single funnel for turning raw task evidence into a recorded <see cref="CrewTaskResult"/>:
    /// DLP sanitization, findings extraction and accumulator append happen here so neither process
    /// mode can produce a task whose result is missing from the final <see cref="CrewExecutionResult"/>.
    /// </summary>
    private CrewTaskResult RecordTaskResult(
        CrewRunAccumulator accumulator,
        GovernedCrewTask task,
        GovernedCrewAgent agent,
        string rawOutput,
        bool success,
        long durationMs,
        SingleToolTemplate? template)
    {
        var sanitizedOutput = _dlpSanitizer != null ? _dlpSanitizer.Sanitize(rawOutput).SanitizedContent : rawOutput;
        var findings = _findingsExtractor.ExtractFindings(sanitizedOutput, null, template?.Name);

        var result = new CrewTaskResult(
            task.TaskId,
            agent.AgentId,
            rawOutput,
            sanitizedOutput,
            findings,
            success,
            durationMs,
            DateTime.UtcNow);

        accumulator.TaskResults.Add(result);
        return result;
    }

    /// <summary>
    /// Asks the manager model to pick the next task from the closed pending set. Reuses
    /// <see cref="ReActDecisionContract.Parse"/> so the whitelist gate and malformed-answer-means-stop
    /// semantics are identical to the investigation loop's: the manager selects from offered work,
    /// it never authors new work.
    /// </summary>
    private async Task<NextStepDecision> ManagerDecideAsync(
        GovernedCrewDefinition crew,
        GovernedCrewAgent manager,
        IReadOnlyList<GovernedCrewTask> pendingTasks,
        CrewTaskResult? lastResult,
        CancellationToken cancellationToken)
    {
        var prompt = new StringBuilder();
        prompt.AppendLine(manager.BuildSystemPrompt());
        prompt.AppendLine();
        prompt.AppendLine($"You are the MANAGER of governed crew '{crew.Name}': {crew.Description}");
        prompt.AppendLine("Decide which ONE pending task to dispatch next, or whether the crew's goal is already met.");
        prompt.AppendLine();
        prompt.AppendLine("[PENDING TASKS — you may select ONE by exact taskId, or none]:");
        foreach (var task in pendingTasks)
        {
            prompt.AppendLine($"- {task.TaskId}: {task.Description} (assigned agent: {task.AssignedAgentId})");
        }

        prompt.AppendLine();
        prompt.AppendLine("Reply with a brief sentence of reasoning, then close with exactly one fenced JSON block:");
        prompt.AppendLine();
        prompt.AppendLine("```json");
        prompt.AppendLine("{");
        prompt.AppendLine("  \"action\": \"continue | stop\",");
        prompt.AppendLine("  \"taskId\": \"exact id from the list above, or null when stopping\",");
        prompt.AppendLine("  \"reason\": \"one sentence an operator will read explaining this choice\"");
        prompt.AppendLine("}");
        prompt.AppendLine("```");

        var observation = new StringBuilder();
        if (lastResult == null)
        {
            observation.AppendLine("[STATE]: No tasks have been dispatched yet.");
        }
        else
        {
            observation.AppendLine(
                $"[LAST DISPATCH]: Task '{lastResult.TaskId}' by agent '{lastResult.AgentId}' — Success: {lastResult.Success}, Status: {lastResult.ExtractedFindings?.OverallStatus}");
            var outputTail = lastResult.SanitizedOutput;
            if (outputTail.Length > 2000)
            {
                outputTail = outputTail[^2000..];
            }

            observation.AppendLine(outputTail);
        }

        var allowedTaskIds = pendingTasks.Select(t => t.TaskId).ToList();

        // 45s ceiling mirrors the investigation loop: a stalled decision call must not hold the
        // crew open, and losing the chance to dispatch further work is the safe thing to lose.
        using var decisionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        decisionCts.CancelAfter(TimeSpan.FromSeconds(45));

        try
        {
            var response = new StringBuilder();
            await foreach (var token in _modelClient!.StreamAnalysisAsync(
                manager.TargetModel, prompt.ToString(), observation.ToString(), decisionCts.Token))
            {
                response.Append(token);
            }

            return ReActDecisionContract.Parse(response.ToString(), allowedTaskIds);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new NextStepDecision(false, null, "Manager decision timed out after 45 seconds; crew dispatch stopped.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new NextStepDecision(false, null, $"Manager decision failed ({ex.Message}); crew dispatch stopped.");
        }
    }

    /// <summary>
    /// Severity escalation that does not trust enum declaration order: the enum declares
    /// Healthy/Warning/Critical/Unknown, so a raw comparison ranks Unknown above Critical.
    /// Critical is terminal; Warning and Unknown both escalate the aggregate to Warning.
    /// </summary>
    private static DiagnosticHealthStatus EscalateStatus(DiagnosticHealthStatus current, DiagnosticHealthStatus observed)
    {
        if (current == DiagnosticHealthStatus.Critical || observed == DiagnosticHealthStatus.Critical)
        {
            return DiagnosticHealthStatus.Critical;
        }

        if (observed == DiagnosticHealthStatus.Warning || observed == DiagnosticHealthStatus.Unknown)
        {
            return DiagnosticHealthStatus.Warning;
        }

        return current;
    }

    /// <summary>
    /// Carries per-task results and halt flags out of the streaming iterators, so
    /// <see cref="RunCrewAsync"/> aggregates from recorded facts instead of scraping chunk text.
    /// </summary>
    private sealed class CrewRunAccumulator
    {
        public List<CrewTaskResult> TaskResults { get; } = new();
        public bool CycleHalted { get; set; }
    }
}
