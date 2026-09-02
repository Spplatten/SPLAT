using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core.Brain;

/// <summary>
/// Layer 2 Cognitive Planning & Autonomous Reasoning Engine ("The Brain").
/// Drives goal decomposition, multi-hypothesis testing, grounded telemetry verification,
/// cross-subsystem root-cause synthesis, and autonomous self-healing formulation.
/// </summary>
public sealed class AgentBrainEngine : IAgentBrain
{
    private readonly IMissionExecutionEngine _missionEngine;
    private readonly ITemplateRegistry _templateRegistry;
    private readonly ICognitiveGoalDecomposer _decomposer;
    private readonly IAuditLedger _auditLedger;
    private readonly ISemanticMemoryIndex? _semanticMemoryIndex;
    private readonly IDiagnosticFindingsExtractor _findingsExtractor;

    public AgentBrainEngine(
        IMissionExecutionEngine missionEngine,
        ITemplateRegistry templateRegistry,
        IAuditLedger auditLedger,
        ICognitiveGoalDecomposer? decomposer = null,
        ISemanticMemoryIndex? semanticMemoryIndex = null,
        IDiagnosticFindingsExtractor? findingsExtractor = null,
        IModelStreamClient? modelClient = null)
    {
        _missionEngine = missionEngine ?? throw new ArgumentNullException(nameof(missionEngine));
        _templateRegistry = templateRegistry ?? throw new ArgumentNullException(nameof(templateRegistry));
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _semanticMemoryIndex = semanticMemoryIndex;
        _findingsExtractor = findingsExtractor ?? new JsonFindingsExtractor();
        _decomposer = decomposer ?? (modelClient != null ? new CognitiveGoalDecomposer(modelClient, semanticMemoryIndex) : throw new ArgumentNullException(nameof(decomposer)));
    }

    public async Task<GoalDecompositionResult> DecomposeGoalAsync(
        string userGoal,
        CancellationToken cancellationToken = default)
    {
        var templates = await _templateRegistry.GetAllTemplatesAsync(cancellationToken);
        return await _decomposer.DecomposeGoalAsync(userGoal, templates, cancellationToken);
    }

    public async Task<BrainExecutionResult> ProcessGoalAsync(
        string userGoal,
        string operatorIdentity,
        int maxReasoningSteps = 3,
        IProgress<MissionChunk>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var sessionId = Guid.NewGuid();
        var memory = new BrainWorkingMemory(sessionId, userGoal);

        progress?.Report(new MissionChunk(
            sessionId,
            MissionChunkType.StatusChange,
            $"🧠 [Agent Brain Initialized] Decomposing objective: \"{userGoal}\"...",
            DateTime.UtcNow));

        await _auditLedger.AppendLogAsync(
            sessionId,
            "agent-brain-core",
            "BRAIN_SESSION_INITIATED",
            $"Goal: '{userGoal}' | MaxSteps: {maxReasoningSteps} | Operator: {operatorIdentity}",
            operatorIdentity,
            cancellationToken);

        // 1. Recall past incidents from semantic memory
        if (_semanticMemoryIndex != null)
        {
            try
            {
                var recalled = await _semanticMemoryIndex.SearchSimilarMissionsAsync(
                    userGoal,
                    topK: 2,
                    minScore: 0.25,
                    cancellationToken: cancellationToken);

                if (recalled.Count > 0)
                {
                    memory.RecalledPastIncidents.AddRange(recalled);
                    progress?.Report(new MissionChunk(
                        sessionId,
                        MissionChunkType.StatusChange,
                        $"🧠 [Incident Recall] Found {recalled.Count} correlated past incidents (Similarity {recalled[0].SimilarityScore:F2}).",
                        DateTime.UtcNow));
                }
            }
            catch
            {
                // Memory lookup is non-blocking enhancement
            }
        }

        // 2. Goal Decomposition
        var allTemplates = await _templateRegistry.GetAllTemplatesAsync(cancellationToken);
        if (allTemplates == null || allTemplates.Count == 0)
        {
            string noTemplatesHeadline = "⚪ UNRESOLVED — No governed templates available in catalog";
            string noTemplatesRootCause = $"The agent brain initialized for goal '{userGoal}', but the governed template registry contains no actionable templates.";

            await _auditLedger.AppendLogAsync(
                sessionId,
                "agent-brain-core",
                "BRAIN_SESSION_EMPTY_CATALOG",
                $"Goal: '{userGoal}' | Status: Unknown",
                operatorIdentity,
                cancellationToken);

            progress?.Report(new MissionChunk(
                sessionId,
                MissionChunkType.Completed,
                $"⚡ [Brain Reasoning Complete] {noTemplatesHeadline}",
                DateTime.UtcNow));

            return new BrainExecutionResult(
                SessionId: sessionId,
                UserGoal: userGoal,
                OverallStatus: DiagnosticHealthStatus.Unknown,
                ExecutiveHeadline: noTemplatesHeadline,
                RootCauseAnalysis: noTemplatesRootCause,
                GroundedKeyFindings: Array.Empty<string>(),
                EvaluatedHypotheses: Array.Empty<BrainHypothesis>(),
                ExecutedSteps: Array.Empty<InvestigationStep>(),
                AvailableRemediations: Array.Empty<RemediationAction>(),
                AuditLedgerEntryHash: null,
                TimestampUtc: DateTime.UtcNow);
        }

        var decomposition = await _decomposer.DecomposeGoalAsync(userGoal, allTemplates, cancellationToken);
        if (decomposition.RecommendedTemplateIds.Count == 0)
        {
            string noMatchHeadline = "⚪ UNRESOLVED — No correlated diagnostic templates identified";
            string noMatchRootCause = $"Goal decomposition for '{userGoal}' did not identify any actionable templates in the governed catalog.";

            await _auditLedger.AppendLogAsync(
                sessionId,
                "agent-brain-core",
                "BRAIN_SESSION_NO_TEMPLATES_MATCHED",
                $"Goal: '{userGoal}' | Status: Unknown",
                operatorIdentity,
                cancellationToken);

            progress?.Report(new MissionChunk(
                sessionId,
                MissionChunkType.Completed,
                $"⚡ [Brain Reasoning Complete] {noMatchHeadline}",
                DateTime.UtcNow));

            return new BrainExecutionResult(
                SessionId: sessionId,
                UserGoal: userGoal,
                OverallStatus: DiagnosticHealthStatus.Unknown,
                ExecutiveHeadline: noMatchHeadline,
                RootCauseAnalysis: noMatchRootCause,
                GroundedKeyFindings: Array.Empty<string>(),
                EvaluatedHypotheses: Array.Empty<BrainHypothesis>(),
                ExecutedSteps: Array.Empty<InvestigationStep>(),
                AvailableRemediations: Array.Empty<RemediationAction>(),
                AuditLedgerEntryHash: null,
                TimestampUtc: DateTime.UtcNow);
        }

        progress?.Report(new MissionChunk(
            sessionId,
            MissionChunkType.StatusChange,
            $"🎯 [Cognitive Plan Formulated] Strategy: {decomposition.ReasoningRationale}",
            DateTime.UtcNow));

        int maxStepsBudget = Math.Clamp(maxReasoningSteps, 1, 5);
        var executedTemplateIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        string currentTemplateId = decomposition.RecommendedTemplateIds[0];
        string currentHypothesisText = $"Testing whether system condition is caused by {allTemplates.FirstOrDefault(t => string.Equals(t.TemplateId, currentTemplateId, StringComparison.OrdinalIgnoreCase))?.Name ?? currentTemplateId}";
        double currentConfidence = decomposition.ConfidenceScore;

        for (int stepNumber = 1; stepNumber <= maxStepsBudget; stepNumber++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            executedTemplateIds.Add(currentTemplateId);
            var template = allTemplates.FirstOrDefault(t => string.Equals(t.TemplateId, currentTemplateId, StringComparison.OrdinalIgnoreCase));
            if (template == null) break;

            // Formulate hypothesis
            var hypothesis = new BrainHypothesis(
                HypothesisId: $"HYP-{stepNumber}",
                Statement: currentHypothesisText,
                CandidateTemplateId: template.TemplateId,
                Status: HypothesisStatus.Pending,
                GroundedEvidence: null,
                ConfidenceScore: currentConfidence);
            memory.Hypotheses.Add(hypothesis);

            progress?.Report(new MissionChunk(
                sessionId,
                MissionChunkType.StatusChange,
                $"🔍 [Hypothesis {stepNumber}/{maxStepsBudget}] {currentHypothesisText}...",
                DateTime.UtcNow));

            // Execute sandboxed 1:1:1 mission
            var toolOutputSb = new StringBuilder();
            var aiOutputSb = new StringBuilder();

            var parameters = new Dictionary<string, string>
            {
                ["UserInstruction"] = userGoal
            };

            await foreach (var chunk in _missionEngine.ExecuteMissionAsync(template, parameters, operatorIdentity, cancellationToken))
            {
                progress?.Report(chunk);

                if (chunk.ChunkType == MissionChunkType.Stdout)
                    toolOutputSb.Append(chunk.Content);
                else if (chunk.ChunkType == MissionChunkType.AiToken)
                    aiOutputSb.Append(chunk.Content);
            }

            // Extract & Ground findings
            var rawDiagnosis = _findingsExtractor.ExtractFindings(aiOutputSb.ToString(), toolOutputSb.ToString(), template.Name);
            var groundedVerdict = TelemetryGrounder.Attest(rawDiagnosis, toolOutputSb.ToString());

            // Update hypothesis status
            // TODO: V1 uses a heuristic confirmation where any Warning or Critical status on the diagnostic
            // template is considered to confirm the formulated hypothesis. In V2, enhance hypothesis evaluation
            // by semantically verifying that the specific grounded key findings correlate directly with the
            // hypothesis statement rather than rubber-stamping based solely on the aggregate template health status.
            var finalHypothesisStatus = groundedVerdict.OverallStatus is DiagnosticHealthStatus.Critical or DiagnosticHealthStatus.Warning
                ? HypothesisStatus.Confirmed
                : HypothesisStatus.Refuted;

            var updatedHypothesis = hypothesis with
            {
                Status = finalHypothesisStatus,
                GroundedEvidence = groundedVerdict.StatusHeadline
            };
            memory.Hypotheses[memory.Hypotheses.Count - 1] = updatedHypothesis;

            // Update facts
            foreach (var finding in groundedVerdict.KeyFindings)
            {
                if (!memory.GroundedFacts.Contains(finding))
                {
                    memory.GroundedFacts.Add(finding);
                }
            }

            // Collect remediations
            foreach (var fix in template.Remediations)
            {
                if (!memory.AvailableRemediations.Any(r => r.ActionId == fix.ActionId))
                {
                    memory.AvailableRemediations.Add(fix);
                }
            }

            memory.CompletedSteps.Add(new InvestigationStep(
                StepNumber: stepNumber,
                TemplateId: template.TemplateId,
                TemplateName: template.Name,
                SelectionReason: currentHypothesisText,
                Verdict: groundedVerdict));

            // Elevate overall status if worse
            if (groundedVerdict.OverallStatus == DiagnosticHealthStatus.Critical)
            {
                memory.OverallStatus = DiagnosticHealthStatus.Critical;
            }
            else if (groundedVerdict.OverallStatus == DiagnosticHealthStatus.Warning && memory.OverallStatus != DiagnosticHealthStatus.Critical)
            {
                memory.OverallStatus = DiagnosticHealthStatus.Warning;
            }

            // Early termination check: if budget reached, finish
            if (stepNumber >= maxStepsBudget)
            {
                break;
            }

            // Early termination on initial clean bill of health if only 1 step was planned and found nominal
            if (groundedVerdict.OverallStatus == DiagnosticHealthStatus.Healthy && stepNumber == 1 && decomposition.RecommendedTemplateIds.Count <= 1)
            {
                break;
            }

            // Adaptive Re-Planning: dynamically decide next diagnostic step based on accumulated grounded telemetry
            var remainingTemplates = allTemplates.Where(t => !executedTemplateIds.Contains(t.TemplateId)).ToList();
            if (remainingTemplates.Count == 0)
            {
                break;
            }

            var nextPlan = await _decomposer.DecomposeNextStepAsync(userGoal, remainingTemplates, memory, cancellationToken);
            if (!nextPlan.ShouldContinue || string.IsNullOrWhiteSpace(nextPlan.NextTemplateId))
            {
                progress?.Report(new MissionChunk(
                    sessionId,
                    MissionChunkType.StatusChange,
                    $"🧠 [Re-Plan Complete] Adaptive reasoning concluded: {nextPlan.Rationale}",
                    DateTime.UtcNow));
                break;
            }

            currentTemplateId = nextPlan.NextTemplateId;
            var nextTemplate = allTemplates.FirstOrDefault(t => string.Equals(t.TemplateId, currentTemplateId, StringComparison.OrdinalIgnoreCase));
            if (nextTemplate == null) break;

            currentHypothesisText = nextPlan.NextHypothesisStatement ?? $"Testing whether system condition is caused by {nextTemplate.Name} ({nextTemplate.Category})";
            currentConfidence = nextPlan.ConfidenceScore;

            progress?.Report(new MissionChunk(
                sessionId,
                MissionChunkType.StatusChange,
                $"🧠 [Dynamic Re-Plan Step {stepNumber + 1}] Telemetry feedback routed to {nextTemplate.Name}: {nextPlan.Rationale}",
                DateTime.UtcNow));
        }

        // 3. Synthesize Root Cause
        string synthesizedHeadline;
        string rootCauseAnalysis;

        if (memory.OverallStatus == DiagnosticHealthStatus.Healthy)
        {
            synthesizedHeadline = "🟢 ALL CLEAR — System Healthy Across Investigated Subsystems";
            rootCauseAnalysis = $"Autonomous cognitive assessment verified {memory.CompletedSteps.Count} subsystem(s) based on user directive '{userGoal}'. No anomalies or security violations were detected.";
        }
        else
        {
            var confirmedHyps = memory.Hypotheses.Where(h => h.Status == HypothesisStatus.Confirmed).ToList();
            synthesizedHeadline = memory.OverallStatus == DiagnosticHealthStatus.Critical
                ? $"🔴 CRITICAL ALERT — Multi-Factor Degradation Identified"
                : $"🟡 WARNING — Action Required on Identified Bottlenecks";

            var rcBuilder = new StringBuilder();
            rcBuilder.AppendLine($"Autonomous Root Cause Synthesis for \"{userGoal}\":");
            foreach (var h in confirmedHyps)
            {
                rcBuilder.AppendLine($"- {h.Statement} → Confirmed: {h.GroundedEvidence}");
            }
            if (memory.AvailableRemediations.Count > 0)
            {
                rcBuilder.AppendLine($"\nRecommended Self-Healing Remediation(s): {string.Join(", ", memory.AvailableRemediations.Select(r => r.Title))}");
            }
            rootCauseAnalysis = rcBuilder.ToString();
        }

        memory.SynthesizedRootCause = rootCauseAnalysis;

        // 4. Cryptographically Commit to Ledger
        await _auditLedger.AppendLogAsync(
            sessionId,
            "agent-brain-core",
            "BRAIN_REASONING_COMPLETED",
            $"Status: {memory.OverallStatus} | StepsExecuted: {memory.CompletedSteps.Count} | RootCause: {synthesizedHeadline}",
            operatorIdentity,
            cancellationToken);

        var logs = await _auditLedger.GetAuditLogsAsync(sessionId, 1, cancellationToken);
        string? merkleHash = logs.Count > 0 ? logs[^1].EntryHash : null;

        // 5. Memory Write-Back: Index completed reasoning session into Semantic Memory for continuous learning
        if (_semanticMemoryIndex != null)
        {
            try
            {
                string memoryDoc = BuildBrainMemoryDocument(sessionId, userGoal, memory, synthesizedHeadline, rootCauseAnalysis);
                await _semanticMemoryIndex.IndexMissionDocumentAsync(
                    sessionId,
                    "agent-brain-session",
                    memoryDoc,
                    cancellationToken);
            }
            catch
            {
                // Semantic memory indexing is non-blocking enhancement
            }
        }

        progress?.Report(new MissionChunk(
            sessionId,
            MissionChunkType.Completed,
            $"⚡ [Brain Reasoning Complete] {synthesizedHeadline}",
            DateTime.UtcNow));

        return new BrainExecutionResult(
            SessionId: sessionId,
            UserGoal: userGoal,
            OverallStatus: memory.OverallStatus,
            ExecutiveHeadline: synthesizedHeadline,
            RootCauseAnalysis: rootCauseAnalysis,
            GroundedKeyFindings: memory.GroundedFacts,
            EvaluatedHypotheses: memory.Hypotheses,
            ExecutedSteps: memory.CompletedSteps,
            AvailableRemediations: memory.AvailableRemediations,
            AuditLedgerEntryHash: merkleHash,
            TimestampUtc: DateTime.UtcNow);
    }

    private static string BuildBrainMemoryDocument(
        Guid sessionId,
        string userGoal,
        BrainWorkingMemory memory,
        string headline,
        string rootCause)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"[BRAIN SESSION]: {sessionId}");
        sb.AppendLine($"[GOAL]: {userGoal}");
        sb.AppendLine($"[OVERALL STATUS]: {memory.OverallStatus}");
        sb.AppendLine($"[HEADLINE]: {headline}");
        if (memory.GroundedFacts.Count > 0)
        {
            sb.AppendLine("[GROUNDED FINDINGS]:");
            foreach (var fact in memory.GroundedFacts)
            {
                sb.AppendLine($"- {fact}");
            }
        }
        if (memory.CompletedSteps.Count > 0)
        {
            sb.AppendLine("[INVESTIGATION STEPS]:");
            foreach (var step in memory.CompletedSteps)
            {
                sb.AppendLine($"- Step {step.StepNumber}: {step.TemplateName} ({step.TemplateId}) -> {step.Verdict.OverallStatus}: {step.Verdict.StatusHeadline}");
            }
        }
        sb.AppendLine($"[ROOT CAUSE SYNTHESIS]:\n{rootCause}");
        if (memory.AvailableRemediations.Count > 0)
        {
            sb.AppendLine("[RECOMMENDED REMEDIATIONS]:");
            foreach (var rem in memory.AvailableRemediations)
            {
                sb.AppendLine($"- {rem.Title} ({rem.ActionId})");
            }
        }
        return sb.ToString();
    }
}
