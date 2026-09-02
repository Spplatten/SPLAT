using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core;

/// <summary>
/// Governed Reason-Act-Observe harness.
///
/// The engine executes strictly one tool per mission, and that rule is not relaxed here: a
/// multi-step investigation is a CHAIN of complete 1:1:1 missions, each with its own jail, job
/// object, egress pin, DLP pass and audit trail. This class owns only the question the engine cannot
/// answer on its own - "given what step N found, is there a governed step N+1 worth running?"
///
/// Three limits are enforced by this loop rather than by the model, because a model asked to police
/// its own budget will eventually decide it needs one more look:
///  - a hard step ceiling (<see cref="AbsoluteMaxSteps"/>) that caps whatever the caller requests;
///  - no repeats, so a chain cannot oscillate between two templates until the budget drains;
///  - selection restricted to the governed catalog, enforced inside <see cref="ReActDecisionContract.Parse"/>.
/// A healthy verdict also ends the chain: the cheapest investigation is the one that stops early.
/// </summary>
public sealed class GovernedInvestigationLoop : IGovernedInvestigationLoop
{
    /// <summary>
    /// Ceiling on chained sandboxed executions, regardless of what a caller passes. Each step spawns
    /// a real confined process against a live endpoint, so the blast radius of a runaway chain is
    /// measured in spawned processes - it is bounded here rather than trusted to configuration.
    /// </summary>
    public const int AbsoluteMaxSteps = 5;

    private readonly IMissionExecutionEngine _engine;
    private readonly ITemplateRegistry _templateRegistry;
    private readonly IModelStreamClient _modelClient;
    private readonly IDiagnosticFindingsExtractor _findingsExtractor;
    private readonly IAuditLedger _auditLedger;

    public GovernedInvestigationLoop(
        IMissionExecutionEngine engine,
        ITemplateRegistry templateRegistry,
        IModelStreamClient modelClient,
        IAuditLedger auditLedger,
        IDiagnosticFindingsExtractor? findingsExtractor = null)
    {
        _engine = engine;
        _templateRegistry = templateRegistry;
        _modelClient = modelClient;
        _auditLedger = auditLedger;
        _findingsExtractor = findingsExtractor ?? new JsonFindingsExtractor();
    }

    public async Task<InvestigationResult> InvestigateAsync(
        SingleToolTemplate startingTemplate,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        int maxSteps = 3,
        IProgress<MissionChunk>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var investigationId = Guid.NewGuid();
        int budget = Math.Clamp(maxSteps, 1, AbsoluteMaxSteps);

        var steps = new List<InvestigationStep>();
        var visitedTemplateIds = new List<string>();
        var current = startingTemplate;
        string selectionReason = "Operator-selected starting diagnostic.";

        string investigationGoal =
            parameters.TryGetValue("UserInstruction", out var instruction) && !string.IsNullOrWhiteSpace(instruction)
                ? instruction
                : $"Investigate the condition reported by {startingTemplate.Name}.";

        await _auditLedger.AppendLogAsync(
            investigationId,
            startingTemplate.TemplateId,
            "INVESTIGATION_STARTED",
            $"Goal: {investigationGoal} | StepBudget: {budget} | Operator: {operatorIdentity}",
            operatorIdentity,
            cancellationToken);

        var stopReason = InvestigationStopReason.StepBudgetExhausted;
        string stopExplanation = $"Reached the {budget}-step investigation budget.";

        for (int stepNumber = 1; stepNumber <= budget; stepNumber++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            visitedTemplateIds.Add(current.TemplateId);

            var (toolOutput, aiAnalysis, missionFailed) =
                await RunStepAsync(current, parameters, operatorIdentity, progress, cancellationToken);

            var verdict = _findingsExtractor.ExtractFindings(aiAnalysis, toolOutput, current.Name);
            steps.Add(new InvestigationStep(stepNumber, current.TemplateId, current.Name, selectionReason, verdict));

            if (missionFailed)
            {
                stopReason = InvestigationStopReason.StepFailed;
                stopExplanation =
                    $"Step {stepNumber} ({current.Name}) could not complete, so the chain was not extended.";
                break;
            }

            // Stop early on a clean result. Chaining further steps off a healthy verdict burns
            // sandboxed executions to confirm an absence of findings.
            if (verdict.OverallStatus == DiagnosticHealthStatus.Healthy)
            {
                stopReason = InvestigationStopReason.SystemHealthy;
                stopExplanation = $"{current.Name} returned a healthy verdict; no further steps were warranted.";
                break;
            }

            if (stepNumber == budget)
            {
                stopReason = InvestigationStopReason.StepBudgetExhausted;
                stopExplanation = $"Reached the {budget}-step investigation budget.";
                break;
            }

            var candidates = await BuildCandidateListAsync(visitedTemplateIds, cancellationToken);
            if (candidates.Count == 0)
            {
                stopReason = InvestigationStopReason.NoGovernedCandidateRemaining;
                stopExplanation = "Every governed template in the catalog has already been run in this investigation.";
                break;
            }

            var decision = await DecideNextStepAsync(
                current, verdict, investigationGoal, candidates, visitedTemplateIds, cancellationToken);

            if (!decision.ShouldContinue || decision.TemplateId is null)
            {
                stopReason = InvestigationStopReason.ModelDeclinedToContinue;
                stopExplanation = decision.Reason;
                break;
            }

            var next = await _templateRegistry.GetTemplateByIdAsync(decision.TemplateId, cancellationToken);
            if (next is null)
            {
                // Belt and braces: the id passed the catalog whitelist a moment ago, so a miss here
                // means the registry changed mid-investigation. Stop rather than improvise.
                stopReason = InvestigationStopReason.NoGovernedCandidateRemaining;
                stopExplanation =
                    $"Selected template '{decision.TemplateId}' was no longer resolvable in the registry.";
                break;
            }

            await _auditLedger.AppendLogAsync(
                investigationId,
                next.TemplateId,
                "INVESTIGATION_STEP_SELECTED",
                $"Step {stepNumber + 1}: {next.Name} | Reason: {decision.Reason}",
                operatorIdentity,
                cancellationToken);

            progress?.Report(new MissionChunk(
                investigationId,
                MissionChunkType.StatusChange,
                $"🔗 Investigation step {stepNumber + 1}: {next.Name} — {decision.Reason}",
                DateTime.UtcNow));

            current = next;
            selectionReason = decision.Reason;
        }

        var overall = DetermineOverallStatus(steps);

        await _auditLedger.AppendLogAsync(
            investigationId,
            startingTemplate.TemplateId,
            "INVESTIGATION_COMPLETED",
            $"Steps: {steps.Count} | Overall: {overall} | StopReason: {stopReason} | {stopExplanation}",
            operatorIdentity,
            cancellationToken);

        return new InvestigationResult(investigationId, steps, overall, stopReason, stopExplanation);
    }

    /// <summary>
    /// Runs one governed mission end to end, forwarding every chunk to the caller so a chained
    /// investigation still streams live. Returns the raw tool output and AI analysis separately
    /// because the findings extractor needs to distinguish "the sensor said" from "the model said".
    /// </summary>
    private async Task<(string ToolOutput, string AiAnalysis, bool Failed)> RunStepAsync(
        SingleToolTemplate template,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        IProgress<MissionChunk>? progress,
        CancellationToken cancellationToken)
    {
        var toolOutput = new StringBuilder();
        var aiAnalysis = new StringBuilder();
        bool completed = false;

        await foreach (var chunk in _engine.ExecuteMissionAsync(template, parameters, operatorIdentity, cancellationToken))
        {
            progress?.Report(chunk);

            switch (chunk.ChunkType)
            {
                case MissionChunkType.Stdout:
                    toolOutput.Append(chunk.Content);
                    break;
                case MissionChunkType.AiToken:
                    aiAnalysis.Append(chunk.Content);
                    break;
                case MissionChunkType.Completed:
                    completed = true;
                    break;
            }
        }

        return (toolOutput.ToString(), aiAnalysis.ToString(), !completed);
    }

    private async Task<List<(string TemplateId, string Name, string Description)>> BuildCandidateListAsync(
        IReadOnlyList<string> visitedTemplateIds,
        CancellationToken cancellationToken)
    {
        var all = await _templateRegistry.GetAllTemplatesAsync(cancellationToken);
        var candidates = new List<(string, string, string)>();

        foreach (var template in all)
        {
            bool alreadyRun = false;
            foreach (var visited in visitedTemplateIds)
            {
                if (string.Equals(visited, template.TemplateId, StringComparison.OrdinalIgnoreCase))
                {
                    alreadyRun = true;
                    break;
                }
            }

            if (!alreadyRun)
            {
                candidates.Add((template.TemplateId, template.Name, template.Description));
            }
        }

        return candidates;
    }

    private async Task<NextStepDecision> DecideNextStepAsync(
        SingleToolTemplate completedTemplate,
        ExecutiveDiagnosisResult verdict,
        string investigationGoal,
        IReadOnlyList<(string TemplateId, string Name, string Description)> candidates,
        IReadOnlyList<string> visitedTemplateIds,
        CancellationToken cancellationToken)
    {
        string systemPrompt = ReActDecisionContract.BuildDecisionPrompt(
            investigationGoal, candidates, visitedTemplateIds);

        var observation = new StringBuilder();
        observation.AppendLine($"[COMPLETED STEP]: {completedTemplate.Name}");
        observation.AppendLine($"[VERDICT]: {verdict.OverallStatus} — {verdict.StatusHeadline}");
        foreach (var finding in verdict.KeyFindings)
        {
            observation.AppendLine($"- {finding}");
        }

        var allowedIds = new List<string>(candidates.Count);
        foreach (var candidate in candidates)
        {
            allowedIds.Add(candidate.TemplateId);
        }

        using var decisionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        decisionCts.CancelAfter(TimeSpan.FromSeconds(45));

        try
        {
            var response = new StringBuilder();
            await foreach (var token in _modelClient.StreamAnalysisAsync(
                completedTemplate.TargetModel, systemPrompt, observation.ToString(), decisionCts.Token))
            {
                response.Append(token);
            }

            return ReActDecisionContract.Parse(response.ToString(), allowedIds);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new NextStepDecision(false, null,
                "Cognitive decision step timed out after 45 seconds; investigation stopped.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // A failed decision call ends the chain. Steps already taken keep their verdicts; what is
            // lost is only the opportunity to take another, which is the safe thing to lose.
            return new NextStepDecision(false, null,
                $"Could not obtain a follow-up decision from the model ({ex.Message}); investigation stopped.");
        }
    }

    private static DiagnosticHealthStatus DetermineOverallStatus(IReadOnlyList<InvestigationStep> steps)
    {
        var worst = DiagnosticHealthStatus.Healthy;
        bool sawAny = false;

        foreach (var step in steps)
        {
            sawAny = true;
            // Ordering is explicit rather than relying on enum values, which are declared
            // Healthy/Warning/Critical/Unknown - so a raw Max() would rank Unknown worst of all.
            if (step.Verdict.OverallStatus == DiagnosticHealthStatus.Critical)
            {
                return DiagnosticHealthStatus.Critical;
            }

            if (step.Verdict.OverallStatus == DiagnosticHealthStatus.Warning ||
                step.Verdict.OverallStatus == DiagnosticHealthStatus.Unknown)
            {
                worst = DiagnosticHealthStatus.Warning;
            }
        }

        return sawAny ? worst : DiagnosticHealthStatus.Unknown;
    }
}
