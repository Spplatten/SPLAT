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
///
/// The model may also propose VALUES for the parameters the selected template declares, so a chain
/// can follow a lead instead of running every step on its defaults. It proposes; it does not decide.
/// <see cref="GovernedArgumentBinder.ScreenProposedValues"/> drops anything undeclared, anything the
/// operator already set, and anything that would not survive the binder - and every drop is written
/// to the ledger, because a command line a model influenced must be readable after the fact.
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

        // Step 1 runs on exactly what the operator supplied. Later steps run on the operator's values
        // PLUS whatever the model proposed and the binder accepted for that specific template; the
        // operator's dictionary is never mutated, so their values remain the floor for every step.
        IReadOnlyDictionary<string, string> stepParameters = parameters;

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
                await RunStepAsync(current, stepParameters, operatorIdentity, progress, cancellationToken);

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
                current, stepParameters, verdict, investigationGoal, candidates, visitedTemplateIds, cancellationToken);

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

            // Screening happens HERE, against the template the registry actually returned, and not
            // in the parser: only now is it known which keys this template declares and where their
            // placeholders sit. A proposal that fails is dropped, never repaired - the step then runs
            // on its default, which is what it would have done before the model could propose at all.
            var screening = GovernedArgumentBinder.ScreenProposedValues(next, decision.Proposals, parameters);
            stepParameters = Merge(parameters, screening.Accepted);

            await _auditLedger.AppendLogAsync(
                investigationId,
                next.TemplateId,
                "INVESTIGATION_STEP_SELECTED",
                $"Step {stepNumber + 1}: {next.Name} | Reason: {decision.Reason}" +
                $" | ModelParameters: {DescribeAccepted(screening.Accepted)}",
                operatorIdentity,
                cancellationToken);

            // Refusals get their own row rather than a clause on the one above. A model that keeps
            // reaching for a parameter it may not set is reporting something about itself, and that
            // has to be findable in the ledger without reading every selection row.
            if (screening.Rejections.Count > 0)
            {
                await _auditLedger.AppendLogAsync(
                    investigationId,
                    next.TemplateId,
                    "INVESTIGATION_PARAMETER_REFUSED",
                    $"Step {stepNumber + 1}: {next.Name} | " + string.Join(" | ", screening.Rejections),
                    operatorIdentity,
                    cancellationToken);
            }

            string targeting = screening.Accepted.Count > 0
                ? $" (targeting {DescribeAccepted(screening.Accepted)})"
                : string.Empty;

            progress?.Report(new MissionChunk(
                investigationId,
                MissionChunkType.StatusChange,
                $"🔗 Investigation step {stepNumber + 1}: {next.Name}{targeting} — {decision.Reason}",
                DateTime.UtcNow));

            current = next;
            selectionReason = screening.Accepted.Count > 0
                ? $"{decision.Reason} [model-targeted: {DescribeAccepted(screening.Accepted)}]"
                : decision.Reason;
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

    private async Task<List<InvestigationCandidate>> BuildCandidateListAsync(
        IReadOnlyList<string> visitedTemplateIds,
        CancellationToken cancellationToken)
    {
        var all = await _templateRegistry.GetAllTemplatesAsync(cancellationToken);
        var candidates = new List<InvestigationCandidate>();

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
                candidates.Add(new InvestigationCandidate(
                    template.TemplateId,
                    template.Name,
                    template.Description,
                    template.ParameterFields ?? Array.Empty<TemplateParameterField>(),
                    template.GetEffectiveDefaults()));
            }
        }

        return candidates;
    }

    private async Task<NextStepDecision> DecideNextStepAsync(
        SingleToolTemplate completedTemplate,
        IReadOnlyDictionary<string, string> completedParameters,
        ExecutiveDiagnosisResult verdict,
        string investigationGoal,
        IReadOnlyList<InvestigationCandidate> candidates,
        IReadOnlyList<string> visitedTemplateIds,
        CancellationToken cancellationToken)
    {
        string systemPrompt = ReActDecisionContract.BuildDecisionPrompt(
            investigationGoal, candidates, visitedTemplateIds);

        var observation = new StringBuilder();
        observation.AppendLine($"[COMPLETED STEP]: {completedTemplate.Name}");

        // What the finished step actually ran against. Without this the model can target step N+1 and
        // then lose that target at step N+2, because each decision otherwise sees only a verdict and
        // has no way to know which host or account the chain is already following.
        string ranAgainst = DescribeStepParameters(completedTemplate, completedParameters);
        if (ranAgainst.Length > 0)
        {
            observation.AppendLine($"[RAN AGAINST]: {ranAgainst}");
        }

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

    /// <summary>
    /// The operator's parameters with the accepted model proposals laid over them.
    ///
    /// Returns the caller's own dictionary when nothing was accepted, so the common case allocates
    /// nothing and the object identity of an unmodified parameter set is preserved. The operator's
    /// dictionary is never mutated: each step composes its own, so one step's targeting cannot leak
    /// into the next - which is the bug this method exists to make impossible rather than unlikely.
    /// </summary>
    /// <summary>
    /// The values a finished step was actually bound with, restricted to that template's own declared
    /// fields. Restricting it matters: the operator's dictionary also carries UserInstruction and
    /// whatever keys the STARTING template needed, and echoing those into a later decision prompt
    /// would invite the model to propose them for a template that never declared them.
    /// </summary>
    private static string DescribeStepParameters(
        SingleToolTemplate template,
        IReadOnlyDictionary<string, string> parameters)
    {
        var fields = template.ParameterFields;
        if (fields is null || fields.Count == 0)
        {
            return string.Empty;
        }

        var defaults = template.GetEffectiveDefaults();
        var parts = new List<string>();

        foreach (var field in fields)
        {
            if (string.IsNullOrWhiteSpace(field.Key) || field.ValueType == TemplateParameterType.Multiline)
            {
                continue;
            }

            string? value =
                parameters.TryGetValue(field.Key, out var supplied) && !string.IsNullOrWhiteSpace(supplied)
                    ? supplied
                    : defaults.TryGetValue(field.Key, out var fallback) ? fallback : null;

            if (!string.IsNullOrWhiteSpace(value))
            {
                parts.Add($"{field.Key}={value}");
            }
        }

        return string.Join(", ", parts);
    }

    private static IReadOnlyDictionary<string, string> Merge(
        IReadOnlyDictionary<string, string> operatorSupplied,
        IReadOnlyDictionary<string, string> accepted)
    {
        if (accepted.Count == 0)
        {
            return operatorSupplied;
        }

        var merged = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in operatorSupplied)
        {
            merged[pair.Key] = pair.Value;
        }

        // Screening already refused every key the operator supplied, so this cannot overwrite one.
        foreach (var pair in accepted)
        {
            merged[pair.Key] = pair.Value;
        }

        return merged;
    }

    /// <summary>
    /// Renders accepted proposals for the ledger and the operator's status line. Values are printed
    /// in full and never truncated: this row is the record of what the model changed about a command
    /// line, and an elided value makes it useless for exactly the audit it exists to serve. The
    /// binder's own length limits keep it bounded.
    /// </summary>
    private static string DescribeAccepted(IReadOnlyDictionary<string, string> accepted)
    {
        if (accepted.Count == 0)
        {
            return "none";
        }

        var parts = new List<string>(accepted.Count);
        foreach (var pair in accepted)
        {
            parts.Add($"{pair.Key}={pair.Value}");
        }

        return string.Join(", ", parts);
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
