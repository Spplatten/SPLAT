using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Evaluators;

/// <summary>
/// Aggregates semantic quality, telemetry grounding, completeness, and anti-hedging evaluators
/// into the unified Y-Axis score [0.0, 1.0].
/// </summary>
public sealed class CompositeSemanticEvaluator : ISemanticEvaluator
{
    private readonly TelemetryGroundingEvaluator _groundingEvaluator;
    private readonly DiagnosticCompletenessEvaluator _completenessEvaluator;
    private readonly AntiHedgingSemanticEvaluator _hedgingEvaluator;

    public CompositeSemanticEvaluator(
        TelemetryGroundingEvaluator? groundingEvaluator = null,
        DiagnosticCompletenessEvaluator? completenessEvaluator = null,
        AntiHedgingSemanticEvaluator? hedgingEvaluator = null)
    {
        _groundingEvaluator = groundingEvaluator ?? new TelemetryGroundingEvaluator();
        _completenessEvaluator = completenessEvaluator ?? new DiagnosticCompletenessEvaluator();
        _hedgingEvaluator = hedgingEvaluator ?? new AntiHedgingSemanticEvaluator();
    }

    public async Task<SemanticEvaluationResult> EvaluateAsync(
        string candidateContent,
        string? telemetryHaystack,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(candidateContent))
        {
            return new SemanticEvaluationResult(
                SemanticScore: 0.0,
                GroundingScore: 0.0,
                CompletenessScore: 0.0,
                AntiHedgingScore: 0.0,
                QualityNotes: new[] { "Candidate content is empty." },
                UngroundedClaims: Array.Empty<string>());
        }

        var groundingTask = _groundingEvaluator.EvaluateAsync(candidateContent, telemetryHaystack, contractType, options, cancellationToken);
        var completenessTask = _completenessEvaluator.EvaluateAsync(candidateContent, telemetryHaystack, contractType, options, cancellationToken);
        var hedgingTask = _hedgingEvaluator.EvaluateAsync(candidateContent, telemetryHaystack, contractType, options, cancellationToken);

        await Task.WhenAll(groundingTask, completenessTask, hedgingTask);

        var groundingRes = await groundingTask;
        var completenessRes = await completenessTask;
        var hedgingRes = await hedgingTask;

        // Weights: Grounding (50%), Completeness (30%), Anti-Hedging (20%)
        double compositeY = (groundingRes.GroundingScore * 0.50) +
                            (completenessRes.CompletenessScore * 0.30) +
                            (hedgingRes.AntiHedgingScore * 0.20);

        compositeY = Math.Clamp(compositeY, 0.0, 1.0);

        var allNotes = new List<string>();
        allNotes.AddRange(groundingRes.QualityNotes);
        allNotes.AddRange(completenessRes.QualityNotes);
        allNotes.AddRange(hedgingRes.QualityNotes);

        return new SemanticEvaluationResult(
            SemanticScore: compositeY,
            GroundingScore: groundingRes.GroundingScore,
            CompletenessScore: completenessRes.CompletenessScore,
            AntiHedgingScore: hedgingRes.AntiHedgingScore,
            QualityNotes: allNotes,
            UngroundedClaims: groundingRes.UngroundedClaims,
            ParsedVerdict: groundingRes.ParsedVerdict ?? completenessRes.ParsedVerdict);
    }
}
