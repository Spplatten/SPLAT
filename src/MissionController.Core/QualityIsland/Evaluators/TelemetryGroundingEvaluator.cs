using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Evaluators;

/// <summary>
/// Evaluates factual grounding against raw sandboxed tool telemetry using <see cref="TelemetryGrounder"/>.
/// Penalizes ungrounded claims, fabricated IPs, counts, and paths.
/// </summary>
public sealed class TelemetryGroundingEvaluator : ISemanticEvaluator
{
    private readonly IDiagnosticFindingsExtractor _extractor;

    public TelemetryGroundingEvaluator(IDiagnosticFindingsExtractor? extractor = null)
    {
        _extractor = extractor ?? new JsonFindingsExtractor();
    }

    public Task<SemanticEvaluationResult> EvaluateAsync(
        string candidateContent,
        string? telemetryHaystack,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(candidateContent))
        {
            return Task.FromResult(new SemanticEvaluationResult(
                SemanticScore: 0.0,
                GroundingScore: 0.0,
                CompletenessScore: 0.0,
                AntiHedgingScore: 0.0,
                QualityNotes: new[] { "Empty candidate content." },
                UngroundedClaims: Array.Empty<string>()));
        }

        // Planning can omit telemetry; a diagnosis cannot earn perfect grounding by losing
        // its sensor. Otherwise truncating all evidence makes an old healthy answer pass.
        if (contractType is SchemaContractType.GoalDecomposition or SchemaContractType.DynamicCodeScript ||
            (string.IsNullOrWhiteSpace(telemetryHaystack) && contractType != SchemaContractType.StructuredDiagnosis))
        {
            return Task.FromResult(SemanticEvaluationResult.Pass(1.0, groundingScore: 1.0));
        }

        var verdict = _extractor.ExtractFindings(candidateContent, telemetryHaystack);
        if (string.IsNullOrWhiteSpace(telemetryHaystack))
        {
            return Task.FromResult(new SemanticEvaluationResult(
                SemanticScore: 0.0, GroundingScore: 0.0, CompletenessScore: 1.0, AntiHedgingScore: 1.0,
                QualityNotes: new[] { "No sensor telemetry was captured; this diagnosis cannot be verified." },
                UngroundedClaims: verdict.KeyFindings, ParsedVerdict: verdict));
        }
        var attestation = verdict.Attestation;

        if (attestation == null || attestation.Findings.Count == 0)
        {
            // No checkable claims extracted
            return Task.FromResult(SemanticEvaluationResult.Pass(0.8, groundingScore: 0.8, parsedVerdict: verdict));
        }

        int total = attestation.Findings.Count;
        int grounded = attestation.GroundedCount;
        int partial = attestation.PartiallyGroundedCount;
        int unattributed = attestation.UnattributedCount;
        int unsupported = attestation.UnsupportedCount;

        // Grounding score calculation: grounded (1.0) + unattributed prose (0.95) + partial (0.60) - unsupported penalty
        double groundingScore = 1.0;
        if (total > 0)
        {
            groundingScore = ((grounded * 1.0) + (unattributed * 0.95) + (partial * 0.60)) / total;
            if (unsupported > 0)
            {
                groundingScore -= (0.40 * unsupported / total);
            }
        }
        groundingScore = Math.Clamp(groundingScore, 0.0, 1.0);

        var ungrounded = new List<string>();
        var notes = new List<string>();

        foreach (var findingAtt in attestation.Findings)
        {
            if (findingAtt.State == GroundingState.Unsupported)
            {
                ungrounded.Add(findingAtt.Finding);
                notes.Add($"Unsupported claim in finding: \"{findingAtt.Finding}\" (Missing: {string.Join(", ", findingAtt.MissingClaims)})");
            }
        }

        // Heavy penalty if critical verdict has unsupported claims with zero grounded claims
        if (verdict.OverallStatus is DiagnosticHealthStatus.Critical or DiagnosticHealthStatus.Warning &&
            grounded == 0 && partial == 0 && unsupported > 0)
        {
            groundingScore = Math.Min(groundingScore, 0.2);
            notes.Add("CRITICAL/WARNING verdict is completely unanchored in collected telemetry (possible hallucination).");
        }

        return Task.FromResult(new SemanticEvaluationResult(
            SemanticScore: groundingScore,
            GroundingScore: groundingScore,
            CompletenessScore: 1.0,
            AntiHedgingScore: 1.0,
            QualityNotes: notes,
            UngroundedClaims: ungrounded,
            ParsedVerdict: verdict));
    }
}
