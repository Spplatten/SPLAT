using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Evaluators;

/// <summary>
/// Evaluates diagnostic completeness, headline clarity, findings quantity and specificity,
/// and actionable remediation presence.
/// </summary>
public sealed class DiagnosticCompletenessEvaluator : ISemanticEvaluator
{
    private readonly IDiagnosticFindingsExtractor _extractor;

    public DiagnosticCompletenessEvaluator(IDiagnosticFindingsExtractor? extractor = null)
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

        var notes = new List<string>();
        double completeness = 1.0;

        if (contractType == SchemaContractType.StructuredDiagnosis)
        {
            var verdict = _extractor.ExtractFindings(candidateContent, telemetryHaystack);

            // 1. Headline quality
            if (string.IsNullOrWhiteSpace(verdict.StatusHeadline) || verdict.StatusHeadline.Length < 10)
            {
                completeness -= 0.3;
                notes.Add("Status headline is missing or too brief (< 10 chars).");
            }

            // 2. Key findings quality
            if (verdict.KeyFindings.Count == 0)
            {
                completeness -= 0.4;
                notes.Add("No key findings provided in diagnosis.");
            }
            else
            {
                int meaningfulFindings = 0;
                foreach (var f in verdict.KeyFindings)
                {
                    if (f.Length >= 15 && !f.Contains("No findings", StringComparison.OrdinalIgnoreCase))
                    {
                        meaningfulFindings++;
                    }
                }

                if (meaningfulFindings == 0)
                {
                    completeness -= 0.2;
                    notes.Add("Findings lack substantive detail or context.");
                }
            }

            // 3. Recommended actions for Warning / Critical status
            if (verdict.OverallStatus is DiagnosticHealthStatus.Critical or DiagnosticHealthStatus.Warning)
            {
                if (verdict.RecommendedActions == null || verdict.RecommendedActions.Count == 0)
                {
                    completeness -= 0.2;
                    notes.Add($"Status is '{verdict.OverallStatus}', but no recommended remediation actions were specified.");
                }
            }

            completeness = Math.Clamp(completeness, 0.0, 1.0);
            return Task.FromResult(new SemanticEvaluationResult(
                SemanticScore: completeness,
                GroundingScore: 1.0,
                CompletenessScore: completeness,
                AntiHedgingScore: 1.0,
                QualityNotes: notes,
                UngroundedClaims: Array.Empty<string>(),
                ParsedVerdict: verdict));
        }

        // For non-structured contracts, basic length and richness check
        if (candidateContent.Length < 50)
        {
            completeness = 0.5;
            notes.Add("Response is brief and may lack complete information.");
        }

        return Task.FromResult(new SemanticEvaluationResult(
            SemanticScore: completeness,
            GroundingScore: 1.0,
            CompletenessScore: completeness,
            AntiHedgingScore: 1.0,
            QualityNotes: notes,
            UngroundedClaims: Array.Empty<string>()));
    }
}
