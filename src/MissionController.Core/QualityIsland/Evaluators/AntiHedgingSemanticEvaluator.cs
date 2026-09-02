using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Evaluators;

/// <summary>
/// Evaluates and penalizes evasive hedging, circular non-answers, and conversational boilerplate
/// ("As an AI language model...", "I cannot determine...", "It depends...").
/// </summary>
public sealed class AntiHedgingSemanticEvaluator : ISemanticEvaluator
{
    private static readonly (Regex Pattern, double Penalty, string Reason)[] HedgingPatterns = new[]
    {
        (new Regex(@"\b(as an ai|as a large language model|i do not have access to|i cannot execute)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), 0.5, "Standard AI refusal / self-identification boilerplate"),
        (new Regex(@"\b(i am unable to determine|cannot be determined without further information|it is impossible to know)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), 0.3, "Excessive hedging / non-committal evasion"),
        (new Regex(@"\b(please consult a professional|contact your system administrator)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), 0.2, "Deflective boilerplate advice in diagnostic context"),
        (new Regex(@"\b(sorry for the confusion|apologies for the oversight)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), 0.2, "Conversational apology filler")
    };

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

        double score = 1.0;
        var notes = new List<string>();

        foreach (var (pattern, penalty, reason) in HedgingPatterns)
        {
            if (pattern.IsMatch(candidateContent))
            {
                score -= penalty;
                notes.Add($"[HEDGING_PENALTY] {reason}");
            }
        }

        score = Math.Clamp(score, 0.0, 1.0);

        return Task.FromResult(new SemanticEvaluationResult(
            SemanticScore: score,
            GroundingScore: 1.0,
            CompletenessScore: 1.0,
            AntiHedgingScore: score,
            QualityNotes: notes,
            UngroundedClaims: Array.Empty<string>()));
    }
}
