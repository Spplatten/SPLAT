using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core.QualityIsland.Contracts;

/// <summary>
/// Semantic & Telemetry Grounding Evaluator (Y-Axis: [0.0, 1.0]).
/// Assesses whether a generated artifact is factually grounded in raw telemetry,
/// contains actionable non-hedging recommendations, and delivers complete diagnostic clarity.
/// </summary>
public interface ISemanticEvaluator
{
    /// <summary>
    /// Evaluates semantic quality and evidence grounding of the candidate output against raw telemetry.
    /// </summary>
    Task<SemanticEvaluationResult> EvaluateAsync(
        string candidateContent,
        string? telemetryHaystack,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default);
}
