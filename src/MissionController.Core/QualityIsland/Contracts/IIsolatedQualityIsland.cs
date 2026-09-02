using System;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Models;

namespace MissionController.Core.QualityIsland.Contracts;

/// <summary>
/// Isolated Quality Check & Escalate Island.
/// Executes AI model generation within an adjacent isolated sub-loop, enforcing 2D Decision Matrix
/// validation (Quadrant I: X >= 1.0, Y >= Y_threshold) and targeted frontier escalation before
/// returning clean artifacts to the main execution pipeline.
/// </summary>
public interface IIsolatedQualityIsland
{
    /// <summary>
    /// Executes the isolated check-and-escalate generation bubble.
    /// </summary>
    Task<QualityIslandResult> ExecuteIslandAsync(
        QualityIslandRequest request,
        IProgress<string>? tokenProgress = null,
        IProgress<MissionChunk>? chunkProgress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates a candidate artifact against the 2D Decision Matrix without invoking LLMs.
    /// </summary>
    Task<QuadrantEvaluationResult> EvaluateArtifactAsync(
        string candidateContent,
        string? rawTelemetry,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default);
}
