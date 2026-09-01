using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core.QualityIsland.Contracts;

/// <summary>
/// Bradley-Terry Pairwise Arbiter with Minorization-Maximization (MM) convergence.
/// Evaluates candidate cohorts in pairs to eliminate presentation and positional bias.
/// </summary>
public interface IBradleyTerryArbiter
{
    /// <summary>
    /// Computes pairwise comparison matrix and solves for candidate skill ratings via MM convergence.
    /// </summary>
    BradleyTerryRankingResult RankCandidates(
        IReadOnlyList<CandidateArtifact> candidates,
        string? telemetryHaystack = null);
}
