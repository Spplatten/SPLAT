using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Arbiter;

/// <summary>
/// Bradley-Terry Pairwise Arbiter with Minorization-Maximization (MM) convergence.
/// Evaluates candidate cohorts in pairwise fashion to eliminate positional, order, and presentation bias.
/// </summary>
public sealed class BradleyTerryArbiter : IBradleyTerryArbiter
{
    private const int DefaultMaxIterations = 100;
    private const double ConvergenceTolerance = 1e-6;
    private const double PriorSmoothing = 1e-3;

    public BradleyTerryRankingResult RankCandidates(
        IReadOnlyList<CandidateArtifact> candidates,
        string? telemetryHaystack = null)
    {
        if (candidates == null || candidates.Count == 0)
        {
            throw new ArgumentException("Candidate list cannot be empty.", nameof(candidates));
        }

        int k = candidates.Count;
        var candidateIds = candidates.Select(c => c.CandidateId).ToList();

        if (k == 1)
        {
            var singleMatrix = new BradleyTerryMatrix(
                CandidateIds: candidateIds,
                WinMatrix: new double[,] { { 0.5 } },
                WinCounts: new double[] { 1.0 },
                Lambdas: new double[] { 1.0 },
                Iterations: 0,
                Converged: true,
                ConvergenceDelta: 0.0);

            return new BradleyTerryRankingResult(
                RankedCandidates: new[] { (candidates[0].CandidateId, 1.0, 1) },
                Matrix: singleMatrix,
                TopCandidateId: candidates[0].CandidateId);
        }

        // 1. Build Pairwise Comparison Win Matrix W[i, j]
        double[,] w = new double[k, k];
        double[] totalWins = new double[k];

        for (int i = 0; i < k; i++)
        {
            for (int j = 0; j < k; j++)
            {
                if (i == j)
                {
                    w[i, j] = 0.0;
                    continue;
                }

                double probIBeatsJ = ComputePairwiseProbability(candidates[i], candidates[j]);
                // Apply prior smoothing to guarantee connectivity of comparison graph
                double winVal = probIBeatsJ + PriorSmoothing;
                w[i, j] = winVal;
                totalWins[i] += winVal;
            }
        }

        // 2. Solve Bradley-Terry parameters via Minorization-Maximization (MM) algorithm (Hunter 2004)
        double[] lambdas = new double[k];
        for (int i = 0; i < k; i++)
        {
            lambdas[i] = 1.0 / k;
        }

        int iterations = 0;
        bool converged = false;
        double maxDelta = 1.0;

        for (iterations = 1; iterations <= DefaultMaxIterations; iterations++)
        {
            double[] nextLambdas = new double[k];
            double sumNext = 0.0;

            for (int i = 0; i < k; i++)
            {
                double denominator = 0.0;
                for (int j = 0; j < k; j++)
                {
                    if (i == j) continue;
                    double n_ij = w[i, j] + w[j, i];
                    double sumLambda = lambdas[i] + lambdas[j];
                    if (sumLambda > 1e-12)
                    {
                        denominator += n_ij / sumLambda;
                    }
                }

                if (denominator > 1e-12)
                {
                    nextLambdas[i] = totalWins[i] / denominator;
                }
                else
                {
                    nextLambdas[i] = lambdas[i];
                }

                sumNext += nextLambdas[i];
            }

            // Normalize: sum(lambda_i) = 1.0
            if (sumNext > 0)
            {
                for (int i = 0; i < k; i++)
                {
                    nextLambdas[i] /= sumNext;
                }
            }

            // Check convergence
            maxDelta = 0.0;
            for (int i = 0; i < k; i++)
            {
                double delta = Math.Abs(nextLambdas[i] - lambdas[i]);
                if (delta > maxDelta) maxDelta = delta;
                lambdas[i] = nextLambdas[i];
            }

            if (maxDelta < ConvergenceTolerance)
            {
                converged = true;
                break;
            }
        }

        // 3. Rank candidates by lambda score descending
        var ranking = new List<(string CandidateId, double Score, int Rank)>();
        var sorted = candidateIds
            .Select((id, index) => new { Id = id, Score = lambdas[index], Index = index })
            .OrderByDescending(x => x.Score)
            .ToList();

        for (int rank = 0; rank < sorted.Count; rank++)
        {
            ranking.Add((sorted[rank].Id, sorted[rank].Score, rank + 1));
        }

        var matrix = new BradleyTerryMatrix(
            CandidateIds: candidateIds,
            WinMatrix: w,
            WinCounts: totalWins,
            Lambdas: lambdas,
            Iterations: iterations,
            Converged: converged,
            ConvergenceDelta: maxDelta);

        return new BradleyTerryRankingResult(
            RankedCandidates: ranking,
            Matrix: matrix,
            TopCandidateId: ranking[0].CandidateId);
    }

    /// <summary>
    /// Computes pairwise win probability P(A beats B) based on 2D Decision Matrix metrics.
    /// Uses logistic sigmoid over composite evaluation difference.
    /// </summary>
    private static double ComputePairwiseProbability(CandidateArtifact a, CandidateArtifact b)
    {
        double scoreA = ComputeCompositeArtifactScore(a);
        double scoreB = ComputeCompositeArtifactScore(b);

        // Strict Quadrant I superiority: Quadrant I always strictly preferred over non-Quadrant I
        if (a.Evaluation.PassedQuadrantI && !b.Evaluation.PassedQuadrantI)
        {
            return 0.99;
        }
        if (!a.Evaluation.PassedQuadrantI && b.Evaluation.PassedQuadrantI)
        {
            return 0.01;
        }

        // Logistic sigmoid scaling
        double diff = scoreA - scoreB;
        double prob = 1.0 / (1.0 + Math.Exp(-8.0 * diff));
        return Math.Clamp(prob, 0.01, 0.99);
    }

    private static double ComputeCompositeArtifactScore(CandidateArtifact artifact)
    {
        var eval = artifact.Evaluation;
        double x = eval.OracleResult.Score;
        double g = eval.SemanticResult.GroundingScore;
        double c = eval.SemanticResult.CompletenessScore;
        double h = eval.SemanticResult.AntiHedgingScore;

        // Weights: Oracle Validity (40%), Grounding (30%), Completeness (15%), Anti-Hedging (15%)
        return (x * 0.40) + (g * 0.30) + (c * 0.15) + (h * 0.15);
    }
}
