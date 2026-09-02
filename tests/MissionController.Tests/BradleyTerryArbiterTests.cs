using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core.QualityIsland;
using MissionController.Core.QualityIsland.Arbiter;
using Xunit;

namespace MissionController.Tests;

public class BradleyTerryArbiterTests
{
    private static CandidateArtifact CreateMockCandidate(
        string id,
        bool passedQuadrantI,
        double oracleScore,
        double groundingScore,
        double completenessScore,
        double antiHedgingScore)
    {
        var eval = new QuadrantEvaluationResult(
            Point: new DecisionMatrixPoint(oracleScore, groundingScore),
            Quadrant: passedQuadrantI ? EvaluationQuadrant.QuadrantI_Pass : EvaluationQuadrant.QuadrantIII_Reject,
            PassedQuadrantI: passedQuadrantI,
            OracleResult: new OracleValidationResult(passedQuadrantI, oracleScore, Array.Empty<string>(), Array.Empty<string>()),
            SemanticResult: new SemanticEvaluationResult(
                SemanticScore: groundingScore,
                GroundingScore: groundingScore,
                CompletenessScore: completenessScore,
                AntiHedgingScore: antiHedgingScore,
                QualityNotes: Array.Empty<string>(),
                UngroundedClaims: Array.Empty<string>()),
            Summary: $"Candidate {id}");

        return new CandidateArtifact(
            CandidateId: id,
            ModelId: "test-model",
            RawContent: $"Raw content for {id}",
            SanitizedContent: $"Sanitized content for {id}",
            Evaluation: eval,
            LatencyMs: 100);
    }

    [Fact]
    public void Arbiter_SingleCandidate_ReturnsRank1WithScore1()
    {
        var arbiter = new BradleyTerryArbiter();
        var cand = CreateMockCandidate("cand-1", true, 1.0, 0.9, 0.9, 0.9);

        var result = arbiter.RankCandidates(new[] { cand });

        Assert.Equal("cand-1", result.TopCandidateId);
        Assert.Single(result.RankedCandidates);
        Assert.Equal(1.0, result.RankedCandidates[0].Score);
        Assert.Equal(1, result.RankedCandidates[0].Rank);
        Assert.True(result.Matrix.Converged);
    }

    [Fact]
    public void Arbiter_MinorizationMaximization_ConvergesAndNormalizesLambdas()
    {
        var arbiter = new BradleyTerryArbiter();
        var c1 = CreateMockCandidate("cand-high", true, 1.0, 0.95, 0.90, 0.95);
        var c2 = CreateMockCandidate("cand-med", true, 1.0, 0.75, 0.80, 0.80);
        var c3 = CreateMockCandidate("cand-low", false, 0.5, 0.40, 0.50, 0.50);

        var result = arbiter.RankCandidates(new[] { c1, c2, c3 });

        Assert.True(result.Matrix.Converged);
        Assert.True(result.Matrix.Iterations > 0);
        Assert.True(result.Matrix.Iterations <= 100);

        // Assert Normalization: Sum(lambda_i) == 1.0
        double sumLambdas = result.Matrix.Lambdas.Sum();
        Assert.True(Math.Abs(sumLambdas - 1.0) < 1e-5, $"Sum of lambdas was {sumLambdas}, expected 1.0");

        // Assert Correct Ranking: high > med > low
        Assert.Equal("cand-high", result.TopCandidateId);
        Assert.Equal("cand-high", result.RankedCandidates[0].CandidateId);
        Assert.Equal("cand-med", result.RankedCandidates[1].CandidateId);
        Assert.Equal("cand-low", result.RankedCandidates[2].CandidateId);

        Assert.True(result.RankedCandidates[0].Score > result.RankedCandidates[1].Score);
        Assert.True(result.RankedCandidates[1].Score > result.RankedCandidates[2].Score);
    }

    [Fact]
    public void Arbiter_QuadrantISuperiority_AlwaysOutranksNonQuadrantICandidates()
    {
        var arbiter = new BradleyTerryArbiter();
        // cNonQuad has high prose semantic score but failed oracle (e.g. invalid syntax)
        var cNonQuad = CreateMockCandidate("cand-invalid-syntax", false, 0.0, 0.99, 0.99, 0.99);
        // cQuad has passed Quadrant I with solid metrics
        var cQuad = CreateMockCandidate("cand-quadrant-i", true, 1.0, 0.85, 0.85, 0.85);

        var result = arbiter.RankCandidates(new[] { cNonQuad, cQuad });

        Assert.Equal("cand-quadrant-i", result.TopCandidateId);
        Assert.True(result.RankedCandidates[0].Score > result.RankedCandidates[1].Score);
    }

    [Fact]
    public void Arbiter_IsPositionallyInvariant_PermutedInputYieldsIdenticalWinner()
    {
        var arbiter = new BradleyTerryArbiter();
        var c1 = CreateMockCandidate("A", true, 1.0, 0.90, 0.90, 0.90);
        var c2 = CreateMockCandidate("B", true, 1.0, 0.70, 0.70, 0.70);
        var c3 = CreateMockCandidate("C", true, 1.0, 0.80, 0.80, 0.80);

        // Order 1: A, B, C
        var res1 = arbiter.RankCandidates(new[] { c1, c2, c3 });
        // Order 2: B, C, A
        var res2 = arbiter.RankCandidates(new[] { c2, c3, c1 });
        // Order 3: C, A, B
        var res3 = arbiter.RankCandidates(new[] { c3, c1, c2 });

        Assert.Equal("A", res1.TopCandidateId);
        Assert.Equal("A", res2.TopCandidateId);
        Assert.Equal("A", res3.TopCandidateId);

        // Check relative ranking: A (rank 1), C (rank 2), B (rank 3)
        var scores1 = res1.RankedCandidates.ToDictionary(x => x.CandidateId, x => x.Rank);
        var scores2 = res2.RankedCandidates.ToDictionary(x => x.CandidateId, x => x.Rank);
        var scores3 = res3.RankedCandidates.ToDictionary(x => x.CandidateId, x => x.Rank);

        Assert.Equal(1, scores1["A"]);
        Assert.Equal(2, scores1["C"]);
        Assert.Equal(3, scores1["B"]);

        Assert.Equal(1, scores2["A"]);
        Assert.Equal(2, scores2["C"]);
        Assert.Equal(3, scores2["B"]);

        Assert.Equal(1, scores3["A"]);
        Assert.Equal(2, scores3["C"]);
        Assert.Equal(3, scores3["B"]);
    }
}
