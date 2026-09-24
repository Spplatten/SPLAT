using System;
using System.Collections.Generic;
using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Core.QualityIsland;

/// <summary>
/// Execution mode for the Isolated Quality Island.
/// </summary>
public enum QualityExecutionMode
{
    /// <summary>
    /// Lean Production Fail-Safe (Default): Single fast generation -> zero-cost deterministic gate ->
    /// targeted single frontier escalation with error telemetry. 0ms extra latency on happy path.
    /// </summary>
    LeanFailSafe = 0,

    /// <summary>
    /// Speculative Best-of-N Sampling: Spawns N parallel generations, filters to Quadrant I cohort,
    /// and uses Bradley-Terry Pairwise Arbiter with MM convergence to rank and select the optimal artifact.
    /// </summary>
    SpeculativeBestOfN = 1,

    /// <summary>
    /// Incremental Stream Verification: Evaluates stream prefix tokens to early-abort malformed or invalid syntax.
    /// </summary>
    IncrementalEarlyAbort = 2
}

/// <summary>
/// Schema contract expected for the generation output.
/// </summary>
public enum SchemaContractType
{
    /// <summary>
    /// Standard structured executive diagnostic (status, headline, findings, recommendedActions).
    /// </summary>
    StructuredDiagnosis = 0,

    /// <summary>
    /// ReAct step decision (action, templateId, reason).
    /// </summary>
    ReActDecision = 1,

    /// <summary>
    /// Cognitive Goal Decomposition (userGoal, subGoals, recommendedTemplateIds, confidenceScore, reasoningRationale).
    /// </summary>
    GoalDecomposition = 2,

    /// <summary>
    /// Dynamic code or script (Python, Bash, Shell) requiring AST security validation.
    /// </summary>
    DynamicCodeScript = 3,

    /// <summary>
    /// Generic or custom JSON schema contract.
    /// </summary>
    CustomJson = 4,

    /// <summary>
    /// Free-form text without strict JSON requirement, but requiring structural and grounding integrity.
    /// </summary>
    FreeFormGroundedText = 5
}

/// <summary>
/// 2D Decision Matrix Quadrant classification.
/// </summary>
public enum EvaluationQuadrant
{
    /// <summary>
    /// Quadrant I (Top-Right): X >= 1.0 (Deterministic Valid) AND Y >= Y_threshold (Semantic Quality).
    /// ONLY Quadrant I artifacts are permitted to propagate downstream into the main pipeline.
    /// </summary>
    QuadrantI_Pass = 1,

    /// <summary>
    /// Quadrant II (Top-Left): X < 1.0 (Syntactically / Programmatically Invalid) AND Y >= Y_threshold (High Semantic Content).
    /// Rejected due to deterministic / schema failure.
    /// </summary>
    QuadrantII_SemanticOnly = 2,

    /// <summary>
    /// Quadrant III (Bottom-Left): X < 1.0 (Invalid) AND Y < Y_threshold (Low Semantic Quality).
    /// Completely rejected.
    /// </summary>
    QuadrantIII_Reject = 3,

    /// <summary>
    /// Quadrant IV (Bottom-Right): X >= 1.0 (Deterministic Valid) AND Y < Y_threshold (Low Semantic Quality / Ungrounded).
    /// Rejected due to semantic / grounding hallucination failure.
    /// </summary>
    QuadrantIV_DeterministicOnly = 4
}

/// <summary>
/// Point on the 2D Decision Matrix.
/// </summary>
/// <param name="X">Deterministic Programmatic Validity score in [0.0, 1.0]. X = 1.0 is required for Quadrant I.</param>
/// <param name="Y">Semantic Quality & Grounding score in [0.0, 1.0]. Y >= Y_threshold is required for Quadrant I.</param>
public readonly record struct DecisionMatrixPoint(double X, double Y)
{
    public override string ToString() => $"({X:F2}, {Y:F2})";
}

/// <summary>
/// Result of deterministic programmatic oracle validation (X-Axis).
/// </summary>
public sealed record OracleValidationResult(
    bool IsProgrammaticallyValid,
    double Score,
    IReadOnlyList<string> RejectionReasons,
    IReadOnlyList<string> DetectedRisks,
    IReadOnlyDictionary<string, string>? ViolationDetails = null)
{
    public static OracleValidationResult Pass() =>
        new(true, 1.0, Array.Empty<string>(), Array.Empty<string>());

    public static OracleValidationResult Fail(string reason, IReadOnlyList<string>? risks = null, double score = 0.0) =>
        new(false, score, new[] { reason }, risks ?? Array.Empty<string>());

    public static OracleValidationResult Fail(IReadOnlyList<string> reasons, IReadOnlyList<string>? risks = null, double score = 0.0) =>
        new(false, score, reasons, risks ?? Array.Empty<string>());
}

/// <summary>
/// Result of semantic quality and evidence grounding evaluation (Y-Axis).
/// </summary>
public sealed record SemanticEvaluationResult(
    double SemanticScore,
    double GroundingScore,
    double CompletenessScore,
    double AntiHedgingScore,
    IReadOnlyList<string> QualityNotes,
    IReadOnlyList<string> UngroundedClaims,
    ExecutiveDiagnosisResult? ParsedVerdict = null)
{
    public static SemanticEvaluationResult Pass(
        double score,
        double groundingScore = 1.0,
        double completenessScore = 1.0,
        double antiHedgingScore = 1.0,
        ExecutiveDiagnosisResult? parsedVerdict = null) =>
        new(score, groundingScore, completenessScore, antiHedgingScore, Array.Empty<string>(), Array.Empty<string>(), parsedVerdict);
}

/// <summary>
/// Combined 2D Decision Matrix evaluation result for a single candidate artifact.
/// </summary>
public sealed record QuadrantEvaluationResult(
    DecisionMatrixPoint Point,
    EvaluationQuadrant Quadrant,
    bool PassedQuadrantI,
    OracleValidationResult OracleResult,
    SemanticEvaluationResult SemanticResult,
    string Summary);

/// <summary>
/// Candidate artifact generated within the isolated island bubble.
/// </summary>
public sealed record CandidateArtifact(
    string CandidateId,
    string ModelId,
    string RawContent,
    string SanitizedContent,
    QuadrantEvaluationResult Evaluation,
    long LatencyMs,
    int AttemptIndex = 0);

/// <summary>
/// Options and thresholds governing the Quality Island.
/// </summary>
public sealed record QualityIslandOptions(
    QualityExecutionMode Mode = QualityExecutionMode.LeanFailSafe,
    double SemanticThreshold = 0.75,
    int SpeculativeSampleSize = 3,
    int MaxEscalationAttempts = 1,
    /// <summary>
    /// The model a rejected analysis is escalated TO, which must be a rung above the one that was
    /// rejected or the escalation is a retry. This defaulted to claude-sonnet-5 - the model
    /// GovernedTemplateCatalog.ModelPro already targets - so for most of the catalog the gate
    /// rejected an analysis and asked the same weights again. Pinned to the same Opus snapshot
    /// ClaudeStreamClient resolves the family to, for the reason stated there: the raw client has
    /// no refusal-stop_reason handling, which a newer Opus wants.
    /// </summary>
    string? FrontierEscalationModel = "claude-opus-4-8",
    string? DynamicLanguage = "bash",
    IReadOnlyCollection<string>? AllowedTemplateIds = null,
    bool EarlyStreamAbortOnSyntaxError = false);

/// <summary>
/// Request to execute an isolated generation within the Quality Island.
/// </summary>
public sealed record QualityIslandRequest(
    Guid MissionId,
    string TemplateId,
    string TargetModel,
    string SystemPrompt,
    string UserPayload,
    string OperatorIdentity,
    SchemaContractType RequiredSchema = SchemaContractType.StructuredDiagnosis,
    string? ExpectedTelemetryHaystack = null,
    QualityIslandOptions? Options = null,
    IReadOnlyDictionary<string, string>? Metadata = null);

/// <summary>
/// Final result produced by the Quality Island.
/// </summary>
public sealed record QualityIslandResult(
    Guid MissionId,
    string TemplateId,
    bool IsSuccess,
    string OutputContent,
    CandidateArtifact WinningArtifact,
    IReadOnlyList<CandidateArtifact> EvaluatedCohort,
    EscalationTelemetry Telemetry,
    DateTime CompletedAtUtc);

/// <summary>
/// Telemetry record capturing escalation, oracle diagnostics, and arbitration metrics.
/// </summary>
public sealed record EscalationTelemetry(
    int TotalCandidatesGenerated,
    int EscalationCount,
    bool EscalationTriggered,
    string? InitialFailureReason,
    string? EscalatedModelUsed,
    long TotalLatencyMs,
    BradleyTerryRankingResult? ArbiterRanking = null);

/// <summary>
/// Pairwise comparison matrix and Minorization-Maximization (MM) solution for Bradley-Terry model.
/// </summary>
public sealed record BradleyTerryMatrix(
    IReadOnlyList<string> CandidateIds,
    double[,] WinMatrix,
    double[] WinCounts,
    double[] Lambdas,
    int Iterations,
    bool Converged,
    double ConvergenceDelta);

/// <summary>
/// Ranking result from Bradley-Terry Pairwise Arbiter.
/// </summary>
public sealed record BradleyTerryRankingResult(
    IReadOnlyList<(string CandidateId, double Score, int Rank)> RankedCandidates,
    BradleyTerryMatrix Matrix,
    string TopCandidateId);
