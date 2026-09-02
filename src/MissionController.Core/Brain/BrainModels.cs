using System;
using System.Collections.Generic;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core.Brain;

public enum HypothesisStatus
{
    Pending = 0,
    Confirmed = 1,
    Refuted = 2,
    Inconclusive = 3
}

/// <summary>
/// A testable hypothesis formulated by the agent brain during cognitive reasoning.
/// </summary>
public record BrainHypothesis(
    string HypothesisId,
    string Statement,
    string CandidateTemplateId,
    HypothesisStatus Status,
    string? GroundedEvidence,
    double ConfidenceScore);

/// <summary>
/// The result of decomposing an operator's high-level goal into structured cognitive sub-goals.
/// </summary>
public record GoalDecompositionResult(
    string UserGoal,
    IReadOnlyList<string> SubGoals,
    IReadOnlyList<string> RecommendedTemplateIds,
    double ConfidenceScore,
    string ReasoningRationale);

/// <summary>
/// Dynamic decision produced when re-planning between autonomous reasoning steps.
/// </summary>
public record NextStepPlanResult(
    bool ShouldContinue,
    string? NextTemplateId,
    string? NextHypothesisStatement,
    string Rationale,
    double ConfidenceScore);

/// <summary>
/// Short-term cognitive working memory maintained throughout an autonomous multi-step reasoning session.
/// </summary>
public sealed class BrainWorkingMemory
{
    public Guid SessionId { get; }
    public string UserGoal { get; }
    public List<BrainHypothesis> Hypotheses { get; } = new();
    public List<string> GroundedFacts { get; } = new();
    public List<string> RefutedSignals { get; } = new();
    public List<InvestigationStep> CompletedSteps { get; } = new();
    public List<SemanticSearchResult> RecalledPastIncidents { get; } = new();
    public List<RemediationAction> AvailableRemediations { get; } = new();
    public string? SynthesizedRootCause { get; set; }
    public DiagnosticHealthStatus OverallStatus { get; set; } = DiagnosticHealthStatus.Healthy;

    public BrainWorkingMemory(Guid sessionId, string userGoal)
    {
        SessionId = sessionId;
        UserGoal = userGoal;
    }
}

/// <summary>
/// Comprehensive outcome of an autonomous reasoning session performed by the SPLAT Agent Brain.
/// </summary>
public record BrainExecutionResult(
    Guid SessionId,
    string UserGoal,
    DiagnosticHealthStatus OverallStatus,
    string ExecutiveHeadline,
    string RootCauseAnalysis,
    IReadOnlyList<string> GroundedKeyFindings,
    IReadOnlyList<BrainHypothesis> EvaluatedHypotheses,
    IReadOnlyList<InvestigationStep> ExecutedSteps,
    IReadOnlyList<RemediationAction> AvailableRemediations,
    string? AuditLedgerEntryHash,
    DateTime TimestampUtc);
