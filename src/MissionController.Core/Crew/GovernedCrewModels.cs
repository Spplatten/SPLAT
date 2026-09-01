using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Core.Crew;

/// <summary>
/// Execution process type for multi-agent crews.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum CrewProcessType
{
    /// <summary>
    /// Tasks execute sequentially in declared order with upstream context propagation and DLP filtering.
    /// </summary>
    Sequential = 0,

    /// <summary>
    /// A manager agent dynamically assigns and routes tasks to specialized worker agents with cycle detection.
    /// </summary>
    Hierarchical = 1
}

/// <summary>
/// Governed agent role definition within a multi-agent crew.
/// Bounded by assigned tool templates, LLM model, execution timeout, and explicit negative constraints.
/// </summary>
public record GovernedCrewAgent(
    string AgentId,
    string Role,
    string Goal,
    string Backstory,
    string TargetModel = "claude-sonnet-5",
    IReadOnlyList<string>? AssignedTemplateIds = null,
    bool AllowDelegation = false,
    int MaxIterations = 3,
    int ExecutionTimeoutSeconds = 60)
{
    /// <summary>
    /// Builds the system prompt for this agent, enforcing role boundaries and strict negative constraints.
    /// </summary>
    public string BuildSystemPrompt()
    {
        var templatesList = AssignedTemplateIds != null && AssignedTemplateIds.Count > 0
            ? string.Join(", ", AssignedTemplateIds)
            : "None (Analytical only)";

        return $@"ROLE: {Role}
GOAL: {Goal}
BACKSTORY & CONTEXT:
{Backstory}

GOVERNED EXECUTION CONSTRAINTS:
1. You are a specialized component of the SPLAT Governed Multi-Agent System.
2. You ONLY operate within your defined domain ({Role}).
3. Assigned Governed Templates: [{templatesList}].
4. DO NOT attempt to run commands or access resources outside of your assigned governed templates.
5. {(AllowDelegation ? "You may delegate sub-tasks when explicitly needed." : "DELEGATION IS FORBIDDEN: You must solve your task directly without delegating to peers.")}
6. Provide structured, factual, and verified outputs without speculation.";
    }
}

/// <summary>
/// A discrete governed task assigned within a multi-agent crew.
/// </summary>
public record GovernedCrewTask(
    string TaskId,
    string Description,
    string ExpectedOutput,
    string AssignedAgentId,
    string? TemplateId = null,
    IReadOnlyList<string>? ContextTaskIds = null,
    string? OutputSchemaJson = null,
    bool ContinueOnFailure = false);

/// <summary>
/// Top-level definition of a Governed Multi-Agent Crew.
/// </summary>
public record GovernedCrewDefinition(
    string CrewId,
    string Name,
    string Description,
    CrewProcessType ProcessType,
    IReadOnlyList<GovernedCrewAgent> Agents,
    IReadOnlyList<GovernedCrewTask> Tasks,
    GovernedCrewAgent? ManagerAgent = null,
    int MaxRpm = 30,
    int MaxCrewIterations = 10,
    bool EnableSemanticMemory = true)
{
    /// <summary>
    /// Validates the structural integrity and boundary rules of the crew definition.
    /// </summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(CrewId))
            throw new InvalidOperationException("CrewId cannot be null or empty.");

        if (string.IsNullOrWhiteSpace(Name))
            throw new InvalidOperationException("Crew Name cannot be null or empty.");

        if (Agents == null || Agents.Count == 0)
            throw new InvalidOperationException("Crew must contain at least one agent.");

        if (Tasks == null || Tasks.Count == 0)
            throw new InvalidOperationException("Crew must contain at least one task.");

        var agentIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var agent in Agents)
        {
            if (!agentIds.Add(agent.AgentId))
                throw new InvalidOperationException($"Duplicate AgentId '{agent.AgentId}' in crew.");
        }

        if (ProcessType == CrewProcessType.Hierarchical && ManagerAgent == null)
            throw new InvalidOperationException("Hierarchical process type requires a configured ManagerAgent.");

        var taskIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var task in Tasks)
        {
            if (!taskIds.Add(task.TaskId))
                throw new InvalidOperationException($"Duplicate TaskId '{task.TaskId}' in crew.");

            if (!agentIds.Contains(task.AssignedAgentId) &&
                (ManagerAgent == null || !string.Equals(ManagerAgent.AgentId, task.AssignedAgentId, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"Task '{task.TaskId}' references unassigned agent '{task.AssignedAgentId}'.");
            }
        }
    }
}

/// <summary>
/// Result of executing an individual task within a crew.
/// </summary>
public record CrewTaskResult(
    string TaskId,
    string AgentId,
    string RawOutput,
    string SanitizedOutput,
    ExecutiveDiagnosisResult? ExtractedFindings,
    bool Success,
    long ExecutionDurationMs,
    DateTime TimestampUtc);

/// <summary>
/// Comprehensive outcome of an entire multi-agent crew execution session.
/// </summary>
public record CrewExecutionResult(
    Guid CrewMissionId,
    string CrewId,
    DiagnosticHealthStatus OverallStatus,
    string ExecutiveSummary,
    IReadOnlyList<CrewTaskResult> TaskResults,
    string? AuditLedgerEntryHash,
    long TotalDurationMs,
    bool CycleDetected,
    DateTime CompletedAtUtc);
