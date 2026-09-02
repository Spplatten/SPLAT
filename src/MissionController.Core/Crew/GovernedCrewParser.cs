using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace MissionController.Core.Crew;

/// <summary>
/// Parser and validator for dynamic declarative Governed Multi-Agent Crew definitions (JSON format).
/// Enforces structural integrity, role non-emptiness, and DAG dependency acyclicity.
/// </summary>
public static class GovernedCrewParser
{
    private static readonly JsonSerializerOptions DefaultOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Parses a JSON string into a validated GovernedCrewDefinition.
    /// </summary>
    public static GovernedCrewDefinition ParseJson(string jsonContent)
    {
        if (string.IsNullOrWhiteSpace(jsonContent))
            throw new ArgumentException("Crew definition JSON cannot be empty or whitespace.", nameof(jsonContent));

        GovernedCrewDefinition? crew;
        try
        {
            crew = JsonSerializer.Deserialize<GovernedCrewDefinition>(jsonContent, DefaultOptions);
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Invalid JSON format for GovernedCrewDefinition: {ex.Message}", ex);
        }

        if (crew == null)
            throw new FormatException("Failed to deserialize GovernedCrewDefinition (result was null).");

        // Validate baseline constraints
        crew.Validate();

        // Validate Task DAG dependencies
        ValidateTaskGraph(crew);

        return crew;
    }

    /// <summary>
    /// Serializes a GovernedCrewDefinition to a formatted JSON string.
    /// </summary>
    public static string ToJson(GovernedCrewDefinition crew)
    {
        ArgumentNullException.ThrowIfNull(crew);
        return JsonSerializer.Serialize(crew, DefaultOptions);
    }

    /// <summary>
    /// Validates that task context dependencies form a valid, acyclic directed graph (DAG).
    /// </summary>
    public static void ValidateTaskGraph(GovernedCrewDefinition crew)
    {
        var taskMap = crew.Tasks.ToDictionary(t => t.TaskId, StringComparer.OrdinalIgnoreCase);

        // 1. Verify all context task IDs reference valid tasks
        foreach (var task in crew.Tasks)
        {
            if (task.ContextTaskIds != null)
            {
                foreach (var depId in task.ContextTaskIds)
                {
                    if (!taskMap.ContainsKey(depId))
                    {
                        throw new InvalidOperationException(
                            $"Task '{task.TaskId}' references non-existent upstream context dependency '{depId}'.");
                    }
                    if (string.Equals(task.TaskId, depId, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException(
                            $"Task '{task.TaskId}' cannot declare a self-dependency on itself.");
                    }
                }
            }
        }

        // 2. Cycle detection in Task DAG (Topological check)
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var recursionStack = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var task in crew.Tasks)
        {
            if (!visited.Contains(task.TaskId))
            {
                if (HasCycle(task.TaskId, taskMap, visited, recursionStack))
                {
                    throw new InvalidOperationException(
                        $"Cyclic dependency detected in task dependency graph involving task '{task.TaskId}'.");
                }
            }
        }
    }

    private static bool HasCycle(
        string currentTaskId,
        Dictionary<string, GovernedCrewTask> taskMap,
        HashSet<string> visited,
        HashSet<string> recursionStack)
    {
        visited.Add(currentTaskId);
        recursionStack.Add(currentTaskId);

        if (taskMap.TryGetValue(currentTaskId, out var task) && task.ContextTaskIds != null)
        {
            foreach (var depId in task.ContextTaskIds)
            {
                if (!visited.Contains(depId))
                {
                    if (HasCycle(depId, taskMap, visited, recursionStack))
                        return true;
                }
                else if (recursionStack.Contains(depId))
                {
                    return true; // Cycle detected
                }
            }
        }

        recursionStack.Remove(currentTaskId);
        return false;
    }
}
