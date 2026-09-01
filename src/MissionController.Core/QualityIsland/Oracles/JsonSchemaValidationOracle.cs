using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Oracles;

/// <summary>
/// Deterministic Oracle validating JSON schema conformance and syntax integrity.
/// </summary>
public sealed class JsonSchemaValidationOracle : IValidationOracle
{
    private static readonly Regex JsonCodeBlockRegex = new(
        @"```(?:json)?\s*(\{[\s\S]*?\})\s*```",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RawJsonObjectRegex = new(
        @"\{(?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!))\}",
        RegexOptions.Compiled | RegexOptions.Singleline);

    public Task<OracleValidationResult> ValidateAsync(
        string candidateContent,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(candidateContent))
        {
            return Task.FromResult(OracleValidationResult.Fail(
                "Candidate content is empty or contains only whitespace."));
        }

        // Fast-path bypass for non-JSON contracts
        if (contractType == SchemaContractType.FreeFormGroundedText)
        {
            return Task.FromResult(OracleValidationResult.Pass());
        }

        // 1. Extract JSON string candidate
        string? jsonString = ExtractJsonCandidate(candidateContent);
        if (string.IsNullOrWhiteSpace(jsonString))
        {
            return Task.FromResult(OracleValidationResult.Fail(
                "No valid JSON code block or JSON object structure found in response."));
        }

        // 2. Parse JSON with System.Text.Json
        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(jsonString);
        }
        catch (JsonException ex)
        {
            return Task.FromResult(OracleValidationResult.Fail(
                $"JSON syntax parse failure: {ex.Message} (Line: {ex.LineNumber}, BytePositionInLine: {ex.BytePositionInLine})"));
        }

        using (doc)
        {
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Task.FromResult(OracleValidationResult.Fail(
                    $"JSON root element must be an Object, found '{root.ValueKind}'."));
            }

            var rejectionReasons = new List<string>();

            switch (contractType)
            {
                case SchemaContractType.StructuredDiagnosis:
                    ValidateStructuredDiagnosis(root, rejectionReasons);
                    break;

                case SchemaContractType.ReActDecision:
                    ValidateReActDecision(root, options.AllowedTemplateIds, rejectionReasons);
                    break;

                case SchemaContractType.GoalDecomposition:
                    ValidateGoalDecomposition(root, options.AllowedTemplateIds, rejectionReasons);
                    break;

                case SchemaContractType.CustomJson:
                default:
                    // Basic object validity passed
                    break;
            }

            if (rejectionReasons.Count > 0)
            {
                return Task.FromResult(OracleValidationResult.Fail(rejectionReasons));
            }
        }

        return Task.FromResult(OracleValidationResult.Pass());
    }

    private static void ValidateStructuredDiagnosis(JsonElement root, List<string> errors)
    {
        // Require 'status' property
        if (!TryGetPropertyInsensitive(root, "status", out var statusElem))
        {
            errors.Add("Missing required 'status' property in diagnosis JSON.");
        }
        else
        {
            string? statusStr = statusElem.GetString();
            if (string.IsNullOrWhiteSpace(statusStr))
            {
                errors.Add("'status' field is empty.");
            }
            else if (!Enum.TryParse<DiagnosticHealthStatus>(statusStr, true, out _))
            {
                errors.Add($"Invalid 'status' value '{statusStr}'. Must be 'Healthy', 'Warning', or 'Critical'.");
            }
        }

        // Require 'headline' property
        if (!TryGetPropertyInsensitive(root, "headline", out var headlineElem))
        {
            errors.Add("Missing required 'headline' property in diagnosis JSON.");
        }
        else if (string.IsNullOrWhiteSpace(headlineElem.GetString()))
        {
            errors.Add("'headline' field is empty.");
        }

        // Require 'findings' array
        if (!TryGetPropertyInsensitive(root, "findings", out var findingsElem))
        {
            errors.Add("Missing required 'findings' array in diagnosis JSON.");
        }
        else if (findingsElem.ValueKind != JsonValueKind.Array)
        {
            errors.Add("'findings' must be a JSON array of strings.");
        }

        // Optional 'recommendedActions'
        if (TryGetPropertyInsensitive(root, "recommendedActions", out var actionsElem) &&
            actionsElem.ValueKind != JsonValueKind.Array &&
            actionsElem.ValueKind != JsonValueKind.Null)
        {
            errors.Add("'recommendedActions' must be an array of strings or omitted.");
        }
    }

    private static void ValidateReActDecision(
        JsonElement root,
        IReadOnlyCollection<string>? allowedTemplateIds,
        List<string> errors)
    {
        // Require 'action' property: "continue" or "stop"
        if (!TryGetPropertyInsensitive(root, "action", out var actionElem))
        {
            errors.Add("Missing required 'action' property in ReAct decision JSON.");
            return;
        }

        string action = actionElem.GetString()?.Trim().ToLowerInvariant() ?? string.Empty;
        if (action != "continue" && action != "stop")
        {
            errors.Add($"Invalid 'action' value '{action}'. Must be 'continue' or 'stop'.");
        }

        // Require 'reason' property
        if (!TryGetPropertyInsensitive(root, "reason", out var reasonElem) || string.IsNullOrWhiteSpace(reasonElem.GetString()))
        {
            errors.Add("Missing or empty 'reason' justification in ReAct decision JSON.");
        }

        if (action == "continue")
        {
            if (!TryGetPropertyInsensitive(root, "templateId", out var templateElem))
            {
                errors.Add("Action 'continue' requires a 'templateId' property.");
            }
            else
            {
                string? tid = templateElem.GetString()?.Trim();
                if (string.IsNullOrWhiteSpace(tid))
                {
                    errors.Add("Action 'continue' specified an empty 'templateId'.");
                }
                else if (allowedTemplateIds != null && allowedTemplateIds.Count > 0 && !allowedTemplateIds.Contains(tid))
                {
                    errors.Add($"Selected 'templateId' '{tid}' is not present in the offered governed catalog.");
                }
            }
        }
    }

    private static void ValidateGoalDecomposition(
        JsonElement root,
        IReadOnlyCollection<string>? allowedTemplateIds,
        List<string> errors)
    {
        // Require 'recommendedTemplateIds' or 'templateIds'
        if (!TryGetPropertyInsensitive(root, "recommendedTemplateIds", out var recElem) &&
            !TryGetPropertyInsensitive(root, "templateIds", out recElem))
        {
            errors.Add("Missing required 'recommendedTemplateIds' array in goal decomposition JSON.");
        }
        else if (recElem.ValueKind != JsonValueKind.Array)
        {
            errors.Add("'recommendedTemplateIds' must be a JSON array.");
        }
        else if (allowedTemplateIds != null && allowedTemplateIds.Count > 0)
        {
            foreach (var item in recElem.EnumerateArray())
            {
                string? id = item.GetString()?.Trim();
                if (!string.IsNullOrEmpty(id) && !allowedTemplateIds.Contains(id))
                {
                    errors.Add($"Recommended template '{id}' is not in the available catalog.");
                }
            }
        }
    }

    private static bool TryGetPropertyInsensitive(JsonElement element, string propertyName, out JsonElement value)
    {
        foreach (var prop in element.EnumerateObject())
        {
            if (string.Equals(prop.Name, propertyName, StringComparison.OrdinalIgnoreCase))
            {
                value = prop.Value;
                return true;
            }
        }
        value = default;
        return false;
    }

    private static string? ExtractJsonCandidate(string content)
    {
        var match = JsonCodeBlockRegex.Match(content);
        if (match.Success)
        {
            return match.Groups[1].Value.Trim();
        }

        var rawMatch = RawJsonObjectRegex.Match(content);
        if (rawMatch.Success)
        {
            return rawMatch.Value.Trim();
        }

        return null;
    }
}
