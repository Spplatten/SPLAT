using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace MissionController.Core;

/// <summary>
/// The model's answer to "should this investigation take another step, and if so which one".
/// </summary>
/// <param name="ShouldContinue">True only when a valid, governed follow-up template was selected.</param>
/// <param name="TemplateId">A template id drawn from the offered catalog - never a synthesized command.</param>
/// <param name="Reason">Operator-facing justification, shown in the investigation trail.</param>
public record NextStepDecision(bool ShouldContinue, string? TemplateId, string Reason);

/// <summary>
/// Prompt contract and defensive parser for the ReAct loop's step decision.
///
/// The security property that makes this loop safe to run is enforced here rather than at the call
/// site: the model does not get to say what to execute, only to PICK from a catalog of governed
/// templates that were each already vetted for the 1:1:1 rule. A decision naming anything outside
/// the offered set is not an error to recover from - it is treated as "stop", because a model
/// reaching for a tool it was not offered is precisely the case that must never reach a sandbox.
/// </summary>
public static class ReActDecisionContract
{
    private static readonly Regex JsonCodeBlockRegex = new(
        @"```(?:json)?\s*(\{[\s\S]*?\})\s*```",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RawJsonObjectRegex = new(
        @"\{(?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!))\}",
        RegexOptions.Compiled | RegexOptions.Singleline);

    /// <summary>
    /// Builds the decision prompt. Candidate templates are listed explicitly so the model chooses by
    /// id from a closed set; the already-visited list is included so it can see why a repeat would be
    /// pointless, even though the loop refuses repeats regardless of what it answers.
    /// </summary>
    public static string BuildDecisionPrompt(
        string investigationGoal,
        IReadOnlyList<(string TemplateId, string Name, string Description)> candidates,
        IReadOnlyList<string> alreadyVisited)
    {
        var sb = new StringBuilder();
        sb.AppendLine("You are triaging a Windows endpoint. A diagnostic step just completed and its verdict is in the");
        sb.AppendLine("message below. Decide whether ONE more diagnostic step would meaningfully advance the investigation.");
        sb.AppendLine();
        sb.AppendLine($"[INVESTIGATION GOAL]: {investigationGoal}");
        sb.AppendLine();

        if (alreadyVisited.Count > 0)
        {
            sb.AppendLine($"[ALREADY RUN — do not repeat]: {string.Join(", ", alreadyVisited)}");
            sb.AppendLine();
        }

        sb.AppendLine("[AVAILABLE DIAGNOSTIC TEMPLATES — you may select ONE by exact templateId, or none]:");
        foreach (var candidate in candidates)
        {
            sb.AppendLine($"- {candidate.TemplateId}: {candidate.Name} — {candidate.Description}");
        }

        sb.AppendLine();
        sb.AppendLine("Reply with a brief sentence of reasoning, then close with exactly one fenced JSON block:");
        sb.AppendLine();
        sb.AppendLine("```json");
        sb.AppendLine("{");
        sb.AppendLine("  \"action\": \"continue | stop\",");
        sb.AppendLine("  \"templateId\": \"exact id from the list above, or null when stopping\",");
        sb.AppendLine("  \"reason\": \"one sentence an operator will read explaining this choice\"");
        sb.AppendLine("}");
        sb.AppendLine("```");
        sb.AppendLine();
        sb.AppendLine("Rules:");
        sb.AppendLine("- Choose \"continue\" ONLY when the finished step surfaced a specific unexplained signal that a");
        sb.AppendLine("  listed template would actually investigate. Curiosity is not a reason to spend a step.");
        sb.AppendLine("- \"templateId\" MUST be copied exactly from the list. Never invent a tool, command, or id.");
        sb.AppendLine("- Choose \"stop\" when the system looks healthy, the finding is already explained, or no listed");
        sb.AppendLine("  template addresses what you saw.");

        return sb.ToString();
    }

    /// <summary>
    /// Parses a decision and validates it against the offered catalog in one pass, so a caller cannot
    /// forget the whitelist check. Anything ambiguous resolves to "stop": in a loop that spawns
    /// sandboxed processes, the safe default on a malformed answer is to do nothing further.
    /// </summary>
    public static NextStepDecision Parse(string? modelOutput, IReadOnlyCollection<string> allowedTemplateIds)
    {
        if (string.IsNullOrWhiteSpace(modelOutput))
        {
            return new NextStepDecision(false, null, "No decision returned by the model; investigation stopped.");
        }

        foreach (var candidate in EnumerateJsonCandidates(modelOutput))
        {
            try
            {
                using var document = JsonDocument.Parse(candidate);
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                string? action = ReadString(root, "action");
                // "taskId" alias: the governed crew manager reuses this contract to pick tasks
                // from a closed pending set, keeping one whitelist gate for both loops.
                string? templateId = ReadString(root, "templateId", "template_id", "template", "taskId");
                string reason = ReadString(root, "reason", "rationale", "why")
                                ?? "No rationale supplied by the model.";

                bool wantsToContinue = action != null &&
                                       action.Contains("continue", StringComparison.OrdinalIgnoreCase);

                if (!wantsToContinue)
                {
                    return new NextStepDecision(false, null, reason);
                }

                if (string.IsNullOrWhiteSpace(templateId))
                {
                    return new NextStepDecision(false, null,
                        "Model asked to continue without naming a template; investigation stopped.");
                }

                // The whitelist gate. A model naming an id it was not offered is refused outright
                // rather than corrected - there is no safe way to guess what it meant to run.
                var match = allowedTemplateIds.FirstOrDefault(
                    id => id.Equals(templateId.Trim(), StringComparison.OrdinalIgnoreCase));

                if (match is null)
                {
                    return new NextStepDecision(false, null,
                        $"Model selected template '{templateId.Trim()}', which was not in the governed catalog it was " +
                        "offered. Investigation stopped.");
                }

                return new NextStepDecision(true, match, reason);
            }
            catch (JsonException)
            {
                // Partial or non-JSON frame - try the next candidate.
            }
        }

        return new NextStepDecision(false, null,
            "Model response contained no parseable decision; investigation stopped.");
    }

    private static IEnumerable<string> EnumerateJsonCandidates(string modelOutput)
    {
        var seen = new List<string>();

        var fenced = JsonCodeBlockRegex.Match(modelOutput);
        if (fenced.Success)
        {
            seen.Add(fenced.Groups[1].Value);
            yield return fenced.Groups[1].Value;
        }

        foreach (Match match in RawJsonObjectRegex.Matches(modelOutput))
        {
            if (!seen.Contains(match.Value, StringComparer.Ordinal))
            {
                yield return match.Value;
            }
        }
    }

    private static string? ReadString(JsonElement root, params string[] names)
    {
        foreach (var property in root.EnumerateObject())
        {
            if (names.Any(name => property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) &&
                property.Value.ValueKind == JsonValueKind.String)
            {
                return property.Value.GetString();
            }
        }

        return null;
    }
}
