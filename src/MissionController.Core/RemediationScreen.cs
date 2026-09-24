using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MissionController.Core;

/// <summary>
/// A recommended action is the one part of a diagnosis a human is invited to run, and it travels
/// further than the diagnosis does: the UI shows it, the MCP server hands it to a calling agent, and
/// the semantic index replays it into the next similar mission as a RESOLUTION line. Nothing read it.
///
/// A model asked to analyse telemetry that CONTAINS a repair command will quote that command, and
/// quoting it is correct behaviour - the command really is in the evidence. So the screen does not
/// try to decide intent. It marks the shapes whose danger does not depend on intent at all: code
/// fetched from the network and executed in one step, execution that is deliberately opaque or
/// unpoliced, and the disabling of a security control. Those are the shapes that turn "the operator
/// pasted a suggestion" into a compromise.
///
/// The flagged action is KEPT, prefixed. Dropping it would hide from the operator the single best
/// evidence that the telemetry was planted, and would leave the findings referring to an action that
/// is no longer there.
/// </summary>
public static class RemediationScreen
{
    /// <summary>What a screened action is prefixed with. One string, so a renderer can find it.</summary>
    public const string Marker = "⚠ UNSCREENED-RISK";

    private sealed record Rule(string Category, Regex Pattern);

    // Deliberately narrow. Every pattern here describes a mechanism, not a tool: `curl` is fine,
    // `curl | sh` is not, and a screen that flagged the first would be turned off within a week.
    private static readonly Rule[] Rules =
    {
        new("fetch-and-execute",
            new Regex(
                @"(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|DownloadString|DownloadFile)" +
                @"[\s\S]{0,200}?\|[\s\S]{0,40}?(?:\b(?:sh|bash|zsh|python3?|perl|node)\b|Invoke-Expression|\biex\b)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),

        new("fetch-and-execute",
            new Regex(
                @"(?:iex|Invoke-Expression)\s*\(?\s*(?:\(|new-object|Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl|wget)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),

        // certutil and bitsadmin are living-off-the-land downloaders; naming a URL is the tell.
        new("fetch-and-execute",
            new Regex(@"(?:certutil[\s\S]{0,80}?-urlcache|bitsadmin[\s\S]{0,80}?/transfer)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),

        new("unpoliced-execution",
            new Regex(@"-(?:ep|ExecutionPolicy)\s+(?:Bypass|Unrestricted)",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),

        // A base64 command line is unreadable by the operator being asked to approve it.
        new("opaque-execution",
            new Regex(@"-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/]{24,}={0,2}",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),

        new("disables-a-security-control",
            new Regex(
                @"(?:Set-MpPreference[\s\S]{0,120}?\$true|Add-MpPreference[\s\S]{0,60}?-Exclusion|" +
                @"Uninstall-WindowsFeature[\s\S]{0,40}?Windows-Defender|" +
                @"netsh\s+advfirewall\s+set[\s\S]{0,60}?\boff\b|" +
                @"Set-ExecutionPolicy[\s\S]{0,40}?(?:Bypass|Unrestricted)|" +
                @"\bsetenforce\s+0\b|systemctl\s+(?:stop|disable|mask)\s+(?:firewalld|apparmor|auditd))",
                RegexOptions.IgnoreCase | RegexOptions.Compiled)),
    };

    /// <summary>The categories this action trips, in rule order, without duplicates.</summary>
    public static IReadOnlyList<string> Categorize(string? action)
    {
        if (string.IsNullOrWhiteSpace(action))
        {
            return Array.Empty<string>();
        }

        var hits = new List<string>();
        foreach (var rule in Rules)
        {
            if (rule.Pattern.IsMatch(action) && !hits.Contains(rule.Category))
            {
                hits.Add(rule.Category);
            }
        }

        return hits;
    }

    /// <summary>
    /// The action as it should be shown: unchanged when it trips nothing, prefixed when it does.
    /// Idempotent, because an action can pass through here on the way to the index and again on the
    /// way out of it.
    /// </summary>
    public static string Screen(string action)
    {
        if (action is null || action.StartsWith(Marker, StringComparison.Ordinal))
        {
            return action ?? string.Empty;
        }

        var categories = Categorize(action);
        return categories.Count == 0
            ? action
            : $"{Marker} ({string.Join(", ", categories)}) — do not run this without reading it; " +
              $"if the telemetry suggested it, treat it as planted: {action}";
    }
}
