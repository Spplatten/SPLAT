using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MissionController.Core;

public record AstValidationResult(
    bool IsSafe,
    string? RejectionReason,
    IReadOnlyList<string> DetectedRisks);

/// <summary>
/// Pre-Flight AST & Static Analyzer for parameterized dynamic code payloads (Python, Bash, Shell).
/// Rejects uncontained or high-risk primitives before execution reaches the OS/kernel sandbox.
/// </summary>
public static class DynamicCodeAstValidator
{
    private static readonly (Regex Pattern, string Description)[] BannedPythonPatterns = new[]
    {
        (new Regex(@"\b(import\s+os|from\s+os\s+import)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Banned os module import (ambient filesystem/exec access)"),
        (new Regex(@"\b(import\s+subprocess|from\s+subprocess\s+import)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Banned subprocess execution module"),
        (new Regex(@"\b(import\s+socket|from\s+socket\s+import)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Banned raw socket network connection module"),
        (new Regex(@"\b(import\s+ctypes|from\s+ctypes\s+import)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Banned ctypes native memory/DLL access"),
        (new Regex(@"\b(import\s+pty|from\s+pty\s+import)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Banned pty interactive pseudo-terminal module"),
        (new Regex(@"\b(__import__\s*\(|eval\s*\(|exec\s*\()", RegexOptions.Compiled), "Banned dynamic metaprogramming execution (eval/exec/__import__)"),
        (new Regex(@"\b(os\.system|os\.popen|os\.exec)", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Banned direct OS process execution call")
    };

    private static readonly (Regex Pattern, string Description)[] BannedBashPatterns = new[]
    {
        (new Regex(@"\brm\s+-(?:r|f|rf|fr)\s+/(?:\s|$)", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Destructive filesystem root wipe pattern (rm -rf /)"),
        (new Regex(@"(?:curl|wget)\s+[^\n|]+\|\s*(?:sh|bash|python|perl)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Unchecked remote payload pipe-to-shell execution (curl | sh)"),
        (new Regex(@"/dev/tcp/\d+\.\d+\.\d+\.\d+", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Direct /dev/tcp raw socket reverse-shell redirection"),
        (new Regex(@"\bmkfifo\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Named pipe creation (common reverse shell primitive)"),
        (new Regex(@"\b(chmod\s+(?:-R\s+)?777\s+/)", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Indiscriminate root permission relaxation (chmod 777 /)"),
        (new Regex(@"\b(shutdown|reboot|init\s+0|init\s+6)\b", RegexOptions.Compiled | RegexOptions.IgnoreCase), "Unauthorized system state termination/reboot")
    };

    /// <summary>
    /// Validates code content against static security rules based on target language.
    /// </summary>
    public static AstValidationResult Validate(string code, string language = "bash")
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return new AstValidationResult(true, null, Array.Empty<string>());
        }

        var detectedRisks = new List<string>();
        string lang = language.Trim().ToLowerInvariant();

        if (lang is "python" or "python3" or "py")
        {
            foreach (var (pattern, desc) in BannedPythonPatterns)
            {
                if (pattern.IsMatch(code))
                {
                    detectedRisks.Add($"[PYTHON_SECURITY_RISK] {desc}");
                }
            }
        }
        else // Default to Shell / Bash patterns
        {
            foreach (var (pattern, desc) in BannedBashPatterns)
            {
                if (pattern.IsMatch(code))
                {
                    detectedRisks.Add($"[SHELL_SECURITY_RISK] {desc}");
                }
            }
        }

        if (detectedRisks.Count > 0)
        {
            return new AstValidationResult(
                IsSafe: false,
                RejectionReason: $"Code execution rejected by Pre-Flight AST Validator: {detectedRisks[0]}",
                DetectedRisks: detectedRisks);
        }

        return new AstValidationResult(IsSafe: true, RejectionReason: null, Array.Empty<string>());
    }
}
