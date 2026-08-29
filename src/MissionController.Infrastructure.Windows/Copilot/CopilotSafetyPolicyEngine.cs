using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Windows.Copilot;

/// <summary>
/// Evaluates Copilot tool execution requests against Fortune 500 CISO enterprise policies.
/// </summary>
public sealed class CopilotSafetyPolicyEngine : ICopilotSafetyPolicyEngine
{
    private static readonly Regex DangerousCmdRegex = new(
        @"(;|\||&&|\|\||`|\$\(|\$\{)\s*(format|del\s+\/[sfq]|rmdir\s+\/s|vssadmin|wbadmin|bcdedit|reg\s+delete|net\s+user\s+\w+\s+\/add)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public CopilotPolicyEvaluationResult EvaluatePolicy(CopilotToolCallContext context, CopilotSafetyPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(policy);

        var violations = new List<CopilotSecurityViolation>();

        // 1. Validate Executable
        string executableName = Path.GetFileName(context.ExecutableOrCommand).Trim().ToLowerInvariant();
        if (policy.AllowedExecutables != null && policy.AllowedExecutables.Count > 0)
        {
            bool isAllowed = false;
            foreach (var allowed in policy.AllowedExecutables)
            {
                string cleanAllowed = Path.GetFileName(allowed).Trim().ToLowerInvariant();
                if (string.Equals(executableName, cleanAllowed, StringComparison.OrdinalIgnoreCase))
                {
                    isAllowed = true;
                    break;
                }
            }

            if (!isAllowed)
            {
                violations.Add(new CopilotSecurityViolation(
                    ViolationType: "UNAUTHORIZED_EXECUTABLE",
                    Description: $"Executable '{context.ExecutableOrCommand}' is not in the enterprise CISO allow-list for Copilot.",
                    Severity: CopilotSecuritySeverity.Critical,
                    OffendingValue: context.ExecutableOrCommand,
                    TimestampUtc: DateTime.UtcNow));
            }
        }

        // 2. Validate Blocked Path Substrings (in executable, arguments, and working directory)
        string combinedCommandPayload = $"{context.ExecutableOrCommand} {context.Arguments} {context.WorkingDirectory ?? string.Empty}";
        string normalizedPayload = combinedCommandPayload.Replace('/', '\\');

        if (policy.BlockedPathSubstrings != null)
        {
            foreach (var blockedPath in policy.BlockedPathSubstrings)
            {
                string normBlocked = blockedPath.Replace('/', '\\');
                if (normalizedPayload.Contains(normBlocked, StringComparison.OrdinalIgnoreCase))
                {
                    violations.Add(new CopilotSecurityViolation(
                        ViolationType: "PROTECTED_SYSTEM_PATH_ACCESS",
                        Description: $"Access to protected system path substring '{blockedPath}' is prohibited by CISO policy.",
                        Severity: CopilotSecuritySeverity.Critical,
                        OffendingValue: blockedPath,
                        TimestampUtc: DateTime.UtcNow));
                }
            }
        }

        // 3. Validate Blocked Argument Patterns (e.g. credential dumps, memory scrapers, unauthorized scripts)
        if (policy.BlockedArgumentPatterns != null)
        {
            foreach (var pattern in policy.BlockedArgumentPatterns)
            {
                if (context.Arguments.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                {
                    violations.Add(new CopilotSecurityViolation(
                        ViolationType: "MALICIOUS_ARGUMENT_PATTERN",
                        Description: $"Dangerous argument pattern '{pattern}' detected in Copilot tool call.",
                        Severity: CopilotSecuritySeverity.High,
                        OffendingValue: pattern,
                        TimestampUtc: DateTime.UtcNow));
                }
            }
        }

        // 4. Heuristic check for destructive system commands (destructive format, bcdedit, vssadmin shadow wipe)
        if (DangerousCmdRegex.IsMatch(context.Arguments))
        {
            var match = DangerousCmdRegex.Match(context.Arguments);
            violations.Add(new CopilotSecurityViolation(
                ViolationType: "DESTRUCTIVE_COMMAND_INJECTION",
                Description: $"Destructive OS command sequence detected: '{match.Value.Trim()}'.",
                Severity: CopilotSecuritySeverity.Critical,
                OffendingValue: match.Value,
                TimestampUtc: DateTime.UtcNow));
        }

        // 5. Working Directory Validation (prevent running directly in Windows System directories)
        if (!string.IsNullOrWhiteSpace(context.WorkingDirectory))
        {
            string normWd = context.WorkingDirectory.Replace('/', '\\').TrimEnd('\\');
            string winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).Replace('/', '\\').TrimEnd('\\');
            string sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System).Replace('/', '\\').TrimEnd('\\');

            if (string.Equals(normWd, winDir, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(normWd, sysDir, StringComparison.OrdinalIgnoreCase))
            {
                violations.Add(new CopilotSecurityViolation(
                    ViolationType: "UNSAFE_WORKING_DIRECTORY",
                    Description: $"Running Copilot tools with working directory in system directory '{context.WorkingDirectory}' is prohibited.",
                    Severity: CopilotSecuritySeverity.High,
                    OffendingValue: context.WorkingDirectory,
                    TimestampUtc: DateTime.UtcNow));
            }
        }

        if (violations.Count > 0)
        {
            string denialReason = string.Join("; ", violations.ConvertAll(v => v.Description));
            return new CopilotPolicyEvaluationResult(
                IsPermitted: false,
                DenialReason: denialReason,
                Violations: violations);
        }

        return new CopilotPolicyEvaluationResult(
            IsPermitted: true,
            DenialReason: null,
            Violations: Array.Empty<CopilotSecurityViolation>());
    }
}
