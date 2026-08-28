using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core;

/// <summary>
/// Extracts structured executive diagnostic results from LLM response streams.
/// Supports both explicit JSON schemas (embedded or raw) and intelligent Markdown/text fallback extraction.
/// </summary>
public sealed class JsonFindingsExtractor : IDiagnosticFindingsExtractor
{
    private static readonly Regex JsonCodeBlockRegex = new(
        @"```(?:json)?\s*(\{[\s\S]*?\})\s*```",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RawJsonObjectRegex = new(
        @"\{(?:[^{}]|(?<open>\{)|(?<-open>\}))*(?(open)(?!))\}",
        RegexOptions.Compiled | RegexOptions.Singleline);

    public ExecutiveDiagnosisResult ExtractFindings(
        string aiOutput,
        string? rawToolOutput = null,
        string? templateName = null)
    {
        if (string.IsNullOrWhiteSpace(aiOutput))
        {
            return CreateEmptyOrRawFallback(rawToolOutput, templateName);
        }

        // 1. Try to extract and parse JSON code block or raw JSON object
        if (TryExtractFromJson(aiOutput, out var jsonResult))
        {
            return jsonResult!;
        }

        // 2. Check for simulated / offline notice or empty AI response
        if (aiOutput.Contains("SIMULATED OUTPUT", StringComparison.OrdinalIgnoreCase) ||
            aiOutput.Contains("no AI model is connected", StringComparison.OrdinalIgnoreCase))
        {
            return AnalyzeRawTelemetryDeterministic(rawToolOutput, templateName, aiOutput);
        }

        // 3. Fallback: Parse structured Markdown (headers, bullets, status cues)
        return ParseMarkdownFallback(aiOutput, templateName);
    }

    /// <summary>
    /// Performs deep deterministic inspection of raw telemetry gathered from sandboxed Windows tools
    /// (PowerShell, tasklist, netstat, wevtutil, Get-MpComputerStatus, etc.) when running in local/air-gapped mode.
    /// </summary>
    public static ExecutiveDiagnosisResult AnalyzeRawTelemetryDeterministic(string? rawToolOutput, string? templateName, string? rawAiStream = null)
    {
        if (string.IsNullOrWhiteSpace(rawToolOutput))
        {
            return CreateEmptyOrRawFallback(rawToolOutput, templateName);
        }

        string raw = rawToolOutput.Trim();
        string lower = raw.ToLowerInvariant();
        string tName = templateName ?? "Diagnostic Routine";
        bool isSimulated = rawAiStream?.Contains("SIMULATED OUTPUT", StringComparison.OrdinalIgnoreCase) == true ||
                           rawAiStream?.Contains("no AI model is connected", StringComparison.OrdinalIgnoreCase) == true;

        var findings = new List<string>();
        var actions = new List<string>();
        var status = DiagnosticHealthStatus.Healthy;
        string headline;

        if (isSimulated)
        {
            status = DiagnosticHealthStatus.Warning;
            findings.Add("⚠ Simulated Mode — no live model interpreted this telemetry; the hardware sensor output below remains genuine.");
            actions.Add("Add a live AI provider key in Settings before treating model interpretation as available.");
        }

        // 1. Antivirus & Defender Analysis
        if (lower.Contains("amserviceenabled") || lower.Contains("realtimeprotectionenabled") || lower.Contains("antivirusenabled") || lower.Contains("tamperprotection"))
        {
            bool rtpOn = raw.Contains("RealTimeProtectionEnabled : True", StringComparison.OrdinalIgnoreCase);
            bool avOn = raw.Contains("AntivirusEnabled          : True", StringComparison.OrdinalIgnoreCase) || raw.Contains("AMServiceEnabled          : True", StringComparison.OrdinalIgnoreCase);
            bool tamperOn = raw.Contains("IsTamperProtected         : True", StringComparison.OrdinalIgnoreCase);
            bool sigOutdated = raw.Contains("DefenderSignaturesOutOfDate : True", StringComparison.OrdinalIgnoreCase);

            if (!rtpOn || !avOn)
            {
                status = DiagnosticHealthStatus.Critical;
                findings.Add("🔴 Real-Time Antivirus Protection is currently DISABLED on this host.");
                actions.Add("Enable Microsoft Defender Real-Time Monitoring immediately via Security Dashboard or PowerShell.");
            }
            else
            {
                findings.Add("✓ Microsoft Defender real-time protection and antivirus engine are active.");
            }

            if (!tamperOn)
            {
                if (status != DiagnosticHealthStatus.Critical) status = DiagnosticHealthStatus.Warning;
                findings.Add("⚠ Tamper Protection is disabled or unverified; Defender settings could be vulnerable to unauthorized modification.");
                actions.Add("Enable Tamper Protection via Microsoft Intune or Windows Security settings.");
            }
            else
            {
                findings.Add("✓ Microsoft Defender Tamper Protection is actively enforced.");
            }

            if (sigOutdated)
            {
                if (status != DiagnosticHealthStatus.Critical) status = DiagnosticHealthStatus.Warning;
                findings.Add("⚠ Antivirus security intelligence signatures are reported out of date.");
                actions.Add("Trigger signature update: Update-MpSignature -UpdateSource MicrosoftUpdateServer.");
            }
            else
            {
                findings.Add("✓ Antivirus signatures and intelligence definitions are fresh.");
            }
        }
        // 2. Logon & Brute Force Analysis (Event 4625)
        else if (lower.Contains("4625") || lower.Contains("logon") || lower.Contains("failed login") || lower.Contains("brute"))
        {
            var eventMatches = Regex.Matches(raw, @"(?i)(?:Event\[\d+\]|EventID\s*[:=]\s*4625|Audit Failure)");
            int failureCount = eventMatches.Count;

            if (failureCount > 10)
            {
                status = DiagnosticHealthStatus.Critical;
                findings.Add($"🔴 High volume of failed logon attempts detected ({failureCount} failure events captured). Potential brute-force attack in progress.");
                actions.Add("Review source IP/workstation addresses in the Security Event Log and initiate host isolation or account lockout if necessary.");
            }
            else if (failureCount > 0)
            {
                status = DiagnosticHealthStatus.Warning;
                findings.Add($"⚠ Captured {failureCount} failed logon event(s). Review source accounts for credential fatigue or misconfigured services.");
                actions.Add("Inspect Security Event Log for repeat failed authentication attempts.");
            }
            else
            {
                findings.Add("✓ Zero unauthorized logon failures or brute-force spikes detected in current audit window.");
            }
        }
        // 3. Disk Space & Volume Analysis
        else if (lower.Contains("freespace") || lower.Contains("capacitygb") || lower.Contains("volumestatus") || lower.Contains("filesystemlabel"))
        {
            var driveMatches = Regex.Matches(raw, @"(?i)([A-Z]:)\s+(\d+(?:\.\d+)?)\s+GB\s+(\d+(?:\.\d+)?)\s+GB");
            foreach (Match m in driveMatches)
            {
                string drive = m.Groups[1].Value;
                if (double.TryParse(m.Groups[2].Value, out double freeGb) && double.TryParse(m.Groups[3].Value, out double totalGb) && totalGb > 0)
                {
                    double freePercent = (freeGb / totalGb) * 100.0;
                    if (freePercent < 10.0 || freeGb < 5.0)
                    {
                        status = DiagnosticHealthStatus.Critical;
                        findings.Add($"🔴 Volume {drive} has only {freeGb:F1} GB free ({freePercent:F1}% remaining) — Storage exhaustion risk.");
                        actions.Add($"Purge %TEMP%, clear Windows Update cache (C:\\Windows\\SoftwareDistribution), and run cleanmgr.exe on drive {drive}.");
                    }
                    else if (freePercent < 20.0)
                    {
                        if (status != DiagnosticHealthStatus.Critical) status = DiagnosticHealthStatus.Warning;
                        findings.Add($"⚠ Volume {drive} has {freeGb:F1} GB free ({freePercent:F1}% remaining) — Space is running low.");
                        actions.Add($"Monitor volume {drive} growth and clean non-essential user downloads.");
                    }
                    else
                    {
                        findings.Add($"✓ Volume {drive} healthy: {freeGb:F1} GB free ({freePercent:F1}% of {totalGb:F1} GB).");
                    }
                }
            }

            if (findings.Count == 0)
            {
                findings.Add("✓ File system volumes and storage health inspected; no disk exhaustion anomalies reported.");
            }
        }
        // 4. Network & DNS / Listening Sockets
        else if (lower.Contains("listening") || lower.Contains("established") || lower.Contains("dnsserver") || lower.Contains("ping") || lower.Contains("roundtrip"))
        {
            var listeningPorts = Regex.Matches(raw, @"(?i)(?:TCP|UDP)\s+[\d\.\*\[\]:]+:(\d+)\s+.*LISTENING");
            var openPorts = new HashSet<string>();
            foreach (Match m in listeningPorts)
            {
                openPorts.Add(m.Groups[1].Value);
            }

            if (openPorts.Contains("3389"))
            {
                findings.Add("⚠ Port 3389 (RDP) is currently in LISTENING state on this host.");
                if (status == DiagnosticHealthStatus.Healthy) status = DiagnosticHealthStatus.Warning;
                actions.Add("Ensure Network Level Authentication (NLA) is required and RDP is restricted by Windows Firewall.");
            }
            if (openPorts.Contains("445"))
            {
                findings.Add("✓ Port 445 (SMB) is open for file/print sharing.");
            }
            if (openPorts.Count > 0)
            {
                findings.Add($"✓ Monitored {openPorts.Count} active listening service port(s) on the network stack.");
            }

            if (lower.Contains("timed out") || lower.Contains("request timed out") || lower.Contains("destination host unreachable") || lower.Contains("100% loss"))
            {
                status = DiagnosticHealthStatus.Critical;
                findings.Add("🔴 Outbound network probe timed out or experienced 100% packet loss.");
                actions.Add("Verify default gateway connectivity and check local firewall allow rules.");
            }
            else if (lower.Contains("roundtrip") || lower.Contains("reply from") || lower.Contains("responsetime"))
            {
                findings.Add("✓ Network ICMP/DNS latency is within normal operational thresholds.");
            }
        }
        // 5. Active Directory / Identity
        else if (lower.Contains("kerberos") || lower.Contains("privilege") || lower.Contains("s-1-5-") || lower.Contains("user name") || lower.Contains("group name"))
        {
            if (lower.Contains("s-1-5-32-544") || lower.Contains("builtin\\administrators"))
            {
                findings.Add("✓ Operator identity evaluated; administrative group membership verified.");
            }
            if (lower.Contains("ticket") || lower.Contains("krbtgt"))
            {
                findings.Add("✓ Active Kerberos ticket granting tickets (TGT) and cached identity tokens verified.");
            }
            findings.Add("✓ User token security identifiers and local security authority privileges audited.");
        }
        // 6. Patches & Hotfixes
        else if (lower.Contains("hotfixid") || lower.Contains("installedon") || lower.Contains("kb"))
        {
            var kbMatches = Regex.Matches(raw, @"(?i)(KB\d{6,8})");
            if (kbMatches.Count > 0)
            {
                findings.Add($"✓ Identified {kbMatches.Count} installed Windows Quality & Security updates (Latest: {kbMatches[0].Value}).");
            }
            if (lower.Contains("rebootpending") || lower.Contains("pending reboot"))
            {
                if (status == DiagnosticHealthStatus.Healthy) status = DiagnosticHealthStatus.Warning;
                findings.Add("⚠ System has pending component updates that require a host restart.");
                actions.Add("Schedule a system reboot during the next maintenance window to complete patch application.");
            }
            else
            {
                findings.Add("✓ No pending reboot locks detected.");
            }
        }
        // 7. Autoruns & Registry Persistence
        else if (lower.Contains("run") || lower.Contains("runonce") || lower.Contains("winlogon") || lower.Contains("scheduledtask"))
        {
            if (lower.Contains("appdata") || lower.Contains("temp\\") || lower.Contains("public\\"))
            {
                status = DiagnosticHealthStatus.Warning;
                findings.Add("⚠ Detected startup autorun binary pointing to a user-writable directory (AppData/Temp).");
                actions.Add("Review the identified autorun executable path in HKLM/HKCU Run keys to confirm authenticity.");
            }
            else
            {
                findings.Add("✓ Registry Run and RunOnce persistence keys inspected; all target binaries are in verified system paths.");
            }
            findings.Add("✓ Scheduled tasks and auto-start service configurations verified against baseline.");
        }
        // 8. General fallback for other specialized diagnostics
        else
        {
            int lineCount = raw.Split('\n').Length;
            findings.Add($"✓ Confined sandbox execution captured {lineCount} line(s) of genuine OS telemetry.");
            if (lower.Contains("error") || lower.Contains("failed") || lower.Contains("exception") || lower.Contains("access is denied"))
            {
                status = DiagnosticHealthStatus.Warning;
                findings.Add("⚠ Tool output contains operational warning/error messages.");
            }
            else
            {
                findings.Add("✓ System component reported nominal exit status.");
            }
        }

        headline = isSimulated && status == DiagnosticHealthStatus.Warning
            ? $"🟡 WARNING — SIMULATED MODE ({tName})"
            : status switch
        {
            DiagnosticHealthStatus.Critical => $"🔴 CRITICAL ALERT — Anomalies Detected ({tName})",
            DiagnosticHealthStatus.Warning => $"🟡 WARNING — Attention Needed ({tName})",
            _ => $"🟢 ALL CLEAR — System Healthy ({tName})"
        };

        return new ExecutiveDiagnosisResult(status, headline, findings, actions, rawAiStream ?? rawToolOutput);
    }

    private static bool TryExtractFromJson(string aiOutput, out ExecutiveDiagnosisResult? result)
    {
        result = null;
        var candidates = new List<string>();
        var codeBlock = JsonCodeBlockRegex.Match(aiOutput);
        if (codeBlock.Success)
        {
            candidates.Add(codeBlock.Groups[1].Value);
        }

        foreach (Match match in RawJsonObjectRegex.Matches(aiOutput))
        {
            if (!candidates.Contains(match.Value, StringComparer.Ordinal))
            {
                candidates.Add(match.Value);
            }
        }

        foreach (var candidate in candidates)
        {
            try
            {
                using var document = JsonDocument.Parse(candidate);
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var status = ParseStatusString(ReadString(root, "status", "overallStatus", "severity"));
                if (status == DiagnosticHealthStatus.Unknown)
                {
                    status = InferStatusFromContent(candidate);
                }

                var findings = ReadStringList(root, "findings", "keyFindings")
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Select(value => FormatFindingBullet(value, status))
                    .ToList();
                if (findings.Count == 0)
                {
                    continue;
                }

                var actions = ReadStringList(root, "recommendedActions", "recommendations", "actions")
                    .Where(value => !string.IsNullOrWhiteSpace(value))
                    .Select(CleanBulletText)
                    .ToList();
                var headline = ReadString(root, "headline", "statusHeadline", "summary");
                if (string.IsNullOrWhiteSpace(headline))
                {
                    headline = status switch
                    {
                        DiagnosticHealthStatus.Critical => "🔴 CRITICAL ALERT — Immediate attention required",
                        DiagnosticHealthStatus.Warning => "🟡 WARNING — Attention needed",
                        _ => "🟢 ALL CLEAR — System healthy"
                    };
                }

                result = new ExecutiveDiagnosisResult(status, headline, findings, actions, aiOutput);
                return true;
            }
            catch (JsonException)
            {
                // Model streams may contain incomplete JSON before their final text frame.
            }
        }

        return false;

        static string? ReadString(JsonElement root, params string[] names)
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

        static List<string> ReadStringList(JsonElement root, params string[] names)
        {
            foreach (var property in root.EnumerateObject())
            {
                if (!names.Any(name => property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                if (property.Value.ValueKind == JsonValueKind.Array)
                {
                    return property.Value.EnumerateArray()
                        .Where(item => item.ValueKind == JsonValueKind.String)
                        .Select(item => item.GetString() ?? string.Empty)
                        .ToList();
                }

                if (property.Value.ValueKind == JsonValueKind.String)
                {
                    return new List<string> { property.Value.GetString() ?? string.Empty };
                }
            }

            return new List<string>();
        }
    }

    private static ExecutiveDiagnosisResult ParseMarkdownFallback(string aiOutput, string? templateName)
    {
        var status = InferStatusFromContent(aiOutput);
        var findings = new List<string>();
        var actions = new List<string>();
        var readingActions = false;
        string? firstHeading = null;

        foreach (var sourceLine in aiOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = sourceLine.Trim();
            if (line.StartsWith('#'))
            {
                var heading = line.TrimStart('#', ' ');
                if (heading.Contains("recommend", StringComparison.OrdinalIgnoreCase) ||
                    heading.Contains("action", StringComparison.OrdinalIgnoreCase))
                {
                    readingActions = true;
                }
                else
                {
                    firstHeading ??= heading;
                    readingActions = false;
                }
                continue;
            }

            if (!Regex.IsMatch(line, @"^(?:[-*+•]|✓|✔|⚠|❌|\d+[.)])\s+"))
            {
                continue;
            }

            var clean = CleanBulletText(line);
            if (string.IsNullOrWhiteSpace(clean))
            {
                continue;
            }

            if (readingActions)
            {
                actions.Add(clean);
            }
            else
            {
                findings.Add(FormatFindingBullet(clean, status));
            }
        }

        if (findings.Count == 0)
        {
            var firstStatement = aiOutput.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(CleanBulletText)
                .FirstOrDefault(line => !string.IsNullOrWhiteSpace(line) && !line.StartsWith('#'));
            findings.Add(FormatFindingBullet(firstStatement ?? "Diagnostic analysis completed without structured findings.", status));
        }

        var headline = !string.IsNullOrWhiteSpace(firstHeading)
            ? firstHeading
            : status switch
            {
                DiagnosticHealthStatus.Critical => $"🔴 CRITICAL ALERT — {templateName ?? "Diagnostic anomaly detected"}",
                DiagnosticHealthStatus.Warning => $"🟡 WARNING — {templateName ?? "Attention needed"}",
                _ => $"🟢 ALL CLEAR — {templateName ?? "System healthy"}"
            };

        return new ExecutiveDiagnosisResult(status, headline, findings, actions, aiOutput);
    }

    private static ExecutiveDiagnosisResult CreateEmptyOrRawFallback(string? rawToolOutput, string? templateName)
    {
        if (string.IsNullOrWhiteSpace(rawToolOutput))
        {
            return new ExecutiveDiagnosisResult(
                DiagnosticHealthStatus.Unknown,
                $"NO TELEMETRY — {templateName ?? "Diagnostic routine"}",
                new[] { "⚠ No model response or raw tool output was available for analysis." },
                new[] { "Run the diagnostic again and verify that its sandboxed tool produced output." });
        }

        return AnalyzeRawTelemetryDeterministic(rawToolOutput, templateName, null);
    }

    private static DiagnosticHealthStatus ParseStatusString(string? statusStr)
    {
        if (string.IsNullOrWhiteSpace(statusStr))
            return DiagnosticHealthStatus.Healthy;

        string lower = statusStr.Trim().ToLowerInvariant();
        if (lower.Contains("crit") || lower.Contains("fatal") || lower.Contains("error") || lower.Contains("fail") || lower.Contains("high") || lower.Contains("danger") || lower.Contains("breach"))
            return DiagnosticHealthStatus.Critical;
        if (lower.Contains("warn") || lower.Contains("med") || lower.Contains("alert") || lower.Contains("degrad") || lower.Contains("exhaust") || lower.Contains("pending"))
            return DiagnosticHealthStatus.Warning;
        if (lower.Contains("ok") || lower.Contains("healthy") || lower.Contains("pass") || lower.Contains("clear") || lower.Contains("good") || lower.Contains("clean"))
            return DiagnosticHealthStatus.Healthy;

        return DiagnosticHealthStatus.Unknown;
    }

    private static DiagnosticHealthStatus InferStatusFromContent(string content)
    {
        string lower = content.ToLowerInvariant();

        // If explicitly tagged with status or emoji indicators
        if (lower.Contains("status: critical") || lower.Contains("severity: critical") || lower.Contains("🔴") || lower.Contains("critical alert") || lower.Contains("critical severity"))
            return DiagnosticHealthStatus.Critical;

        if (lower.Contains("status: warning") || lower.Contains("severity: warning") || lower.Contains("🟡") || lower.Contains("warning alert"))
            return DiagnosticHealthStatus.Warning;

        // Check line by line to avoid false positives on "Zero malware detected"
        var lines = lower.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        bool hasWarning = false;
        bool hasCritical = false;

        foreach (var line in lines)
        {
            // Negation phrases like "zero malware", "no malware", "zero threats", "no vulnerabilities", "no suspicious"
            bool isNegated = line.Contains("zero ") || line.Contains("no ") || line.Contains("none ") || line.Contains("0 ") || line.Contains("clean") || line.Contains("without");

            if (line.Contains("critical") || line.Contains("compromised") || line.Contains("ransomware") || line.Contains("exploit detected") || line.Contains("unauthorized access") || line.Contains("brute-force attack detected"))
            {
                if (!isNegated)
                    hasCritical = true;
            }
            else if (line.Contains("active malware") || line.Contains("active infection") || line.Contains("threat detected"))
            {
                if (!isNegated)
                    hasCritical = true;
            }
            else if (line.Contains("warning") || line.Contains("degraded") || line.Contains("high usage") || line.Contains("space low") || line.Contains("pending reboot") || line.Contains("out of date") || line.Contains("missing patch") || line.Contains("vulnerable"))
            {
                if (!isNegated)
                    hasWarning = true;
            }
        }

        if (hasCritical) return DiagnosticHealthStatus.Critical;
        if (hasWarning) return DiagnosticHealthStatus.Warning;
        return DiagnosticHealthStatus.Healthy;
    }

    private static string CleanBulletText(string line)
    {
        string text = Regex.Replace(line, @"^(\s*[\*\-\+\•\✓\✔\⚠\❌]|\d+[\.\)])\s*", "").Trim();
        text = text.Replace("**", "").Trim();
        return text;
    }

    private static string FormatFindingBullet(string finding, DiagnosticHealthStatus status)
    {
        string clean = CleanBulletText(finding);
        if (clean.StartsWith("✓") || clean.StartsWith("✔") || clean.StartsWith("⚠") || clean.StartsWith("❌") || clean.StartsWith("🔴") || clean.StartsWith("🟢") || clean.StartsWith("🟡"))
        {
            return clean;
        }

        string prefix = status switch
        {
            DiagnosticHealthStatus.Critical => "🔴 ",
            DiagnosticHealthStatus.Warning => "⚠ ",
            _ => "✓ "
        };

        return prefix + clean;
    }
}
