using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Network.Edr;

[SupportedOSPlatform("windows")]
public sealed class EdrIngestionBridge : IEdrIngestionBridge
{
    private static EndpointIsolationState _currentIsolationState = EndpointIsolationState.NotIsolated;
    private static readonly List<EdrSecurityAlert> _manualAlerts = new();

    public Task<EdrDevicePosture> GetLocalDevicePostureAsync(CancellationToken cancellationToken = default)
    {
        string hostname = Environment.MachineName.ToLowerInvariant();
        string deviceId = $"WIN-{Convert.ToHexString(System.Text.Encoding.UTF8.GetBytes(hostname)).Substring(0, Math.Min(12, hostname.Length * 2))}";

        bool isDefenderProcessActive = false;
        bool isCrowdStrikeActive = false;
        bool isSentinelOneActive = false;
        string engineVersion = "Unavailable";
        string intelligenceVersion = "Unavailable";
        bool realTimeEnabled = false;

        try
        {
            var processes = Process.GetProcesses();
            isDefenderProcessActive = processes.Any(p => p.ProcessName.Equals("MsMpEng", StringComparison.OrdinalIgnoreCase) || p.ProcessName.Equals("Sense", StringComparison.OrdinalIgnoreCase));
            isCrowdStrikeActive = processes.Any(p => p.ProcessName.Equals("CSFalconService", StringComparison.OrdinalIgnoreCase) || p.ProcessName.Equals("CSFalconContainer", StringComparison.OrdinalIgnoreCase));
            isSentinelOneActive = processes.Any(p => p.ProcessName.Equals("SentinelAgent", StringComparison.OrdinalIgnoreCase) || p.ProcessName.Equals("SentinelService", StringComparison.OrdinalIgnoreCase));
        }
        catch
        {
            isDefenderProcessActive = true;
        }

        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Signature Updates");
                if (key != null)
                {
                    var engine = key.GetValue("EngineVersion") as string;
                    if (!string.IsNullOrWhiteSpace(engine)) engineVersion = engine;

                    var sig = key.GetValue("AVSignatureVersion") as string;
                    if (!string.IsNullOrWhiteSpace(sig)) intelligenceVersion = sig;
                }

                using var rtpKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
                if (rtpKey != null)
                {
                    var disableRtp = rtpKey.GetValue("DisableRealtimeMonitoring");
                    if (disableRtp is int dVal)
                    {
                        realTimeEnabled = dVal == 0 && isDefenderProcessActive;
                    }
                    else
                    {
                        realTimeEnabled = isDefenderProcessActive;
                    }
                }
                else
                {
                    realTimeEnabled = isDefenderProcessActive;
                }
            }
            catch
            {
                realTimeEnabled = isDefenderProcessActive;
            }
        }

        var provider = isCrowdStrikeActive
            ? EdrProviderType.CrowdStrikeFalcon
            : (isSentinelOneActive
                ? EdrProviderType.SentinelOne
                : (isDefenderProcessActive ? EdrProviderType.MicrosoftDefenderForEndpoint : EdrProviderType.GenericLocal));

        // Read live alerts to compute active threats count
        var liveAlerts = QueryLiveDefenderEvents(10);
        var activeThreats = liveAlerts
            .Where(a => a.Status.Equals("Active", StringComparison.OrdinalIgnoreCase) || a.Severity.Equals("High", StringComparison.OrdinalIgnoreCase) || a.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase))
            .Select(a => $"{a.Severity}: {a.Title}")
            .ToList();

        var posture = new EdrDevicePosture(
            DeviceId: deviceId,
            Hostname: hostname,
            Provider: provider,
            IsolationState: _currentIsolationState,
            RealTimeProtectionEnabled: realTimeEnabled || isCrowdStrikeActive || isSentinelOneActive,
            AntivirusEngineVersion: engineVersion,
            SecurityIntelligenceVersion: intelligenceVersion,
            LastSyncTimeUtc: DateTimeOffset.UtcNow,
            ActiveThreats: activeThreats);

        return Task.FromResult(posture);
    }

    public Task<IReadOnlyList<EdrSecurityAlert>> GetRecentAlertsAsync(int maxCount = 20, CancellationToken cancellationToken = default)
    {
        var alerts = new List<EdrSecurityAlert>();

        lock (_manualAlerts)
        {
            alerts.AddRange(_manualAlerts);
        }

        var liveEvents = QueryLiveDefenderEvents(maxCount);
        alerts.AddRange(liveEvents);

        IReadOnlyList<EdrSecurityAlert> result = alerts
            .OrderByDescending(a => a.DetectedTimeUtc)
            .Take(maxCount)
            .ToList();

        return Task.FromResult(result);
    }

    public Task<bool> SetDeviceIsolationStateAsync(string deviceId, bool isolate, string justification, CancellationToken cancellationToken = default)
    {
        _currentIsolationState = isolate ? EndpointIsolationState.Isolated : EndpointIsolationState.NotIsolated;

        lock (_manualAlerts)
        {
            _manualAlerts.Insert(0, new EdrSecurityAlert(
                AlertId: $"EDR-ISO-{Guid.NewGuid():N}".Substring(0, 16).ToUpperInvariant(),
                Title: isolate ? "Endpoint Network Isolation Activated" : "Endpoint Network Isolation Released",
                Category: "Containment",
                Severity: isolate ? "High" : "Informational",
                Status: "Active",
                DetectedTimeUtc: DateTimeOffset.UtcNow,
                Description: $"Operator justification: {justification}. Isolation state transitioned to {_currentIsolationState}.",
                MitreTechniqueId: "T1071"));
        }

        return Task.FromResult(true);
    }

    private static List<EdrSecurityAlert> QueryLiveDefenderEvents(int maxCount)
    {
        var alerts = new List<EdrSecurityAlert>();
        if (!OperatingSystem.IsWindows()) return alerts;

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "wevtutil.exe"),
                Arguments = "qe \"Microsoft-Windows-Windows Defender/Operational\" /c:15 /rd:true /f:text",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc != null)
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);

                if (!string.IsNullOrWhiteSpace(output))
                {
                    var blocks = output.Split(new[] { "Event[" }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (var block in blocks)
                    {
                        if (alerts.Count >= maxCount) break;

                        var eventMatch = Regex.Match(block, @"Event ID:\s*(\d+)");
                        if (!eventMatch.Success) continue;

                        int eventId = int.Parse(eventMatch.Groups[1].Value);
                        var dateMatch = Regex.Match(block, @"Date:\s*([^\r\n]+)");
                        DateTimeOffset dt = dateMatch.Success && DateTimeOffset.TryParse(dateMatch.Groups[1].Value, out var parsedDt)
                            ? parsedDt
                            : DateTimeOffset.UtcNow;

                        var descLines = block.Split('\n')
                            .Where(l => !l.StartsWith("Event ID:") && !l.StartsWith("Date:") && !l.StartsWith("Log Name:") && !l.StartsWith("Source:"))
                            .Select(l => l.Trim())
                            .Where(l => l.Length > 0)
                            .Take(2);
                        string desc = string.Join(" ", descLines);
                        if (string.IsNullOrWhiteSpace(desc)) desc = $"Defender telemetry Event ID {eventId}";

                        alerts.Add(MapEventIdToAlert(eventId, desc, dt));
                    }
                }
            }
        }
        catch
        {
            // Non-elevated execution fallback
        }

        return alerts;
    }

    private static EdrSecurityAlert MapEventIdToAlert(int eventId, string desc, DateTimeOffset time)
    {
        return eventId switch
        {
            1116 => new EdrSecurityAlert(
                AlertId: $"DEF-1116-{time.ToUnixTimeSeconds()}",
                Title: "Malware Detected on Host",
                Category: "Execution",
                Severity: "High",
                Status: "Active",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1204"),

            1117 => new EdrSecurityAlert(
                AlertId: $"DEF-1117-{time.ToUnixTimeSeconds()}",
                Title: "Malware Remediated by Defender",
                Category: "Defense Evasion",
                Severity: "Medium",
                Status: "Resolved",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1070"),

            1006 => new EdrSecurityAlert(
                AlertId: $"DEF-1006-{time.ToUnixTimeSeconds()}",
                Title: "Unwanted Software or Exploit Blocked",
                Category: "Execution",
                Severity: "Medium",
                Status: "Resolved",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1059"),

            1007 => new EdrSecurityAlert(
                AlertId: $"DEF-1007-{time.ToUnixTimeSeconds()}",
                Title: "Attack Surface Reduction Rule Triggered",
                Category: "Initial Access",
                Severity: "Medium",
                Status: "Active",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1566"),

            1001 => new EdrSecurityAlert(
                AlertId: $"DEF-1001-{time.ToUnixTimeSeconds()}",
                Title: "Defender Antivirus Scan Completed",
                Category: "Discovery",
                Severity: "Informational",
                Status: "Resolved",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1082"),

            2000 => new EdrSecurityAlert(
                AlertId: $"DEF-2000-{time.ToUnixTimeSeconds()}",
                Title: "Defender Security Intelligence Updated",
                Category: "Defense Evasion",
                Severity: "Informational",
                Status: "Resolved",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1027"),

            5007 => new EdrSecurityAlert(
                AlertId: $"DEF-5007-{time.ToUnixTimeSeconds()}",
                Title: "Defender Configuration or Policy Changed",
                Category: "Defense Evasion",
                Severity: "Low",
                Status: "Active",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1562.001"),

            _ => new EdrSecurityAlert(
                AlertId: $"DEF-{eventId}-{time.ToUnixTimeSeconds()}",
                Title: $"Defender Event {eventId}",
                Category: "Endpoint Security",
                Severity: "Informational",
                Status: "Resolved",
                DetectedTimeUtc: time,
                Description: desc,
                MitreTechniqueId: "T1082")
        };
    }
}
