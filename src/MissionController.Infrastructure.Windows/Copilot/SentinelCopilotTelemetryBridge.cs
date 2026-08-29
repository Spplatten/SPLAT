using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Windows.Copilot;

/// <summary>
/// Bridges Copilot safety events, execution telemetry, and kernel violation alerts directly
/// into Microsoft Sentinel and SIEM infrastructure.
/// </summary>
public sealed class SentinelCopilotTelemetryBridge
{
    private readonly ISiemForwarder _siemForwarder;

    public SentinelCopilotTelemetryBridge(ISiemForwarder siemForwarder)
    {
        _siemForwarder = siemForwarder ?? throw new ArgumentNullException(nameof(siemForwarder));
    }

    public async Task<bool> StreamCopilotEventAsync(
        CopilotToolCallContext context,
        CopilotExecutionResult result,
        SiemConfiguration sentinelConfig,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(sentinelConfig);

        try
        {
            // Build CEF event for SIEM / Sentinel
            string eventClassId = result.PolicyBlocked
                ? "COPILOT_POLICY_BLOCKED"
                : (result.IsSuccess ? "COPILOT_TOOL_SUCCESS" : "COPILOT_TOOL_FAILED");

            int severity = result.PolicyBlocked ? 9 : (result.IsSuccess ? 3 : 6);
            if (result.Violations.Count > 0)
            {
                severity = 10; // Maximum security severity for active kernel/policy violations
            }

            var extensions = new Dictionary<string, string>
            {
                ["cs1"] = context.AgentId,
                ["cs1Label"] = "CopilotAgentId",
                ["cs2"] = context.ToolName,
                ["cs2Label"] = "InvokedTool",
                ["cs3"] = context.ExecutableOrCommand,
                ["cs3Label"] = "TargetExecutable",
                ["cs4"] = context.SessionId.ToString("D"),
                ["cs4Label"] = "CopilotSessionId",
                ["suser"] = context.OperatorIdentity,
                ["outcome"] = result.PolicyBlocked ? "Blocked" : (result.IsSuccess ? "Success" : "Failure"),
                ["externalId"] = result.MerkleEntryHash ?? "UNHASHED",
                ["msg"] = result.PolicyBlocked
                    ? $"[SPLAT SECURITY BLOCK] Copilot agent '{context.AgentId}' attempted blocked action: {result.StandardError}"
                    : $"Copilot tool '{context.ToolName}' executed. ExitCode={result.ExitCode} Violations={result.Violations.Count}"
            };

            if (result.ResourceMetrics != null)
            {
                extensions["cn1"] = result.ResourceMetrics.TotalCpuKernelTimeMs.ToString();
                extensions["cn1Label"] = "KernelTimeMs";
                extensions["cn2"] = result.ResourceMetrics.TotalCpuUserTimeMs.ToString();
                extensions["cn2Label"] = "UserTimeMs";
                extensions["cn3"] = result.ResourceMetrics.PeakMemoryBytes.ToString();
                extensions["cn3Label"] = "PeakMemoryBytes";
            }

            if (result.Violations.Count > 0)
            {
                var vList = new List<string>();
                foreach (var v in result.Violations)
                {
                    vList.Add($"[{v.Severity}] {v.ViolationType}: {v.Description} (Offending='{v.OffendingValue}')");
                }
                extensions["cs5"] = string.Join(" | ", vList);
                extensions["cs5Label"] = "ViolationsList";
            }

            var cefEvent = new CefEvent(
                DeviceVendor: "PlattenIndustries",
                DeviceProduct: "SPLAT_Copilot_Safety_Substrate",
                DeviceVersion: "1.0",
                DeviceEventClassId: eventClassId,
                Name: $"Microsoft Copilot Action: {context.ToolName}",
                Severity: severity,
                ExtensionFields: extensions);

            // Also format audit entry for native Sentinel REST ingestion
            var auditEntry = new AuditLogEntry(
                Id: 0,
                TimestampUtc: result.TimestampUtc,
                MissionId: context.SessionId,
                TemplateId: $"copilot-tool-{context.ToolName}",
                Action: eventClassId,
                Details: JsonSerializer.Serialize(extensions),
                OperatorIdentity: context.OperatorIdentity,
                EntryHash: result.MerkleEntryHash ?? Guid.NewGuid().ToString("N"),
                PreviousHash: "0000000000000000000000000000000000000000000000000000000000000000");

            if (sentinelConfig.Protocol == SiemProtocol.MicrosoftSentinel)
            {
                await _siemForwarder.ForwardAuditEntryAsync(auditEntry, sentinelConfig, cancellationToken);
            }
            else
            {
                await _siemForwarder.ForwardCefEventAsync(cefEvent, sentinelConfig, cancellationToken);
            }

            return true;
        }
        catch
        {
            // Do not fault the caller if SIEM telemetry is momentarily unreachable, but log/fail as appropriate
            return false;
        }
    }
}
