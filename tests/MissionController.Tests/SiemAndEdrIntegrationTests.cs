using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Network.Edr;
using MissionController.Infrastructure.Network.Siem;
using Xunit;

namespace MissionController.Tests;

public class SiemAndEdrIntegrationTests
{
    [Fact]
    public void SiemForwarder_FormatsRfc5424Syslog_WithStructuredData()
    {
        var structuredData = new Dictionary<string, IReadOnlyDictionary<string, string>>
        {
            ["mission@32473"] = new Dictionary<string, string>
            {
                ["id"] = "11111111-2222-3333-4444-555555555555",
                ["template"] = "net-dns-audit",
                ["operator"] = "admin-sysops"
            }
        };

        var msg = new SyslogMessage(
            Facility: 1, // User
            Severity: 6, // Informational
            Timestamp: DateTimeOffset.Parse("2026-08-27T12:00:00.000000+00:00"),
            Hostname: "campus-dc01",
            AppName: "MissionController",
            ProcessId: "4088",
            MessageId: "EXEC_TOOL",
            Message: "DNS cache sweep completed successfully.",
            StructuredData: structuredData);

        string formatted = SiemForwarder.FormatRfc5424(msg);

        // PRI = (1 * 8) + 6 = 14
        Assert.StartsWith("<14>1 ", formatted);
        Assert.Contains("campus-dc01 MissionController 4088 EXEC_TOOL", formatted);
        Assert.Contains("[mission@32473", formatted);
        Assert.Contains("id=\"11111111-2222-3333-4444-555555555555\"", formatted);
        Assert.Contains("template=\"net-dns-audit\"", formatted);
        Assert.Contains("DNS cache sweep completed successfully.", formatted);
    }

    [Fact]
    public void SiemForwarder_FormatsCef_CompliesWithArcSightSpec()
    {
        var extensions = new Dictionary<string, string>
        {
            ["cs1"] = "win-bitlocker-audit",
            ["cs1Label"] = "TemplateId",
            ["suser"] = "Tier2Tech",
            ["msg"] = "Volume encryption verified"
        };

        var cefEvent = new CefEvent(
            DeviceVendor: "EnterpriseIT",
            DeviceProduct: "MissionController",
            DeviceVersion: "2.0",
            DeviceEventClassId: "BITLOCKER_VERIFY",
            Name: "BitLocker TPM Verification",
            Severity: 4,
            ExtensionFields: extensions);

        string formatted = SiemForwarder.FormatCef(cefEvent);

        Assert.StartsWith("CEF:0|EnterpriseIT|MissionController|2.0|BITLOCKER_VERIFY|BitLocker TPM Verification|4|", formatted);
        Assert.Contains("cs1=win-bitlocker-audit", formatted);
        Assert.Contains("suser=Tier2Tech", formatted);
        Assert.Contains("msg=Volume encryption verified", formatted);
    }

    [Fact]
    public void SiemForwarder_CalculatesMicrosoftSentinelHmacSignature()
    {
        string workspaceId = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d";
        string mockSharedKey = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("SuperSecretSentinelSharedKey123456"));
        string dateString = "Thu, 27 Aug 2026 12:00:00 GMT";
        int contentLength = 256;

        string signatureHeader = SiemForwarder.BuildSentinelAuthSignature(workspaceId, mockSharedKey, contentLength, dateString);

        Assert.StartsWith($"SharedKey {workspaceId}:", signatureHeader);
        Assert.True(signatureHeader.Length > 40);
    }

    [Fact]
    public async Task EdrIngestionBridge_ReturnsValidDevicePosture()
    {
        var bridge = new EdrIngestionBridge();
        var posture = await bridge.GetLocalDevicePostureAsync();

        Assert.NotNull(posture);
        Assert.NotEmpty(posture.DeviceId);
        Assert.NotEmpty(posture.Hostname);
        Assert.NotEmpty(posture.AntivirusEngineVersion);
        Assert.Equal(EndpointIsolationState.NotIsolated, posture.IsolationState);

        var alerts = await bridge.GetRecentAlertsAsync(5);
        Assert.NotNull(alerts);
        Assert.NotEmpty(alerts);
    }

    [Fact]
    public async Task EdrIngestionBridge_TogglesIsolationState_RecordsAuditAlert()
    {
        var bridge = new EdrIngestionBridge();

        bool isolated = await bridge.SetDeviceIsolationStateAsync("TEST-DEV-01", true, "Potential C2 Beaconing Detected");
        Assert.True(isolated);

        var posture = await bridge.GetLocalDevicePostureAsync();
        Assert.Equal(EndpointIsolationState.Isolated, posture.IsolationState);

        var alerts = await bridge.GetRecentAlertsAsync(5);
        Assert.Contains(alerts, a => a.Title.Contains("Isolation Activated", StringComparison.OrdinalIgnoreCase));

        // Revert back
        await bridge.SetDeviceIsolationStateAsync("TEST-DEV-01", false, "Investigation Concluded - False Positive");
        var postureReverted = await bridge.GetLocalDevicePostureAsync();
        Assert.Equal(EndpointIsolationState.NotIsolated, postureReverted.IsolationState);
    }
}
