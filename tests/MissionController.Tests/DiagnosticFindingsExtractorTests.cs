using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

public class DiagnosticFindingsExtractorTests
{
    private readonly JsonFindingsExtractor _extractor = new();

    [Fact]
    public void ExtractFindings_WithValidJsonBlock_ParsesCorrectly()
    {
        string aiOutput = """
            Here is the diagnostic assessment:
            ```json
            {
              "status": "Healthy",
              "headline": "🟢 Atlas-Net Network Baseline Verified",
              "findings": [
                "Ping round-trip latency to gateway is 12ms (well under 25ms threshold)",
                "Zero packet loss detected across all sample frames",
                "Listening socket analysis revealed no unauthorized open ports"
              ],
              "recommendedActions": [
                "No immediate action required - schedule next routine probe in 24 hours"
              ]
            }
            ```
            Hope this helps!
            """;

        var result = _extractor.ExtractFindings(aiOutput, rawToolOutput: "ping statistics: 0% loss", templateName: "Atlas-Net");

        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.Equal("🟢 Atlas-Net Network Baseline Verified", result.StatusHeadline);
        Assert.Equal(3, result.KeyFindings.Count);
        Assert.Contains(result.KeyFindings, f => f.Contains("12ms"));
        Assert.Single(result.RecommendedActions!);
        Assert.Contains("schedule next routine", result.RecommendedActions![0]);
    }

    [Fact]
    public void ExtractFindings_WithCriticalJson_SetsCriticalStatusAndBadges()
    {
        string aiOutput = """
            ```json
            {
              "status": "Critical",
              "headline": "🔴 Brute-Force Logon Spike Detected",
              "findings": [
                "Event 4625 failed logon count exceeded 1,200 events in past 15 minutes",
                "Source IP 192.168.1.105 targeting Administrator account repeatedly",
                "Compromised service account credentials suspected"
              ],
              "recommendedActions": [
                "Temporarily isolate endpoint from local subnet",
                "Rotate Administrator password and revoke Kerberos TGT"
              ]
            }
            ```
            """;

        var result = _extractor.ExtractFindings(aiOutput);

        Assert.Equal(DiagnosticHealthStatus.Critical, result.OverallStatus);
        Assert.Contains("Brute-Force", result.StatusHeadline);
        Assert.Equal(3, result.KeyFindings.Count);
        Assert.All(result.KeyFindings, f => Assert.StartsWith("🔴 ", f));
        Assert.Equal(2, result.RecommendedActions!.Count);
    }

    [Fact]
    public void ExtractFindings_WithRawJsonObject_ExtractsCorrectly()
    {
        string aiOutput = """
            {
              "status": "Warning",
              "headline": "🟡 High Storage Capacity Warning on Drive C:",
              "findings": [
                "Drive C: has only 8% free space remaining (12 GB free of 150 GB)",
                "Temp directory holds 18 GB of unpurged installer caches"
              ],
              "recommendedActions": [
                "Execute Disk Cleanup routine to purge temporary files"
              ]
            }
            """;

        var result = _extractor.ExtractFindings(aiOutput);

        Assert.Equal(DiagnosticHealthStatus.Warning, result.OverallStatus);
        Assert.Contains("Drive C:", result.StatusHeadline);
        Assert.Equal(2, result.KeyFindings.Count);
        Assert.All(result.KeyFindings, f => Assert.StartsWith("⚠ ", f));
    }

    [Fact]
    public void ExtractFindings_WithMarkdownBulletsFallback_ExtractsBulletsAndInfersStatus()
    {
        string aiOutput = """
            ### Executive Security Assessment
            Based on the Windows Defender scan results:
            - Microsoft Defender real-time protection shield is ACTIVE.
            - Virus definition version 1.403.291.0 is up-to-date (installed 2 hours ago).
            - Zero malware threats or active infections detected in the memory sweep.

            ### Recommendations:
            - Maintain automatic cloud-delivered signature updates.
            """;

        var result = _extractor.ExtractFindings(aiOutput, templateName: "Aegis-Endpoint");

        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.True(result.KeyFindings.Count >= 3);
        Assert.Contains(result.KeyFindings, f => f.Contains("real-time protection shield is ACTIVE"));
        Assert.Single(result.RecommendedActions!);
    }

    [Fact]
    public void ExtractFindings_WithSimulatedNotice_SurfacesHonestNoticeWithoutMockFabrication()
    {
        string aiOutput = """
            ⚠ SIMULATED OUTPUT — no AI model is connected.
            No Anthropic API key is configured, so no real analysis was performed.
            Add your API key in Settings to enable live diagnostics.
            """;

        string rawTool = "Node: WORKSTATION-01\nPing: 14ms\nLoss: 0%";

        var result = _extractor.ExtractFindings(aiOutput, rawToolOutput: rawTool, templateName: "Atlas-Net");

        Assert.Equal(DiagnosticHealthStatus.Warning, result.OverallStatus);
        Assert.Contains("SIMULATED", result.StatusHeadline);
        Assert.Contains(result.KeyFindings, f => f.Contains("Simulated Mode"));
        Assert.Contains(result.KeyFindings, f => f.Contains("hardware sensor output") || f.Contains("raw tool output"));
        Assert.Single(result.RecommendedActions!);
        Assert.Contains("Settings", result.RecommendedActions![0]);
    }

    [Fact]
    public void ExtractFindings_WithEmptyOutput_FallsBackGracefully()
    {
        var result = _extractor.ExtractFindings(string.Empty, rawToolOutput: "Output lines 1\nOutput lines 2", templateName: "Titan-SysOps");

        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.Contains("ALL CLEAR", result.StatusHeadline);
        Assert.NotEmpty(result.KeyFindings);
    }
}
