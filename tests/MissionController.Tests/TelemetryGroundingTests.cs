using System.Linq;
using MissionController.Core;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Layer 9 attestation. These tests encode the property the whole layer exists for: a claim the
/// telemetry never contained must never reach an operator wearing the same styling as one it did.
/// </summary>
public class TelemetryGroundingTests
{
    private readonly JsonFindingsExtractor _extractor = new();

    private static ExecutiveDiagnosisResult Verdict(
        DiagnosticHealthStatus status,
        string headline,
        params string[] findings) =>
        new(status, headline, findings.ToList());

    [Fact]
    public void Attest_FabricatedSpecifics_MarkedUnsupported()
    {
        var verdict = Verdict(
            DiagnosticHealthStatus.Critical,
            "Brute force detected",
            "47 failed logon attempts originated from 10.0.0.5");

        // Telemetry describes a quiet host - the counts and the address were invented.
        var attested = TelemetryGrounder.Attest(verdict, "Event 4624 count: 2\nSource: 127.0.0.1");

        Assert.Equal(GroundingState.Unsupported, attested.Attestation!.Findings[0].State);
        Assert.Contains("UNSUPPORTED", attested.KeyFindings[0]);
        Assert.Contains("47", attested.Attestation.Findings[0].MissingClaims);
        Assert.Contains("10.0.0.5", attested.Attestation.Findings[0].MissingClaims);
    }

    [Fact]
    public void Attest_ClaimsPresentInTelemetry_MarkedGroundedAndLeftUnannotated()
    {
        var verdict = Verdict(
            DiagnosticHealthStatus.Warning,
            "Elevated failures",
            "12 failed logons recorded from 192.168.1.44");

        var attested = TelemetryGrounder.Attest(
            verdict,
            "EventID 4625 occurrences: 12\nWorkstation source 192.168.1.44 flagged");

        Assert.Equal(GroundingState.Grounded, attested.Attestation!.Findings[0].State);
        Assert.DoesNotContain("UNSUPPORTED", attested.KeyFindings[0]);
        Assert.DoesNotContain("UNVERIFIED", attested.StatusHeadline);
    }

    [Fact]
    public void Attest_AlertRestingEntirelyOnFabrication_FlagsHeadline()
    {
        var verdict = Verdict(
            DiagnosticHealthStatus.Critical,
            "🔴 CRITICAL ALERT — Immediate attention required",
            "Detected 9001 malicious connections to 203.0.113.9");

        var attested = TelemetryGrounder.Attest(verdict, "netstat: no active foreign connections");

        Assert.StartsWith("⚠ UNVERIFIED", attested.StatusHeadline);
        Assert.True(attested.Attestation!.HasUnsupportedFindings);
    }

    [Fact]
    public void Attest_AlertWithAtLeastOneGroundedFinding_DoesNotFlagHeadline()
    {
        var verdict = Verdict(
            DiagnosticHealthStatus.Critical,
            "🔴 CRITICAL ALERT",
            "Defender realtime protection disabled on host 10.20.30.40",
            "Speculative: 55 additional endpoints may be affected");

        var attested = TelemetryGrounder.Attest(verdict, "RealTimeProtectionEnabled : False\nHost 10.20.30.40");

        Assert.DoesNotContain("UNVERIFIED", attested.StatusHeadline);
        Assert.Equal(1, attested.Attestation!.GroundedCount);
        Assert.Equal(1, attested.Attestation.UnsupportedCount);
    }

    [Fact]
    public void Attest_NeverDropsFindingsOrMutatesSeverity()
    {
        var verdict = Verdict(
            DiagnosticHealthStatus.Critical,
            "Critical",
            "Fabricated claim about 8888 events",
            "Another invented detail at 198.51.100.7",
            "Vague prose with no specifics whatsoever");

        var attested = TelemetryGrounder.Attest(verdict, "clean telemetry");

        // Suppressing a real signal is the more dangerous failure; nothing is ever removed.
        Assert.Equal(3, attested.KeyFindings.Count);
        Assert.Equal(DiagnosticHealthStatus.Critical, attested.OverallStatus);
    }

    [Fact]
    public void Attest_ProseWithoutFalsifiableClaims_IsUnattributedNotUnsupported()
    {
        var verdict = Verdict(
            DiagnosticHealthStatus.Warning,
            "Concerns noted",
            "System behaviour appears somewhat concerning and warrants review");

        var attested = TelemetryGrounder.Attest(verdict, "some unrelated telemetry text");

        Assert.Equal(GroundingState.Unattributed, attested.Attestation!.Findings[0].State);
        Assert.False(attested.Attestation.HasUnsupportedFindings);
        Assert.DoesNotContain("UNSUPPORTED", attested.KeyFindings[0]);
    }

    [Fact]
    public void Attest_WithNoTelemetry_MarksUnverifiedRatherThanPassing()
    {
        var verdict = Verdict(DiagnosticHealthStatus.Warning, "Something", "Claim about 42 things");

        var attested = TelemetryGrounder.Attest(verdict, rawToolOutput: null);

        Assert.Equal(GroundingState.NoTelemetry, attested.Attestation!.Findings[0].State);
        Assert.Contains("UNVERIFIED", attested.KeyFindings[0]);
    }

    [Fact]
    public void Attest_PartiallyAnchoredClaim_IsDistinguishedFromBoth()
    {
        var verdict = Verdict(
            DiagnosticHealthStatus.Warning,
            "Mixed",
            "Host 10.0.0.9 reported 777 anomalies");

        var attested = TelemetryGrounder.Attest(verdict, "interface bound to 10.0.0.9");

        var finding = attested.Attestation!.Findings[0];
        Assert.Equal(GroundingState.PartiallyGrounded, finding.State);
        Assert.Contains("10.0.0.9", finding.AnchoredClaims);
        Assert.Contains("777", finding.MissingClaims);
        Assert.Contains("PARTIALLY VERIFIED", attested.KeyFindings[0]);
    }

    [Theory]
    [InlineData("Traffic to 203.0.113.5 observed", "203.0.113.5")]
    [InlineData(@"Persistence key HKLM\Software\Run altered", @"HKLM\Software\Run")]
    [InlineData("Process svchost.exe spawned unexpectedly", "svchost.exe")]
    [InlineData("Disk at 94% capacity", "94")]
    [InlineData("Saw 1024 events", "1024")]
    public void ExtractClaims_PullsFalsifiableSpecifics(string finding, string expectedClaim)
    {
        Assert.Contains(expectedClaim, TelemetryGrounder.ExtractClaims(finding));
    }

    [Theory]
    [InlineData("The situation looks bad")]
    [InlineData("Performance seems degraded overall")]
    public void ExtractClaims_IgnoresUnfalsifiableProse(string finding)
    {
        Assert.Empty(TelemetryGrounder.ExtractClaims(finding));
    }

    [Fact]
    public void ExtractFindings_JsonPath_AttestsAgainstTelemetryEndToEnd()
    {
        string aiOutput = """
            ```json
            {
              "status": "Critical",
              "headline": "Intrusion detected",
              "findings": ["Observed 6502 unauthorized attempts from 198.51.100.23"]
            }
            ```
            """;

        var result = _extractor.ExtractFindings(
            aiOutput,
            rawToolOutput: "Security log queried. No failed logon events in window.",
            templateName: "Sentinel-SecOps");

        Assert.NotNull(result.Attestation);
        Assert.True(result.Attestation!.HasUnsupportedFindings);
        Assert.StartsWith("⚠ UNVERIFIED", result.StatusHeadline);
    }

    [Fact]
    public void ExtractFindings_DeterministicSimulatedPath_IsExemptFromAttestation()
    {
        // This path reads the telemetry directly, so it is grounded by construction; re-checking it
        // would only manufacture doubt about findings that were never model-authored.
        var result = _extractor.ExtractFindings(
            "⚠ SIMULATED OUTPUT — no AI model is connected.",
            rawToolOutput: "RealTimeProtectionEnabled : True\nIsTamperProtected         : True",
            templateName: "Aegis-Endpoint");

        Assert.Null(result.Attestation);
        Assert.DoesNotContain(result.KeyFindings, f => f.Contains("UNSUPPORTED"));
    }
}
