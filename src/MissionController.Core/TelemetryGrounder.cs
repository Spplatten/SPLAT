using System;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;
using System.Text.RegularExpressions;
using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Core;

/// <summary>
/// Layer 9 - Evidence Attestation.
///
/// Every layer beneath this one protects the INTEGRITY of a finding: the sandbox bounds how it was
/// gathered, the DLP scrubber bounds what left the host, the SHA-256 chain and Merkle root prove the
/// record was not altered after the fact. None of them establish that the finding was ever TRUE. A
/// model that invents "47 failed logons from 10.0.0.5" produces a claim that is jailed, scrubbed,
/// chained, rooted and archived with perfect fidelity - a cryptographically notarized fabrication.
///
/// This class closes that gap deterministically, without asking a model to audit a model. It pulls
/// the checkable assertions out of each finding (addresses, counts, identifiers, paths, service and
/// binary names) and requires each one to actually appear in the sensor text the sandboxed tool
/// returned. A finding whose specifics are absent from the telemetry cannot be evidence-backed,
/// whatever confidence the prose carries.
///
/// Deliberately NOT done here:
///  - Findings are never silently dropped. Suppressing a real signal because the grounder could not
///    anchor its phrasing is the more dangerous failure for a security product, so unsupported
///    findings are marked and surfaced rather than removed.
///  - Severity is never silently reduced. A Critical verdict resting entirely on unsupported claims
///    is flagged in the headline so an operator sees the distinction; OverallStatus itself is left
///    alone so no genuine alert can be quietly downgraded by a parsing miss.
/// </summary>
public static class TelemetryGrounder
{
    /// <summary>
    /// Claim shapes worth checking. Prose adjectives ("elevated", "concerning") are unfalsifiable
    /// against raw text and are ignored on purpose - flagging them would bury the real signal, which
    /// is a SPECIFIC value the telemetry never contained.
    ///
    /// Bare single digits are excluded: they collide with ordinals, dates and severity words often
    /// enough that treating them as claims produces noise instead of detections.
    /// </summary>
    private static readonly Regex ClaimTokenRegex = new(
        string.Join("|",
            @"(?<ip>\b\d{1,3}(?:\.\d{1,3}){3}\b)",
            @"(?<path>\b[A-Za-z]:\\[^\s"",;]+)",
            @"(?<reg>\bHK(?:EY_)?[A-Z_]*\\[^\s"",;]+)",
            @"(?<binary>\b[\w.-]+\.(?:exe|dll|sys|ps1|bat|cmd)\b)",
            @"(?<quoted>""[^""\r\n]{2,64}"")",
            @"(?<percent>\b\d{1,3}(?:\.\d+)?\s*%)",
            @"(?<number>\b\d{2,}\b)"),
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// MITRE ATT&amp;CK technique and sub-technique ids (T1547, T1547.001) and CVE ids: the two
    /// catalogues a finding legitimately cites without the telemetry containing them.
    /// </summary>
    private static readonly Regex KnowledgeIdentifierRegex = new(
        @"\bT\d{4}(?:\.\d{3})?\b|\bCVE-\d{4}-\d{4,}\b",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Presentation prefixes this codebase adds to bullets. Stripped before analysis so a marker
    /// glyph is never mistaken for part of a claim.
    /// </summary>
    private static readonly char[] BulletNoise = { '•', '-', '*', ' ', '\t', '⚠', '✓' };

    /// <summary>
    /// Attests a model-derived verdict against the telemetry that produced it.
    ///
    /// When no raw telemetry is available the result is passed through with an explicit
    /// <see cref="GroundingState.NoTelemetry"/> attestation rather than a silent pass - an
    /// ungrounded verdict must never be indistinguishable from a verified one.
    /// </summary>
    public static ExecutiveDiagnosisResult Attest(ExecutiveDiagnosisResult verdict, string? rawToolOutput)
    {
        if (verdict.KeyFindings is null || verdict.KeyFindings.Count == 0)
        {
            return verdict with { Attestation = GroundingAttestation.Empty };
        }

        if (string.IsNullOrWhiteSpace(rawToolOutput))
        {
            var unbacked = verdict.KeyFindings
                .Select(finding => new FindingAttestation(
                    finding, GroundingState.NoTelemetry, Array.Empty<string>(), Array.Empty<string>()))
                .ToList();

            return verdict with
            {
                KeyFindings = verdict.KeyFindings.Select(f => Annotate(f, GroundingState.NoTelemetry)).ToList(),
                Attestation = new GroundingAttestation(unbacked)
            };
        }

        var attestations = verdict.KeyFindings
            .Select(finding => Evaluate(finding, rawToolOutput))
            .ToList();

        var attestation = new GroundingAttestation(attestations);
        var headline = verdict.StatusHeadline;

        // A non-healthy verdict carried entirely by claims the telemetry does not contain is the
        // exact fabrication case this layer exists to catch. Surface it in the line the operator
        // reads first; leave OverallStatus untouched so a genuine alert can never be lost to a miss.
        // Partially-grounded findings count as evidence here. A verdict whose primary finding is
        // anchored but carries one stray unmatched number is not "unverified", and saying so would
        // be a false statement printed above a true alert.
        if (verdict.OverallStatus is DiagnosticHealthStatus.Critical or DiagnosticHealthStatus.Warning &&
            attestation.GroundedCount == 0 &&
            attestation.PartiallyGroundedCount == 0 &&
            attestation.UnsupportedCount > 0)
        {
            headline = $"⚠ UNVERIFIED - {StripStatusGlyphs(headline)} " +
                       "(no finding in this verdict is anchored in the collected telemetry)";
        }

        return verdict with
        {
            StatusHeadline = headline,
            KeyFindings = attestations.Select(a => Annotate(a.Finding, a.State)).ToList(),
            Attestation = attestation
        };
    }

    private static FindingAttestation Evaluate(string finding, string haystack)
    {
        var subject = finding.Trim(BulletNoise);
        var claims = subject.Length == 0
            ? Array.Empty<string>()
            : ExtractClaims(subject).ToArray();

        if (claims.Length == 0)
        {
            // Pure prose. Nothing falsifiable was asserted, so this is neither backed nor refuted.
            return new FindingAttestation(
                finding, GroundingState.Unattributed, Array.Empty<string>(), Array.Empty<string>());
        }

        var anchored = new List<string>();
        var missing = new List<string>();
        var percentClaims = PercentOriginClaims(subject);
        Lazy<IReadOnlyList<double>> telemetryNumbers = new(() => ReadNumbers(haystack));

        foreach (var claim in claims)
        {
            if (haystack.Contains(claim, StringComparison.OrdinalIgnoreCase))
            {
                anchored.Add(claim);
                continue;
            }

            // A percentage is almost always COMPUTED from two telemetry values rather than printed
            // by the sensor, so a literal-text miss is not evidence of fabrication. Accept it when it
            // reconciles against a ratio of numbers the telemetry does contain. Without this, every
            // correct piece of arithmetic reads as a lie and operators learn to ignore the marker -
            // which costs more than the hole this layer was built to close.
            if (percentClaims.Contains(claim) && IsDerivableRatio(claim, telemetryNumbers.Value))
            {
                anchored.Add(claim);
                continue;
            }

            missing.Add(claim);
        }

        var state = missing.Count == 0
            ? GroundingState.Grounded
            : anchored.Count > 0
                ? GroundingState.PartiallyGrounded
                : GroundingState.Unsupported;

        return new FindingAttestation(finding, state, anchored, missing);
    }

    /// <summary>
    /// Pulls the falsifiable specifics out of a finding. Quoted spans and percentages are unwrapped
    /// to their inner value so the check still matches telemetry that carries the value without the
    /// model's surrounding punctuation.
    /// </summary>
    public static IReadOnlyList<string> ExtractClaims(string finding)
    {
        var claims = new List<string>();

        // Framework identifiers are knowledge, not measurements: a finding that maps a Run key to
        // ATT&CK T1547.001 or a version to CVE-2024-3094 cites a catalogue, and no sensor's stdout
        // will ever contain the catalogue. Left in, "001" and "3094" read as fabricated counts and the
        // finding is marked unsupported - which on 2026-09-23 sank an otherwise grounded persistence
        // audit below the quality threshold twice and failed the mission. The ids are removed before
        // extraction; every other specific in the finding is still checked.
        finding = KnowledgeIdentifierRegex.Replace(finding, " ");

        foreach (Match match in ClaimTokenRegex.Matches(finding))
        {
            var value = match.Value;

            if (match.Groups["quoted"].Success)
            {
                value = value.Trim('"');
            }
            else if (match.Groups["percent"].Success)
            {
                value = value.Replace(" ", string.Empty).TrimEnd('%');
            }

            value = value.Trim().TrimEnd('.', ',', ';', ':', ')');

            if (value.Length == 0 || claims.Contains(value, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            claims.Add(value);
        }

        return claims;
    }

    /// <summary>
    /// Percentage tokens as they appear after normalisation, so the ratio-reconciliation path only
    /// ever applies to values the model actually wrote as a percentage.
    /// </summary>
    private static HashSet<string> PercentOriginClaims(string finding)
    {
        var percents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in ClaimTokenRegex.Matches(finding))
        {
            if (match.Groups["percent"].Success)
            {
                percents.Add(match.Value.Replace(" ", string.Empty).TrimEnd('%').Trim().TrimEnd('.', ',', ';', ':', ')'));
            }
        }

        return percents;
    }

    private static readonly Regex TelemetryNumberRegex = new(@"\b\d+(?:\.\d+)?\b", RegexOptions.Compiled);

    /// <summary>Numbers the sensor actually printed. Capped so a huge dump cannot make this quadratic.</summary>
    private static IReadOnlyList<double> ReadNumbers(string haystack) =>
        TelemetryNumberRegex.Matches(haystack)
            .Select(m => double.TryParse(m.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.NaN)
            .Where(d => !double.IsNaN(d))
            .Take(64)
            .ToList();

    /// <summary>
    /// True when the claimed percentage reconciles with a ratio of two numbers present in the
    /// telemetry, within the slack a model's rounding introduces.
    /// </summary>
    private static bool IsDerivableRatio(string claim, IReadOnlyList<double> telemetryNumbers)
    {
        if (!double.TryParse(claim, NumberStyles.Float, CultureInfo.InvariantCulture, out var claimed))
        {
            return false;
        }

        // Index-based so "the same reading twice" is excluded by position rather than by value: two
        // distinct sensor readings that happen to be equal are still a legitimate ratio.
        for (int i = 0; i < telemetryNumbers.Count; i++)
        {
            for (int j = 0; j < telemetryNumbers.Count; j++)
            {
                if (i == j || telemetryNumbers[j] == 0d)
                {
                    continue;
                }

                if (Math.Abs((telemetryNumbers[i] / telemetryNumbers[j] * 100d) - claimed) <= 0.15d)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static string StripStatusGlyphs(string? headline) =>
        string.IsNullOrWhiteSpace(headline)
            ? "Verdict"
            : headline.Trim('⚠', '✓', '•', ' ', '\t').TrimStart('-', ' ');

    private static string Annotate(string finding, GroundingState state) => state switch
    {
        GroundingState.Unsupported => finding + "  [UNSUPPORTED - not found in collected telemetry]",
        GroundingState.PartiallyGrounded => finding + "  [PARTIALLY VERIFIED]",
        GroundingState.NoTelemetry => finding + "  [UNVERIFIED - no telemetry captured]",
        _ => finding
    };
}
