using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The source probes are the only templates in the catalog whose whole purpose is to arrive at a
/// third party's API. That makes them the catalog's largest network surface and its most attractive
/// target: a caller who could steer one of them would have a governed fetcher with an audit trail
/// saying the mission was approved.
///
/// These checks hold the properties that make them safe to ship - one hardcoded host each, nothing
/// that carries a credential, and a failure that reaches the model as a stated failure rather than
/// as an empty result a summariser would read as a measurement of zero.
/// </summary>
public class SourceDiscoveryTemplateTests
{
    private static IReadOnlyList<SingleToolTemplate> Probes() => GovernedTemplateCatalog.All
        .Where(template => template.Category == "Source Discovery & Feeds")
        .ToList();

    [Fact]
    public void TheCatalogShipsTheFourProbes_EachWithItsOwnDestination()
    {
        var probes = Probes();

        Assert.Equal(4, probes.Count);
        Assert.Equal(
            new[] { "api.bls.gov", "api.eia.gov", "rareresources.net", "wikimedia.org" },
            probes.Select(p => p.EgressRule.AllowedFqdn).OrderBy(f => f, StringComparer.Ordinal).ToArray());

        // One host each. Two probes sharing a destination would mean one of them is not the reason
        // that destination is declared, and the declaration is what an auditor reads.
        Assert.Equal(probes.Count, probes.Select(p => p.EgressRule.AllowedFqdn).Distinct().Count());
        Assert.All(probes, p => Assert.Equal(EgressScope.ToolProcess, p.EgressRule.Scope));
        Assert.All(probes, p => Assert.True(p.EgressRule.ToolProcessNeedsNetwork));
    }

    /// <summary>
    /// The SSRF property, per probe. The script names its own scheme and host; a parameter may fill
    /// a path segment, a query value or a request body under that host and nothing above it.
    /// </summary>
    [Fact]
    public void NoProbeLetsABoundValueChooseWhereItGoes()
    {
        foreach (var probe in Probes())
        {
            string script = probe.Tool.ArgumentsTemplate;
            string prefix = $"https://{probe.EgressRule.AllowedFqdn}/";

            Assert.Contains(prefix, script, StringComparison.Ordinal);

            // Every URL in the script starts with the declared host. A second scheme anywhere is a
            // second destination, whatever the egress rule says.
            foreach (var index in Occurrences(script, "https://"))
            {
                Assert.StartsWith(prefix, script[index..], StringComparison.Ordinal);
            }

            Assert.DoesNotContain("http://", script, StringComparison.Ordinal);
            Assert.DoesNotContain(
                probe.GetEffectiveDefaults(),
                entry => entry.Value.Contains("://", StringComparison.Ordinal));
        }
    }

    /// <summary>
    /// Credential-free, and deliberately so for the one that probes a key-gated source: its whole
    /// output is what that source says to a caller who has none. A probe that could carry a secret
    /// would be a probe that could leak one into an audit row.
    /// </summary>
    [Fact]
    public void NoProbeCarriesOrAsksForACredential()
    {
        string[] forbidden = { "-Credential", "Authorization", "api_key=", "apikey=", "Bearer ", "-Token" };

        foreach (var probe in Probes())
        {
            foreach (string needle in forbidden)
            {
                Assert.DoesNotContain(needle, probe.Tool.ArgumentsTemplate, StringComparison.OrdinalIgnoreCase);
            }

            Assert.DoesNotContain(
                probe.GetEffectiveDefaults(),
                entry => entry.Key.Contains("key", StringComparison.OrdinalIgnoreCase)
                      || entry.Key.Contains("token", StringComparison.OrdinalIgnoreCase)
                      || entry.Key.Contains("secret", StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// The failure that matters. A probe whose source is down must hand the model a stated failure,
    /// because the dangerous reading of an empty result is "the metric is zero" rather than "the
    /// metric is unknown" - and a dashboard slot filled from the first reading is a fabrication.
    /// </summary>
    [Fact]
    public void EveryProbeStatesItsOwnFailure_AndItsPromptRefusesToReadOneAsAMeasurement()
    {
        foreach (var probe in Probes())
        {
            Assert.Contains("PROBE_FAILED", probe.Tool.ArgumentsTemplate, StringComparison.Ordinal);
            Assert.Contains(0, probe.Tool.AllowedExitCodes);
            Assert.Contains("UNKNOWN", probe.SystemPrompt, StringComparison.OrdinalIgnoreCase);

            // The prompt has to say what an unusable answer means, not merely that one is possible.
            Assert.Contains("untrusted", probe.SystemPrompt, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Read-only. None of these registers, buys, files or publishes anything, and the verbs that
    /// would are absent from every script.
    /// </summary>
    [Fact]
    public void NoProbeWritesAnythingAnywhere()
    {
        string[] mutating = { "Invoke-WebRequest -Method Post", "-Method Put", "-Method Delete", "Out-File", "Set-Content", "Remove-Item", "New-Item" };

        foreach (var probe in Probes())
        {
            foreach (string needle in mutating)
            {
                Assert.DoesNotContain(needle, probe.Tool.ArgumentsTemplate, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    private static IEnumerable<int> Occurrences(string haystack, string needle)
    {
        for (int at = haystack.IndexOf(needle, StringComparison.Ordinal); at >= 0;
             at = haystack.IndexOf(needle, at + 1, StringComparison.Ordinal))
        {
            yield return at;
        }
    }
}
