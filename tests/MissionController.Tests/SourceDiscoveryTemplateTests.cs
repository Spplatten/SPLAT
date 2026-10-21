using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland;
using MissionController.Core.QualityIsland.Oracles;
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
    /// <summary>The source sensors and the brief the figures feed.</summary>
    private static IReadOnlyList<SingleToolTemplate> Reaching() => GovernedTemplateCatalog.All
        .Where(template => template.Category == "Source Discovery & Feeds")
        .ToList();

    /// <summary>The probes alone. The composer reads what a probe already published, so it shares a
    /// destination rather than owning one.</summary>
    private static IReadOnlyList<SingleToolTemplate> Probes() => Reaching()
        .Where(template => template.TemplateId.StartsWith("source-", StringComparison.Ordinal))
        .ToList();

    /// <summary>
    /// The brief is the one template here that writes rather than reports, so it carries the rule
    /// that decides whether what it writes can be published: cite by name, and an uncited figure
    /// costs the whole brief. The page enforces it; this is the instruction that matches.
    /// </summary>
    [Fact]
    public async Task TheBriefComposer_MustCiteEveryFigureItUses_AndWriteNothingWhenThereAreNone()
    {
        var composer = Assert.Single(GovernedTemplateCatalog.All, t => t.TemplateId == "trends-brief-composer");

        Assert.Contains("grounded_in", composer.SystemPrompt, StringComparison.Ordinal);
        Assert.Contains("drops any brief whose citations are not all present", composer.SystemPrompt, StringComparison.Ordinal);

        // The refusals a trends page needs most, because an invented one would be believed there.
        foreach (string refusal in new[] { "No revenue", "no forecast", "is not one causing the other" })
        {
            Assert.Contains(refusal, composer.SystemPrompt, StringComparison.Ordinal);
        }

        // Nothing measured means no brief, not a shorter one.
        Assert.Contains("NO_FIGURES", composer.Tool.ArgumentsTemplate, StringComparison.Ordinal);
        Assert.Contains("write no brief", composer.SystemPrompt, StringComparison.Ordinal);

        // The brief rides in the engine's ONE closing block. Asking for a second object lost to the
        // engine's "nothing after it" rule on 2026-10-20; the schema the model is shown now carries both
        // keys, and the island rejects an answer that drops them, so the next model runs instead.
        Assert.Equal(new[] { "text", "grounded_in" }, composer.EffectiveOutputContract.ResponseFields!.Select(f => f.Name));
        string suffix = StructuredDiagnosisContract.For(composer.EffectiveOutputContract);
        Assert.Contains("\"grounded_in\": [\"exact-figure-name\"]\n}", suffix, StringComparison.Ordinal);
        Assert.Contains("This template also requires \"text\"", suffix, StringComparison.Ordinal);
        var plain = GovernedTemplateCatalog.All.First(t => t.EffectiveOutputContract.ResponseFields is null);
        Assert.Equal(StructuredDiagnosisContract.SystemPromptSuffix, StructuredDiagnosisContract.For(plain.EffectiveOutputContract));

        var oracle = new JsonSchemaValidationOracle();
        var options = new QualityIslandOptions(RequiredResponseFields: new[] { "text", "grounded_in" });
        const string withoutBrief = "Brief.\n```json\n{\"status\":\"Healthy\",\"headline\":\"Figures retrieved\",\"findings\":[\"food +2.5%\"]}\n```";
        const string withBrief = "Brief.\n```json\n{\"status\":\"Healthy\",\"headline\":\"Figures retrieved\",\"findings\":[\"food +2.5%\"],\"text\":\"Food rose 2.5%.\",\"grounded_in\":[\"food-index-change\"]}\n```";
        Assert.False((await oracle.ValidateAsync(withoutBrief, SchemaContractType.StructuredDiagnosis, options)).IsProgrammaticallyValid);
        Assert.True((await oracle.ValidateAsync(withBrief, SchemaContractType.StructuredDiagnosis, options)).IsProgrammaticallyValid);
        Assert.True((await oracle.ValidateAsync(withoutBrief, SchemaContractType.StructuredDiagnosis, new QualityIslandOptions())).IsProgrammaticallyValid);
    }

    [Fact]
    public void EveryProbeReachesOneDeclaredDestination_AndEveryDestinationHasAProbe()
    {
        var probes = Probes();
        var destinations = probes.Select(p => p.EgressRule.AllowedFqdn).Distinct()
            .OrderBy(f => f, StringComparer.Ordinal).ToArray();

        Assert.Equal(9, probes.Count);

        // Not one host each. That rule held while every probe read a different publisher, and the
        // average-price probe is what showed it was the wrong rule: BLS serves an index family and a
        // price family from the same host, and two probes sharing a destination is a publisher with
        // two datasets rather than a redundant declaration. What has to hold is the other direction -
        // no destination is declared that nothing reaches, since an unused declaration is a hole an
        // auditor would read as an intended reach. Apple's search and review feeds share
        // itunes.apple.com the same way, with separate commands and evidence contracts.
        Assert.Equal(new[] { "api.bls.gov", "api.census.gov", "api.eia.gov", "apps.apple.com", "itunes.apple.com", "rareresources.net", "wikimedia.org" }, destinations);
        Assert.All(destinations, fqdn => Assert.Contains(probes, p => p.EgressRule.AllowedFqdn == fqdn));

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
        foreach (var probe in Reaching())
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

        foreach (var probe in Reaching())
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
        foreach (var probe in Reaching())
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

        foreach (var probe in Reaching())
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
