using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A project chains agent templates by ID, and nothing at compile time ties the two catalogs
/// together: a stage naming a template that was renamed or never shipped compiles fine, seeds
/// fine, and fails at stage dispatch in front of an operator - see ProjectExecutionEngine, which
/// can only emit "references unavailable agent template" once the run is already underway.
///
/// These tests are the missing link between the two catalogs.
/// </summary>
public class GovernedProjectCatalogTests
{
    [Fact]
    public void EveryShippedProject_PassesItsOwnValidation()
    {
        var failures = new List<string>();

        foreach (var project in GovernedProjectCatalog.All)
        {
            try
            {
                project.Validate();
            }
            catch (InvalidOperationException ex)
            {
                failures.Add($"{project.ProjectId}: {ex.Message}");
            }
        }

        Assert.Empty(failures);
    }

    /// <summary>
    /// The one that matters: every stage must resolve against the agent catalog it will be looked
    /// up in at runtime.
    /// </summary>
    [Fact]
    public void EveryProjectStage_ResolvesToAShippedAgentTemplate()
    {
        var knownTemplateIds = GovernedTemplateCatalog.All
            .Select(template => template.TemplateId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var dangling = GovernedProjectCatalog.All
            .SelectMany(project => project.Stages.Select(stage => (project, stage)))
            .Where(pair => !knownTemplateIds.Contains(pair.stage.TemplateId))
            .Select(pair => $"{pair.project.ProjectId} / stage '{pair.stage.StageId}' -> '{pair.stage.TemplateId}'")
            .ToList();

        Assert.Empty(dangling);
    }

    [Fact]
    public void ProjectIds_AreUnique()
    {
        var duplicates = GovernedProjectCatalog.All
            .GroupBy(project => project.ProjectId, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .ToList();

        Assert.Empty(duplicates);
    }

    /// <summary>
    /// The grant pipeline is the first project whose opening stage reaches the network. Discovery
    /// failing offline must not abort a drafting run against a program the operator already named,
    /// so its tolerate-failure policy is a shipped behaviour rather than an incidental default.
    /// </summary>
    [Fact]
    public void GrantCapturePipeline_ToleratesDiscoveryFailureButNotEligibilityFailure()
    {
        var pipeline = GovernedProjectCatalog.All
            .Single(project => project.ProjectId == "project-grant-capture-pipeline");

        var ingest = pipeline.Stages.First();
        Assert.Equal("grants-opportunity-ingestion", ingest.TemplateId);
        Assert.True(ingest.ContinueOnFailure);

        Assert.All(
            pipeline.Stages.Skip(1),
            stage => Assert.False(stage.ContinueOnFailure));
    }

    /// <summary>
    /// Only the ingestion sensor may hold a non-gateway destination. This is the guard against a
    /// later template quietly acquiring egress: widening the set is a deliberate act that has to
    /// come here and say so.
    /// </summary>
    [Fact]
    public void EveryNonGatewayEgress_IsOneThisCatalogDeclares()
    {
        var offGateway = GovernedTemplateCatalog.All
            .Where(template => !template.EgressRule.AllowedFqdn.Equals("api.anthropic.com", StringComparison.OrdinalIgnoreCase))
            .Select(template => $"{template.TemplateId} -> {template.EgressRule.AllowedFqdn}")
            .ToList();

        // The whole set, named. A template that reaches a host nobody listed here is the change
        // this test exists to stop being silent: each destination is an explicit decision.
        Assert.Equal(
            new[]
            {
                "grants-opportunity-ingestion -> api.grants.gov",
                "source-average-price-probe -> api.bls.gov",
                "source-consumer-catalog -> itunes.apple.com",
                "source-consumer-offers -> apps.apple.com",
                "source-consumer-reviews -> itunes.apple.com",
                "source-credential-gate-probe -> api.eia.gov",
                "source-dataset-catalog-search -> api.census.gov",
                "source-price-index-probe -> api.bls.gov",
                "source-public-interest-probe -> wikimedia.org",
                "source-published-artifact-check -> rareresources.net",
                "trends-brief-composer -> rareresources.net",
            },
            offGateway.OrderBy(entry => entry, StringComparer.Ordinal).ToArray());
    }

    /// <summary>
    /// The fetch destination must never become operator-controllable: a bindable host would turn a
    /// read-only discovery sensor into a governed SSRF primitive reachable from splat-mcp.
    /// </summary>
    [Fact]
    public void IngestionTemplate_HardCodesItsHostRatherThanBindingIt()
    {
        var ingestion = GovernedTemplateCatalog.All
            .Single(template => template.TemplateId == "grants-opportunity-ingestion");

        Assert.Contains("https://api.grants.gov/", ingestion.Tool.ArgumentsTemplate, StringComparison.Ordinal);

        Assert.DoesNotContain(
            ingestion.GetEffectiveDefaults(),
            entry => entry.Value.Contains("://", StringComparison.Ordinal));
    }

    /// <summary>
    /// The same rule, swept over every template that reaches a host, because the danger scales with
    /// the count: one bindable destination is an SSRF primitive, and five would be a fetcher.
    ///
    /// The script must name its own scheme and host literally, and no default may carry a URL - a
    /// parameter that can hold "://" is a parameter that can propose a destination, whatever the
    /// binder does with it afterwards.
    /// </summary>
    [Fact]
    public void EveryTemplateThatReachesAHost_WritesThatHostIntoItsOwnScript()
    {
        var reaching = GovernedTemplateCatalog.All
            .Where(template => !template.EgressRule.AllowedFqdn.Equals("api.anthropic.com", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.NotEmpty(reaching);
        foreach (var template in reaching)
        {
            Assert.Contains(
                $"https://{template.EgressRule.AllowedFqdn}/",
                template.Tool.ArgumentsTemplate,
                StringComparison.Ordinal);

            Assert.DoesNotContain(
                template.GetEffectiveDefaults(),
                entry => entry.Value.Contains("://", StringComparison.Ordinal));

            // A placeholder standing where the scheme or host goes would let a bound value choose
            // the destination while the declared FQDN went on saying otherwise.
            Assert.DoesNotContain("{", template.Tool.ArgumentsTemplate.Split("https://")[1][..template.EgressRule.AllowedFqdn.Length], StringComparison.Ordinal);
        }
    }
}
