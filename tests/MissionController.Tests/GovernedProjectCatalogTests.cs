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
    public void OnlyTheIngestionTemplate_DeclaresANonGatewayEgress()
    {
        var offGateway = GovernedTemplateCatalog.All
            .Where(template => !template.EgressRule.AllowedFqdn.Equals("api.anthropic.com", StringComparison.OrdinalIgnoreCase))
            .Select(template => $"{template.TemplateId} -> {template.EgressRule.AllowedFqdn}")
            .ToList();

        Assert.Equal(new[] { "grants-opportunity-ingestion -> api.grants.gov" }, offGateway);
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
}
