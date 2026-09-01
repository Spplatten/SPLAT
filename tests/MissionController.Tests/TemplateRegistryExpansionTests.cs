using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Templates;
using Xunit;

namespace MissionController.Tests;

public class TemplateRegistryExpansionTests
{
    [Fact]
    public async Task RegistrySeedsExpandedGovernedCatalogAndPersistsCustomAgents()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"template_expansion_{Guid.NewGuid():N}.db");
        try
        {
            var context = new SqliteStorageContext(dbPath);
            var registry = new SqliteTemplateRegistry(context);
            var templates = await registry.GetAllTemplatesAsync();

            Assert.True(templates.Count >= 40);
            Assert.Contains(templates, template => template.TemplateId == "network-proxy-config");

            var baseTemplate = templates.First(template => template.TemplateId == "net-dns-audit");
            var customTemplate = new SingleToolTemplate(
                "custom-project-readiness",
                "Project Readiness Agent",
                "Correlates local evidence against a project readiness objective.",
                "Custom Projects",
                baseTemplate.TargetModel,
                baseTemplate.Tool,
                baseTemplate.EgressRule,
                "Evaluate the supplied evidence for project readiness.",
                baseTemplate.ParameterFields,
                baseTemplate.GetEffectiveDefaults(),
                Array.Empty<RemediationAction>(),
                TemplateKind.ProjectAgent,
                new TemplateOutputContract(
                    "Determine project readiness from observed evidence.",
                    new[] { "Readiness decision", "Blocking evidence" },
                    new[] { "Every conclusion cites evidence" }),
                baseTemplate.TemplateId,
                true);

            await registry.RegisterTemplateAsync(customTemplate);
            var persisted = await registry.GetTemplateByIdAsync(customTemplate.TemplateId);

            Assert.NotNull(persisted);
            Assert.Equal(TemplateKind.ProjectAgent, persisted!.Kind);
            Assert.Equal(baseTemplate.TemplateId, persisted.SourceTemplateId);
            Assert.True(persisted.IsUserCreated);

            var projectRegistry = new SqliteProjectTemplateRegistry(context);
            var projects = await projectRegistry.GetAllProjectTemplatesAsync();

            // Asserted against the shipped catalog rather than a literal count: the property under
            // test is that seeding persists every built-in project, and a magic number only pins how
            // many happened to exist the day it was written - it fails on the next addition without
            // anything actually being broken.
            Assert.Equal(GovernedProjectCatalog.All.Count, projects.Count);
            Assert.Contains(projects, project => project.ProjectId == "project-workstation-incident-review");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }
}
