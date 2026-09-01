using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MissionController.Core.Crew;
using MissionController.Infrastructure.Data;
using Xunit;

namespace MissionController.Tests;

public class GovernedCrewRegistryTests : IDisposable
{
    private readonly string _tempDbPath;
    private readonly SqliteStorageContext _context;

    public GovernedCrewRegistryTests()
    {
        _tempDbPath = Path.Combine(Path.GetTempPath(), $"splat_crew_test_{Guid.NewGuid():N}.db");
        _context = new SqliteStorageContext(_tempDbPath);
    }

    public void Dispose()
    {
        if (File.Exists(_tempDbPath))
        {
            try { File.Delete(_tempDbPath); } catch { }
        }
    }

    [Fact]
    public void GovernedCrewParser_ParsesValidJsonDefinition()
    {
        string json = @"
        {
            ""crewId"": ""dynamic-secops-crew"",
            ""name"": ""Dynamic SecOps Crew"",
            ""description"": ""Custom incident response team"",
            ""processType"": ""Sequential"",
            ""agents"": [
                {
                    ""agentId"": ""hunter-1"",
                    ""role"": ""Log Analyst"",
                    ""goal"": ""Analyze authentication logs"",
                    ""backstory"": ""Senior SecOps analyst specializing in AD events."",
                    ""targetModel"": ""claude-3-5-sonnet"",
                    ""assignedTemplateIds"": [""secops-auth-inspector""],
                    ""allowDelegation"": false
                }
            ],
            ""tasks"": [
                {
                    ""taskId"": ""task-analyze-logs"",
                    ""description"": ""Scan security event logs for anomalies"",
                    ""expectedOutput"": ""Log summary"",
                    ""assignedAgentId"": ""hunter-1"",
                    ""templateId"": ""secops-auth-inspector""
                }
            ],
            ""maxRpm"": 25,
            ""maxCrewIterations"": 5,
            ""enableSemanticMemory"": true
        }";

        var crew = GovernedCrewParser.ParseJson(json);

        Assert.NotNull(crew);
        Assert.Equal("dynamic-secops-crew", crew.CrewId);
        Assert.Equal(CrewProcessType.Sequential, crew.ProcessType);
        Assert.Single(crew.Agents);
        Assert.Single(crew.Tasks);
        Assert.Equal("hunter-1", crew.Agents[0].AgentId);
    }

    [Fact]
    public void GovernedCrewParser_RejectsCyclicTaskDependencyGraph()
    {
        string cyclicJson = @"
        {
            ""crewId"": ""cyclic-crew"",
            ""name"": ""Cyclic Crew"",
            ""description"": ""Invalid cyclic task dependencies"",
            ""processType"": ""Sequential"",
            ""agents"": [
                { ""agentId"": ""a1"", ""role"": ""Worker 1"", ""goal"": ""G1"", ""backstory"": ""B1"" },
                { ""agentId"": ""a2"", ""role"": ""Worker 2"", ""goal"": ""G2"", ""backstory"": ""B2"" }
            ],
            ""tasks"": [
                { ""taskId"": ""t1"", ""description"": ""Task 1"", ""expectedOutput"": ""Out 1"", ""assignedAgentId"": ""a1"", ""contextTaskIds"": [""t2""] },
                { ""taskId"": ""t2"", ""description"": ""Task 2"", ""expectedOutput"": ""Out 2"", ""assignedAgentId"": ""a2"", ""contextTaskIds"": [""t1""] }
            ]
        }";

        var ex = Assert.Throws<InvalidOperationException>(() => GovernedCrewParser.ParseJson(cyclicJson));
        Assert.Contains("Cyclic dependency detected", ex.Message);
    }

    [Fact]
    public void GovernedCrewParser_RejectsSelfDependency()
    {
        string selfDepJson = @"
        {
            ""crewId"": ""self-dep-crew"",
            ""name"": ""Self Dep Crew"",
            ""description"": ""Invalid self dependency"",
            ""processType"": ""Sequential"",
            ""agents"": [
                { ""agentId"": ""a1"", ""role"": ""Worker 1"", ""goal"": ""G1"", ""backstory"": ""B1"" }
            ],
            ""tasks"": [
                { ""taskId"": ""t1"", ""description"": ""Task 1"", ""expectedOutput"": ""Out 1"", ""assignedAgentId"": ""a1"", ""contextTaskIds"": [""t1""] }
            ]
        }";

        var ex = Assert.Throws<InvalidOperationException>(() => GovernedCrewParser.ParseJson(selfDepJson));
        Assert.Contains("cannot declare a self-dependency", ex.Message);
    }

    [Fact]
    public async Task SqliteGovernedCrewRegistry_SeedsDefaultCatalogCrews()
    {
        var registry = new SqliteGovernedCrewRegistry(_context);
        var allCrews = await registry.GetAllCrewsAsync();

        Assert.NotEmpty(allCrews);
        Assert.Contains(allCrews, c => c.CrewId == "secops-incident-response-crew");
        Assert.Contains(allCrews, c => c.CrewId == "campus-infrastructure-audit-crew");
    }

    [Fact]
    public async Task SqliteGovernedCrewRegistry_PersistsAndRetrievesCustomCrews()
    {
        var registry = new SqliteGovernedCrewRegistry(_context);

        var customCrew = new GovernedCrewDefinition(
            CrewId: "custom-forensics-crew",
            Name: "Custom Forensics Crew",
            Description: "Specialized memory and registry forensics team",
            ProcessType: CrewProcessType.Sequential,
            Agents: new[]
            {
                new GovernedCrewAgent("analyst-1", "Forensics Analyst", "Audit Registry", "Expert in registry keys")
            },
            Tasks: new[]
            {
                new GovernedCrewTask("task-reg", "Audit Run keys", "Run keys list", "analyst-1")
            });

        await registry.RegisterCrewAsync(customCrew);

        var retrieved = await registry.GetCrewByIdAsync("custom-forensics-crew");
        Assert.NotNull(retrieved);
        Assert.Equal("Custom Forensics Crew", retrieved.Name);
        Assert.Single(retrieved.Agents);

        // Test unregister
        bool unregistered = await registry.UnregisterCrewAsync("custom-forensics-crew");
        Assert.True(unregistered);

        var postDelete = await registry.GetCrewByIdAsync("custom-forensics-crew");
        Assert.Null(postDelete);
    }
}
