using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

public class ProjectExecutionEngineTests
{
    [Fact]
    public async Task OrderedStages_ForwardBoundedEvidenceToTheNextAgent()
    {
        var template = BuildTemplate("agent-one");
        var registry = new InMemoryTemplateRegistry(template);
        var missionEngine = new RecordingMissionEngine();
        var engine = new ProjectExecutionEngine(registry, missionEngine);
        var project = BuildProject(
            new ProjectStage("first", "First evidence pass", template.TemplateId, "Collect the first evidence pass."),
            new ProjectStage("second", "Second evidence pass", template.TemplateId, "Correlate the second evidence pass."));

        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteProjectAsync(project, new Dictionary<string, string>(), "operator"))
        {
            chunks.Add(chunk);
        }

        Assert.Contains(chunks, chunk => chunk.ChunkType == MissionChunkType.Completed);
        Assert.Equal(2, missionEngine.Calls.Count);
        Assert.Equal("Collect the first evidence pass.", missionEngine.Calls[0].Parameters["UserInstruction"]);
        Assert.Equal("Correlate the second evidence pass.", missionEngine.Calls[1].Parameters["UserInstruction"]);
        Assert.Contains("analysis: Collect the first evidence pass.", missionEngine.Calls[1].Parameters["ProjectContext"]);
    }

    [Fact]
    public async Task MissingStageTemplate_StopsTheProjectBeforeTheNextStage()
    {
        var template = BuildTemplate("available-agent");
        var registry = new InMemoryTemplateRegistry(template);
        var missionEngine = new RecordingMissionEngine();
        var engine = new ProjectExecutionEngine(registry, missionEngine);
        var project = BuildProject(
            new ProjectStage("first", "Missing evidence pass", "missing-agent", "Collect evidence."),
            new ProjectStage("second", "Unreachable stage", template.TemplateId, "This must not run."));

        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteProjectAsync(project, new Dictionary<string, string>(), "operator"))
        {
            chunks.Add(chunk);
        }

        Assert.Contains(chunks, chunk => chunk.Content.Contains("unavailable agent template", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(chunks, chunk => chunk.Content.Contains("Project aborted", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(chunks, chunk => chunk.ChunkType == MissionChunkType.Completed);
        Assert.Empty(missionEngine.Calls);
    }

    [Fact]
    public async Task FailedStageWithContinuePolicy_AllowsLaterStageToRun()
    {
        var template = BuildTemplate("resilient-agent");
        var registry = new InMemoryTemplateRegistry(template);
        var missionEngine = new RecordingMissionEngine(failFirstCall: true);
        var engine = new ProjectExecutionEngine(registry, missionEngine);
        var project = BuildProject(
            new ProjectStage("first", "Best effort evidence", template.TemplateId, "Run the best effort evidence pass.", true),
            new ProjectStage("second", "Final correlation", template.TemplateId, "Complete the final correlation."));

        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteProjectAsync(project, new Dictionary<string, string>(), "operator"))
        {
            chunks.Add(chunk);
        }

        Assert.Equal(2, missionEngine.Calls.Count);
        Assert.Contains(chunks, chunk => chunk.ChunkType == MissionChunkType.Completed);
    }

    [Fact]
    public void ProjectValidation_RejectsMoreThanSixStages()
    {
        var stages = Enumerable.Range(1, 7)
            .Select(index => new ProjectStage($"stage-{index}", $"Stage {index}", "agent", "Collect evidence."))
            .ToArray();
        var project = new ProjectTemplate("project-test", "Test", "Description", "Tests", stages, new[] { "Deliverable" });

        Assert.Throws<InvalidOperationException>(() => project.Validate());
    }

    private static ProjectTemplate BuildProject(params ProjectStage[] stages) =>
        new("project-test", "Test Project", "Bounded test project", "Tests", stages, new[] { "Evidence report" });

    private static SingleToolTemplate BuildTemplate(string id) => new(
        id,
        "Test Agent",
        "Agent for project tests",
        "Tests",
        "test-model",
        new SingleToolDefinition("tool-" + id, "Test Tool", "test.exe", string.Empty, new[] { 0 }),
        new EgressRule("example.test"),
        "Analyze evidence.",
        new Dictionary<string, string>());

    private sealed class InMemoryTemplateRegistry : ITemplateRegistry
    {
        private readonly IReadOnlyList<SingleToolTemplate> _templates;

        public InMemoryTemplateRegistry(params SingleToolTemplate[] templates)
        {
            _templates = templates;
        }

        public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(_templates);

        public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_templates.FirstOrDefault(template => template.TemplateId == templateId));

        public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }

    private sealed class RecordingMissionEngine : IMissionExecutionEngine
    {
        public List<MissionCall> Calls { get; } = new();
        private readonly bool _failFirstCall;

        public RecordingMissionEngine(bool failFirstCall = false)
        {
            _failFirstCall = failFirstCall;
        }

        public IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            CancellationToken cancellationToken = default)
        {
            var call = new MissionCall(new Dictionary<string, string>(parameters));
            Calls.Add(call);
            return StreamAsync(call, _failFirstCall && Calls.Count == 1, cancellationToken);
        }

        private static async IAsyncEnumerable<MissionChunk> StreamAsync(
            MissionCall call,
            bool fail,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();
            cancellationToken.ThrowIfCancellationRequested();
            if (fail)
            {
                yield return new MissionChunk(Guid.NewGuid(), MissionChunkType.Stderr, "MISSION FAILED: test failure", DateTime.UtcNow);
                yield break;
            }

            yield return new MissionChunk(Guid.NewGuid(), MissionChunkType.Stdout, "sensor: " + call.Parameters["UserInstruction"], DateTime.UtcNow);
            yield return new MissionChunk(Guid.NewGuid(), MissionChunkType.AiToken, "analysis: " + call.Parameters["UserInstruction"], DateTime.UtcNow);
            yield return new MissionChunk(Guid.NewGuid(), MissionChunkType.Completed, "done", DateTime.UtcNow);
        }
    }

    private sealed record MissionCall(IReadOnlyDictionary<string, string> Parameters);
}
