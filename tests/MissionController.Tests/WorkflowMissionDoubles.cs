using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.Workflow;

namespace MissionController.Tests;

/// <summary>
/// The doubles the workflow tests use now that a step is a mission rather than a script.
///
/// These stand in for the mission engine, not for containment: the containment assertions live in
/// the mission-engine suites, where the real jail, token and job object are exercised. What the
/// workflow suite has to prove is narrower and was previously untestable - that a node's work is
/// DELEGATED, that the template came from the catalogue, and that a mission which never completes
/// fails the run rather than passing an empty string downstream.
/// </summary>
internal static class WorkflowMissionDoubles
{
    /// <summary>A catalogue entry with the shape a mission needs and nothing it does not.</summary>
    public static SingleToolTemplate Template(string templateId, string? name = null) =>
        new(
            templateId,
            name ?? templateId,
            $"Test catalogue entry {templateId}",
            "Testing",
            TargetModel: "test-model",
            new SingleToolDefinition($"{templateId}-tool", templateId, "powershell.exe", "-Command Write-Output ok", new[] { 0 }),
            new EgressRule("api.anthropic.com"),
            "System prompt",
            new List<TemplateParameterField>());

    /// <summary>
    /// A node that names a governed template. This is the only way a workflow runs anything now,
    /// so it is the shape every execution test builds on.
    /// </summary>
    public static WorkflowNode MissionNode(
        string nodeId,
        string name,
        string templateId,
        params (string Key, string Value)[] parameters)
    {
        var config = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [WorkflowExecutionEngine.TemplateIdKey] = templateId,
        };
        foreach (var (key, value) in parameters)
        {
            config[key] = value;
        }
        return new WorkflowNode(nodeId, name, WorkflowNodeType.GovernedMission, config);
    }
}

/// <summary>
/// Serves whatever template ids it was told about and refuses the rest, which is the behaviour the
/// engine's catalogue check depends on - an id absent here must fail the node, not be synthesised.
/// </summary>
internal sealed class StubTemplateRegistry : ITemplateRegistry
{
    private readonly Dictionary<string, SingleToolTemplate> _templates;

    public StubTemplateRegistry(params string[] templateIds)
        : this(templateIds.Select(id => WorkflowMissionDoubles.Template(id)))
    {
    }

    public StubTemplateRegistry(IEnumerable<SingleToolTemplate> templates)
    {
        _templates = templates.ToDictionary(t => t.TemplateId, StringComparer.OrdinalIgnoreCase);
    }

    public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<SingleToolTemplate>>(_templates.Values.ToList());

    public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_templates.TryGetValue(templateId, out var t) ? t : null);

    public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default)
    {
        _templates[template.TemplateId] = template;
        return Task.CompletedTask;
    }
}

/// <summary>
/// Records every mission the workflow asked for and replays a scripted result.
///
/// The recording is the point. A workflow node that "succeeded" while never reaching the mission
/// engine is precisely the defect the GovernedMission rewrite closed, so the tests assert on
/// <see cref="Invocations"/> rather than only on the run's own report of itself.
/// </summary>
internal sealed class RecordingMissionEngine : IMissionExecutionEngine
{
    public sealed record Invocation(
        string TemplateId,
        IReadOnlyDictionary<string, string> Parameters,
        string OperatorIdentity);

    private readonly Func<string, IReadOnlyDictionary<string, string>, IReadOnlyList<MissionChunk>> _script;

    public List<Invocation> Invocations { get; } = new();

    /// <summary>Every mission emits <paramref name="stdout"/> and completes.</summary>
    public RecordingMissionEngine(string stdout = "mission output")
        : this((templateId, _) => Emit(stdout, complete: true))
    {
    }

    public RecordingMissionEngine(
        Func<string, IReadOnlyDictionary<string, string>, IReadOnlyList<MissionChunk>> script)
    {
        _script = script;
    }

    /// <summary>A mission that produces output and then dies without completing.</summary>
    public static RecordingMissionEngine NeverCompletes(string stdout = "partial output") =>
        new((_, _) => Emit(stdout, complete: false));

    public static IReadOnlyList<MissionChunk> Emit(string stdout, bool complete)
    {
        var missionId = Guid.NewGuid();
        var chunks = new List<MissionChunk>
        {
            new(missionId, MissionChunkType.Stdout, stdout, DateTime.UtcNow),
        };
        if (complete)
        {
            chunks.Add(new MissionChunk(missionId, MissionChunkType.Completed, "Mission complete.", DateTime.UtcNow));
        }
        return chunks;
    }

    public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
        SingleToolTemplate template,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        Invocations.Add(new Invocation(
            template.TemplateId,
            new Dictionary<string, string>(parameters, StringComparer.OrdinalIgnoreCase),
            operatorIdentity));

        foreach (var chunk in _script(template.TemplateId, parameters))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return chunk;
            await Task.Yield();
        }
    }
}
