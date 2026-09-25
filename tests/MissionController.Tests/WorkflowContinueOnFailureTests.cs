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
using MissionController.Infrastructure.Data.Catalog;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A failed node stops the workflow unless the plan said otherwise. Both halves matter, and the
/// second one is new: until 2026-09-25 the engine stopped whatever the flag said, because the run
/// loop streamed each node's chunks with <c>await foreach</c> and C# forbids <c>yield return</c>
/// inside a try that has a catch.
///
/// The loop now pumps the node's enumerator by hand - <c>MoveNextAsync</c> inside the catch, the
/// yield inside a try/finally - so a node can fail mid-stream with everything it had already emitted
/// already delivered. Nothing is buffered, which is why these tests assert the streamed chunks and
/// the partial output, not just the verdict.
/// </summary>
public class WorkflowContinueOnFailureTests
{
    private static readonly SingleToolTemplate Fails = GovernedTemplateCatalog.All[0];
    private static readonly SingleToolTemplate Works = GovernedTemplateCatalog.All[1];

    private static WorkflowGraph Graph(bool continueOnFailure)
    {
        var configuration = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [WorkflowExecutionEngine.TemplateIdKey] = Fails.TemplateId,
        };
        if (continueOnFailure)
        {
            configuration[WorkflowExecutionEngine.ContinueOnFailureKey] = "true";
        }

        return new WorkflowGraph(
            WorkflowId: "flow-carry-on",
            Name: "Carry On",
            Description: "One stage that fails, then one that does not.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("trigger-manual", "Start", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                new("step-fails", "Disk Sweep", WorkflowNodeType.GovernedMission, configuration),
                new("step-works", "Network Check", WorkflowNodeType.GovernedMission,
                    new Dictionary<string, string> { [WorkflowExecutionEngine.TemplateIdKey] = Works.TemplateId }),
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger-manual", "step-fails"),
                new("step-fails", "step-works"),
            });
    }

    private static WorkflowExecutionEngine Engine() => new(
        missionEngine: new PartlyFailingMissionEngine(),
        templateRegistry: new TwoTemplateRegistry());

    [Fact]
    public async Task AFailedStageThePlanDeclaredSurvivable_LetsTheRestOfTheRunHappen()
    {
        var result = await Engine().ExecuteAsync(Graph(continueOnFailure: true), new Dictionary<string, string>(), "operator");

        Assert.True(result.Success, result.FailureReason);
        Assert.Contains("step-works", result.NodeOutputs.Keys);
        Assert.Contains("the network is up", result.NodeOutputs["step-works"], StringComparison.Ordinal);

        // What the failing node measured before it failed is what the rest of the run reads. The
        // evidence that produced a failure is the most interesting thing about it.
        Assert.Contains("partial disk reading", result.NodeOutputs["step-fails"], StringComparison.Ordinal);

        Assert.Contains(result.ExecutionLogs, l => l.Contains("carries on", StringComparison.Ordinal));
    }

    /// <summary>
    /// The control. The same graph without the flag must still stop, or the test above is measuring
    /// nothing: a run that never stops would pass it whatever the engine did.
    /// </summary>
    [Fact]
    public async Task TheSameGraphWithoutTheFlag_StopsAtTheFailedStage()
    {
        var result = await Engine().ExecuteAsync(Graph(continueOnFailure: false), new Dictionary<string, string>(), "operator");

        Assert.False(result.Success);
        Assert.DoesNotContain("step-works", result.NodeOutputs.Keys);
        Assert.Contains("did not complete", result.FailureReason ?? string.Empty, StringComparison.Ordinal);
    }

    /// <summary>
    /// A run that carried past a failure did not complete successfully, and the line an operator
    /// reads last must not say it did.
    /// </summary>
    [Fact]
    public async Task TheClosingLine_CountsWhatWasCarriedPast()
    {
        var carried = await Engine().ExecuteAsync(Graph(continueOnFailure: true), new Dictionary<string, string>(), "operator");
        Assert.Contains(carried.ExecutionLogs, l => l.Contains("completed with 1 failed node(s)", StringComparison.Ordinal));
        Assert.DoesNotContain(carried.ExecutionLogs, l => l.Contains("completed successfully", StringComparison.Ordinal));
    }

    /// <summary>
    /// Nothing is buffered: the chunks a node emitted before it failed reach the operator in order,
    /// not as a lump after the verdict. This is the property the manual pump preserves and a
    /// collect-then-decide rewrite would have lost.
    /// </summary>
    [Fact]
    public async Task ChunksEmittedBeforeTheFailure_AreStreamedNotSwallowed()
    {
        var chunks = new List<MissionChunk>();
        await foreach (var chunk in Engine().ExecuteStreamingAsync(
            Graph(continueOnFailure: true), new Dictionary<string, string>(), "operator"))
        {
            chunks.Add(chunk);
        }

        int partial = chunks.FindIndex(c => c.Content.Contains("partial disk reading", StringComparison.Ordinal));
        int carriedOn = chunks.FindIndex(c => c.Content.Contains("carries on", StringComparison.Ordinal));

        Assert.True(partial >= 0, "the failing node's own output never reached the stream");
        Assert.True(carriedOn > partial, "the continuation notice must come after the evidence, not instead of it");
    }

    /// <summary>
    /// Completes missions for one template and fails them for the other, by the rule the engine
    /// actually reads: a mission that never yields <see cref="MissionChunkType.Completed"/> failed.
    /// The failing one streams first, so the failure arrives mid-stream rather than before it.
    /// </summary>
    private sealed class PartlyFailingMissionEngine : IMissionExecutionEngine
    {
        public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            var id = Guid.NewGuid();

            if (string.Equals(template.TemplateId, Works.TemplateId, StringComparison.OrdinalIgnoreCase))
            {
                yield return new MissionChunk(id, MissionChunkType.Stdout, "the network is up", DateTime.UtcNow);
                yield return new MissionChunk(id, MissionChunkType.Completed, "done", DateTime.UtcNow);
                yield break;
            }

            yield return new MissionChunk(id, MissionChunkType.Stdout, "partial disk reading", DateTime.UtcNow);
            // No Completed chunk: the tool failed its exit contract or the gate rejected the analysis.
        }
    }

    private sealed class TwoTemplateRegistry : ITemplateRegistry
    {
        public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<SingleToolTemplate>>(new[] { Fails, Works });

        public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default) =>
            Task.FromResult(new[] { Fails, Works }
                .FirstOrDefault(t => string.Equals(t.TemplateId, templateId, StringComparison.OrdinalIgnoreCase)));

        public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
