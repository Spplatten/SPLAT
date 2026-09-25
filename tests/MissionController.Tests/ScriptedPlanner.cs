using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Tests;

/// <summary>
/// A model that answers with one scripted plan and records what it was asked.
///
/// Shared by every test that drives <c>WorkflowSynthesizerEngine</c>, because the synthesiser now
/// refuses without a model rather than matching keywords - which is the point of it, and means a
/// test that wants a graph has to say what the model said. The recorded prompts are how a test
/// asserts the model was called at all: the defect this replaced was a client held in a field and
/// never used.
/// </summary>
internal sealed class ScriptedPlanner : IModelStreamClient
{
    private readonly string _answer;

    public ScriptedPlanner(string answer) => _answer = answer;

    /// <summary>Answers with the named prebuilt recipe, as a model choosing one would.</summary>
    public static ScriptedPlanner ChoosingRecipe(string recipeId) =>
        new($"{{\"recipeId\": \"{recipeId}\"}}");

    public string LastSystemPrompt { get; private set; } = string.Empty;

    public string LastUserPrompt { get; private set; } = string.Empty;

    public Task<ModelAvailability> CheckAvailabilityAsync(
        string requestedModel, CancellationToken cancellationToken = default) =>
        Task.FromResult(new ModelAvailability(true, "Scripted", requestedModel, null));

    public async IAsyncEnumerable<string> StreamAnalysisAsync(
        string requestedModel, string systemPrompt, string userPrompt,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        LastSystemPrompt = systemPrompt;
        LastUserPrompt = userPrompt;
        await Task.Yield();

        // One chunk at a time, because the compiler accumulates a stream rather than reading a
        // string, and a parser that only ever saw whole answers would not be exercised.
        foreach (var chunk in _answer.Chunk(64))
        {
            yield return new string(chunk);
        }
    }
}
