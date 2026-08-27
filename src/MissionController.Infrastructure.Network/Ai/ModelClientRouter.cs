using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Network.Ai;

/// <summary>
/// Routes each mission to whichever governed provider client actually has credentials.
///
/// Selection policy (a product decision, kept in exactly one place):
///  1. Claude is the product default - it wins whenever an Anthropic key is configured.
///  2. Gemini engages only when it holds the sole configured key, so a user who pastes either
///     vendor's key gets live analysis instead of the simulated placeholder.
///  3. With no keys at all, the Claude client's honest SIMULATED path handles messaging.
///
/// The router owns no HTTP and no egress pinning - each concrete client pins its own host
/// through the Layer-4 firewall, so routing can never widen the whitelist.
/// </summary>
public sealed class ModelClientRouter : IModelStreamClient
{
    private readonly ClaudeStreamClient _claude;
    private readonly GeminiStreamClient _gemini;

    public ModelClientRouter(ClaudeStreamClient claude, GeminiStreamClient gemini)
    {
        _claude = claude;
        _gemini = gemini;
    }

    public async Task<ModelAvailability> CheckAvailabilityAsync(
        string requestedModel,
        CancellationToken cancellationToken = default)
    {
        var claude = await _claude.CheckAvailabilityAsync(requestedModel, cancellationToken);
        if (claude.IsLive)
            return claude;

        var gemini = await _gemini.CheckAvailabilityAsync(requestedModel, cancellationToken);
        if (gemini.IsLive)
            return gemini;

        // Neither provider is configured - report the full recovery path, not just one vendor's.
        return claude with
        {
            UnavailableReason =
                "No AI provider key configured (Anthropic or Gemini). Add either key in Settings to enable live analysis."
        };
    }

    public async IAsyncEnumerable<string> StreamAnalysisAsync(
        string requestedModel,
        string systemPrompt,
        string userPrompt,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var client = await SelectAsync(requestedModel, cancellationToken);
        await foreach (var chunk in client.StreamAnalysisAsync(requestedModel, systemPrompt, userPrompt, cancellationToken))
        {
            yield return chunk;
        }
    }

    private async Task<IModelStreamClient> SelectAsync(string requestedModel, CancellationToken cancellationToken)
    {
        var claude = await _claude.CheckAvailabilityAsync(requestedModel, cancellationToken);
        if (claude.IsLive)
            return _claude;

        var gemini = await _gemini.CheckAvailabilityAsync(requestedModel, cancellationToken);
        return gemini.IsLive ? _gemini : _claude;
    }
}
