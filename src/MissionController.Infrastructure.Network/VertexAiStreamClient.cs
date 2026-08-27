using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Network.Egress;

namespace MissionController.Infrastructure.Network.Vertex;

/// <summary>
/// Dormant Google Vertex AI provider slot.
///
/// The previous implementation shipped a malformed Vertex request path
/// (<c>/v1/models/{model}:streamGenerateContent</c> on the regional aiplatform host, which 404s -
/// the real path needs <c>/v1/projects/{p}/locations/{l}/publishers/google/models/...</c> plus a
/// GCP project/location this client was never given) and silently fell back to canned text, so it
/// could never produce real output. That deceptive path has been removed.
///
/// This type is intentionally kept as a labeled, NOT-wired provider to document the
/// <see cref="IModelStreamClient"/> seam. <see cref="ClaudeStreamClient"/> is the supported client.
/// A future Vertex integration should reinstate a verified request path (project/location plumbed
/// in, egress pinned through the firewall) behind <see cref="CheckAvailabilityAsync"/>.
/// </summary>
public sealed class VertexAiStreamClient : IModelStreamClient
{
    private const string ProviderName = "Google Vertex AI";

    public VertexAiStreamClient(
        HttpClient httpClient,
        EgressFirewallHandler firewallHandler,
        ICredentialVault vault,
        ITokenLifecycleManager? tokenLifecycleManager = null)
    {
        // Dependencies retained for signature/DI compatibility; no live path is wired yet.
    }

    public Task<ModelAvailability> CheckAvailabilityAsync(
        string requestedModel,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new ModelAvailability(
            IsLive: false,
            ProviderName: ProviderName,
            ModelId: requestedModel,
            UnavailableReason: "Vertex AI provider is not configured in this build. Use the Anthropic provider."));
    }

    public async IAsyncEnumerable<string> StreamAnalysisAsync(
        string requestedModel,
        string systemPrompt,
        string userPrompt,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await Task.CompletedTask;
        yield return "⚠ SIMULATED OUTPUT — the Vertex AI provider is not configured in this build. " +
                     "No analysis was performed.\n";
    }
}
