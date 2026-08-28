using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Network.Egress;

namespace MissionController.Infrastructure.Network.Ai;

/// <summary>
/// Streaming client for the Anthropic Messages API (Claude), implemented as raw HTTP over the
/// shared hardened <see cref="HttpClient"/> ON PURPOSE: every model request must pass through the
/// Layer-4 <see cref="EgressFirewallHandler"/> in the pipeline. An SDK opening its own socket would
/// bypass that governance, so we hand-build the request and let the firewall validate the host.
///
/// Honesty invariants (these close the "silent mannequin" gap):
///  - When no API key is configured, <see cref="CheckAvailabilityAsync"/> reports IsLive=false and
///    <see cref="StreamAnalysisAsync"/> yields a placeholder that explicitly labels itself SIMULATED
///    and states that no interpretation was performed - it never fabricates findings.
///  - When the live request fails (bad key, blocked egress, network), the stream yields a loud
///    "MODEL REQUEST FAILED" line rather than silently substituting canned text.
/// </summary>
public sealed class ClaudeStreamClient : IModelStreamClient
{
    private const string ProviderName = "Anthropic";
    private const string AnthropicHost = "api.anthropic.com";
    private const string MessagesEndpoint = "https://api.anthropic.com/v1/messages";
    private const string ApiVersion = "2023-06-01";
    private const string DefaultModel = "claude-3-5-sonnet-20241022";

    /// <summary>Vault key the onboarding wizard and Settings write the user's API key to.</summary>
    public const string ApiKeyVaultKey = "Anthropic.ApiKey";

    private readonly HttpClient _httpClient;
    private readonly EgressFirewallHandler _firewallHandler;
    private readonly ICredentialVault _vault;

    public ClaudeStreamClient(
        HttpClient httpClient,
        EgressFirewallHandler firewallHandler,
        ICredentialVault vault,
        ITokenLifecycleManager? tokenLifecycleManager = null)
    {
        _httpClient = httpClient;
        _firewallHandler = firewallHandler;
        _vault = vault;
        // tokenLifecycleManager reserved for a future OAuth/device-code flow; unused for API-key auth.
    }

    public async Task<ModelAvailability> CheckAvailabilityAsync(
        string requestedModel,
        CancellationToken cancellationToken = default)
    {
        string model = ResolveModel(requestedModel);
        string? apiKey = await ResolveApiKeyAsync(cancellationToken);
        return apiKey is null
            ? new ModelAvailability(false, ProviderName, model,
                "No Anthropic API key configured. Add your key in Settings to enable live analysis.")
            : new ModelAvailability(true, ProviderName, model, null);
    }

    public async IAsyncEnumerable<string> StreamAnalysisAsync(
        string requestedModel,
        string systemPrompt,
        string userPrompt,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string model = ResolveModel(requestedModel);
        string? apiKey = await ResolveApiKeyAsync(cancellationToken);

        if (apiKey is null)
        {
            foreach (var part in BuildSimulatedPlaceholder(userPrompt))
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return part;
            }
            yield break;
        }

        // Governed egress: pin the request to the provider host so the Layer-4 firewall validates it.
        _firewallHandler.SetActiveAllowedFqdn(AnthropicHost);

        var payload = new
        {
            model,
            max_tokens = 4096,
            stream = true,
            system = systemPrompt,
            messages = new[] { new { role = "user", content = userPrompt } }
        };

        var (response, sendError) = await TrySendAsync(payload, apiKey, cancellationToken);
        if (sendError is not null || response is null)
        {
            yield return sendError ?? "⚠ MODEL REQUEST FAILED: Transport returned empty response.";
            yield break;
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                string body = await SafeReadBodyAsync(response, cancellationToken);
                yield return $"⚠ MODEL REQUEST FAILED (HTTP {(int)response.StatusCode}). " +
                             "The sandboxed tool output is real; live AI interpretation could not be produced. " +
                             Truncate(body);
                yield break;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var reader = new StreamReader(stream, Encoding.UTF8);

            string? line;
            while ((line = await reader.ReadLineAsync(cancellationToken)) is not null)
            {
                if (!line.StartsWith("data:", StringComparison.Ordinal))
                    continue;

                string data = line.Substring(5).Trim();
                if (data.Length == 0 || data == "[DONE]")
                    continue;

                string? text = ExtractTextDelta(data);
                if (!string.IsNullOrEmpty(text))
                    yield return text;
            }
        }
    }

    /// <summary>
    /// Live round-trip proving the supplied Anthropic key works BEFORE it is persisted - an
    /// authenticated GET against the models listing (no token spend).
    /// </summary>
    public async Task<Core.Models.AiGatewayValidationResult> ValidateApiKeyAsync(
        string apiKey,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return new Core.Models.AiGatewayValidationResult(false, "No API key supplied.");

        _firewallHandler.SetActiveAllowedFqdn(AnthropicHost);
        try
        {
            var request = new HttpRequestMessage(
                HttpMethod.Get, "https://api.anthropic.com/v1/models?limit=1");
            request.Headers.TryAddWithoutValidation("x-api-key", apiKey.Trim());
            request.Headers.TryAddWithoutValidation("anthropic-version", ApiVersion);

            using var response = await _httpClient.SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
                return new Core.Models.AiGatewayValidationResult(true, "Anthropic Claude API key verified against live endpoint.");

            string body = await SafeReadBodyAsync(response, cancellationToken);
            return new Core.Models.AiGatewayValidationResult(
                false, $"Anthropic rejected the key (HTTP {(int)response.StatusCode}). {Truncate(body)}");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            return new Core.Models.AiGatewayValidationResult(false, $"Validation request failed: {ex.Message}");
        }
    }

    private static string ResolveModel(string requestedModel)
    {
        if (string.IsNullOrWhiteSpace(requestedModel))
            return DefaultModel;

        string lower = requestedModel.ToLowerInvariant();
        if (lower.Contains("haiku") || lower.Contains("flash"))
            return "claude-3-5-haiku-20241022";
        if (lower.Contains("opus"))
            return "claude-3-opus-20240229";
        if (lower.StartsWith("claude-"))
            return requestedModel.Trim();

        return DefaultModel;
    }

    private async Task<string?> ResolveApiKeyAsync(CancellationToken cancellationToken)
    {
        string? key = await _vault.RetrieveSecretStringAsync(ApiKeyVaultKey, cancellationToken);
        if (!string.IsNullOrWhiteSpace(key))
            return key.Trim();

        // Support standard developer/enterprise environment variable fallback
        string? envKey = Environment.GetEnvironmentVariable("ANTHROPIC_API_KEY");
        if (!string.IsNullOrWhiteSpace(envKey))
            return envKey.Trim();

        return null;
    }

    private async Task<(HttpResponseMessage? Response, string? Error)> TrySendAsync(
        object payload, string apiKey, CancellationToken cancellationToken)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Post, MessagesEndpoint)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
            };
            // Per-request headers (not DefaultRequestHeaders) - the HttpClient is a shared singleton.
            request.Headers.TryAddWithoutValidation("x-api-key", apiKey);
            request.Headers.TryAddWithoutValidation("anthropic-version", ApiVersion);

            var response = await _httpClient.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            return (response, null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Includes SecurityException from the egress firewall - surfaced honestly, not hidden.
            return (null, $"⚠ MODEL REQUEST FAILED: {ex.Message}. " +
                          "The sandboxed tool output is real; live AI interpretation could not be produced.");
        }
    }

    private static string? ExtractTextDelta(string dataJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(dataJson);
            var root = doc.RootElement;
            if (!root.TryGetProperty("type", out var typeProp) ||
                typeProp.GetString() != "content_block_delta")
            {
                return null;
            }

            if (root.TryGetProperty("delta", out var delta) &&
                delta.TryGetProperty("type", out var deltaType) &&
                deltaType.GetString() == "text_delta" &&
                delta.TryGetProperty("text", out var text))
            {
                return text.GetString();
            }
        }
        catch
        {
            // Ignore partial/non-JSON keepalive frames.
        }
        return null;
    }

    private static string[] BuildSimulatedPlaceholder(string userPrompt)
    {
        int lines = string.IsNullOrEmpty(userPrompt)
            ? 0
            : userPrompt.Split('\n').Length;

        return new[]
        {
            "⚠ SIMULATED OUTPUT — no AI model is connected.\n\n",
            "No Anthropic API key is configured in DPAPI vault or environment.\n",
            $"The sandboxed diagnostic tool executed and produced {lines} line(s) of genuine OS telemetry.\n",
            "This placeholder is NOT an interpretation from a remote LLM; raw telemetry is evaluated by the local governance engine.\n"
        };
    }

    private static async Task<string> SafeReadBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        try
        {
            return await response.Content.ReadAsStringAsync(cancellationToken);
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string Truncate(string s)
    {
        if (string.IsNullOrEmpty(s)) return string.Empty;
        return s.Length <= 300 ? s : s.Substring(0, 300) + "…";
    }
}
