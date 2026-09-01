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
/// Streaming client for the Google Gemini Developer API (generativelanguage.googleapis.com),
/// implemented as raw HTTP over the shared hardened <see cref="HttpClient"/> so every request
/// passes through the Layer-4 <see cref="EgressFirewallHandler"/>.
///
/// This replaces the retired Vertex AI path: the Developer API needs only an API key - no GCP
/// project id, no location, no OAuth token minting - which is why it is the correct "paste a key
/// and it works" tier for single-workstation deployments. It shares the honesty invariants of
/// <see cref="ClaudeStreamClient"/>: no key => labeled SIMULATED placeholder; live failure =>
/// loud MODEL REQUEST FAILED line; never canned text posing as analysis.
/// </summary>
public sealed class GeminiStreamClient : IModelStreamClient
{
    private const string ProviderName = "Google Gemini";
    private const string GeminiHost = "generativelanguage.googleapis.com";
    private const string DefaultModel = "gemini-2.5-flash";

    /// <summary>
    /// Vault key for the user's Gemini API key. This is intentionally the exact string the
    /// onboarding wizard has always written, so keys stored before this client existed light up.
    /// </summary>
    public const string ApiKeyVaultKey = "GoogleGeminiApiKey";

    private readonly HttpClient _httpClient;
    private readonly EgressFirewallHandler _firewallHandler;
    private readonly ICredentialVault _vault;

    public GeminiStreamClient(
        HttpClient httpClient,
        EgressFirewallHandler firewallHandler,
        ICredentialVault vault)
    {
        _httpClient = httpClient;
        _firewallHandler = firewallHandler;
        _vault = vault;
    }

    public async Task<ModelAvailability> CheckAvailabilityAsync(
        string requestedModel,
        CancellationToken cancellationToken = default)
    {
        string model = ResolveModel(requestedModel);
        string? apiKey = await ResolveApiKeyAsync(cancellationToken);
        return apiKey is null
            ? new ModelAvailability(false, ProviderName, model,
                "No Gemini API key configured. Add your key in Settings to enable live analysis.")
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
        using var egressScope = _firewallHandler.BeginScope(GeminiHost);

        // systemInstruction is the API's first-class system-prompt channel; concatenating it into
        // the user turn (the old Vertex client's approach) weakens instruction/data separation.
        var payload = new
        {
            systemInstruction = new { parts = new[] { new { text = systemPrompt } } },
            contents = new[]
            {
                new { role = "user", parts = new[] { new { text = userPrompt } } }
            },
            generationConfig = new { temperature = 0.2, maxOutputTokens = 4096 }
        };

        string endpoint = $"https://{GeminiHost}/v1beta/models/{model}:streamGenerateContent?alt=sse";
        var (response, sendError) = await TrySendAsync(endpoint, payload, apiKey, cancellationToken);
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
            bool timedOut = false;
            while (true)
            {
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                readCts.CancelAfter(TimeSpan.FromSeconds(30));

                try
                {
                    line = await reader.ReadLineAsync(readCts.Token);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    timedOut = true;
                    line = null;
                }

                if (timedOut) break;
                if (line is null) break;

                if (!line.StartsWith("data:", StringComparison.Ordinal))
                    continue;

                string data = line.Substring(5).Trim();
                if (data.Length == 0 || data == "[DONE]")
                    continue;

                string? text = ExtractCandidateText(data);
                if (!string.IsNullOrEmpty(text))
                    yield return text;
            }

            if (timedOut)
            {
                yield return "\n⚠ MODEL STREAM TIMEOUT: Remote AI provider stream stalled after 30s of inactivity.";
            }
        }
    }

    /// <summary>
    /// Live round-trip proving the supplied key works BEFORE it is persisted - a cheap
    /// authenticated GET against the models listing (no token spend). Deliberately a concrete
    /// method rather than an IModelStreamClient member: per cross-session agreement the shared
    /// interface stays minimal, and only Gemini onboarding needs pre-validation.
    /// </summary>
    public async Task<Core.Models.AiGatewayValidationResult> ValidateApiKeyAsync(
        string apiKey,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            return new Core.Models.AiGatewayValidationResult(false, "No API key supplied.");

        using var egressScope = _firewallHandler.BeginScope(GeminiHost);
        try
        {
            var request = new HttpRequestMessage(
                HttpMethod.Get, $"https://{GeminiHost}/v1beta/models?pageSize=1");
            request.Headers.TryAddWithoutValidation("x-goog-api-key", apiKey.Trim());

            using var response = await _httpClient.SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
                return new Core.Models.AiGatewayValidationResult(true, "Gemini API key verified against live endpoint.");

            string body = await SafeReadBodyAsync(response, cancellationToken);
            return new Core.Models.AiGatewayValidationResult(
                false, $"Gemini rejected the key (HTTP {(int)response.StatusCode}). {Truncate(body)}");
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

    private static string ResolveModel(string requestedModel) =>
        !string.IsNullOrWhiteSpace(requestedModel) &&
        requestedModel.StartsWith("gemini", StringComparison.OrdinalIgnoreCase)
            ? requestedModel.Trim()
            : DefaultModel;

    private async Task<string?> ResolveApiKeyAsync(CancellationToken cancellationToken)
    {
        string? key = await _vault.RetrieveSecretStringAsync(ApiKeyVaultKey, cancellationToken);
        if (string.IsNullOrWhiteSpace(key))
            key = Environment.GetEnvironmentVariable("GEMINI_API_KEY")
                  ?? Environment.GetEnvironmentVariable("GOOGLE_API_KEY");
        return string.IsNullOrWhiteSpace(key) ? null : key.Trim();
    }

    private async Task<(HttpResponseMessage? Response, string? Error)> TrySendAsync(
        string endpoint, object payload, string apiKey, CancellationToken cancellationToken)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Post, endpoint)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
            };
            // Per-request header (not DefaultRequestHeaders) - the HttpClient is a shared singleton.
            request.Headers.TryAddWithoutValidation("x-goog-api-key", apiKey);

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

    private static string? ExtractCandidateText(string dataJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(dataJson);
            if (doc.RootElement.TryGetProperty("candidates", out var candidates) &&
                candidates.ValueKind == JsonValueKind.Array &&
                candidates.GetArrayLength() > 0 &&
                candidates[0].TryGetProperty("content", out var content) &&
                content.TryGetProperty("parts", out var parts) &&
                parts.ValueKind == JsonValueKind.Array &&
                parts.GetArrayLength() > 0 &&
                parts[0].TryGetProperty("text", out var text))
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
            "No Gemini API key is configured in DPAPI vault or environment.\n",
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
