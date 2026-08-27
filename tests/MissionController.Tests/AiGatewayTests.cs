using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Network.Ai;
using MissionController.Infrastructure.Network.Egress;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Regression tests for the credential->gateway handoff. The original shipped bug was exactly
/// this seam: onboarding stored a key under a vault name no client read, the client silently
/// streamed canned text, and 41 green tests never noticed because none crossed the seam.
/// These tests pin (1) the vault-key contract, (2) the exact request shape on the wire,
/// (3) the honesty invariants (labeled simulation, loud failure), and (4) router selection.
/// </summary>
public class AiGatewayTests
{
    public AiGatewayTests()
    {
        // The clients fall back to process env vars; clear them so vault state alone drives
        // selection and the no-credential tests cannot be flipped by the host machine's config.
        Environment.SetEnvironmentVariable("ANTHROPIC_API_KEY", null);
        Environment.SetEnvironmentVariable("GEMINI_API_KEY", null);
        Environment.SetEnvironmentVariable("GOOGLE_API_KEY", null);
    }

    // ---------------------------------------------------------------- test doubles

    private sealed class InMemoryVault : ICredentialVault
    {
        private readonly ConcurrentDictionary<string, byte[]> _store = new();

        public Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default)
        {
            _store[key] = secretBytes;
            return Task.CompletedTask;
        }

        public Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default) =>
            Task.FromResult(_store.TryGetValue(key, out var v) ? v : null);

        public Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default) =>
            Task.FromResult(_store.TryGetValue(key, out var v) ? Encoding.UTF8.GetString(v) : null);

        public Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default)
        {
            _store[key] = Encoding.UTF8.GetBytes(secretString);
            return Task.CompletedTask;
        }

        public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            _store.TryRemove(key, out _);
            return Task.CompletedTask;
        }
    }

    private sealed class StubHttpHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;
        public List<(Uri? Uri, string? ApiKeyHeader, string Body)> Requests { get; } = new();

        public StubHttpHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) => _responder = responder;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            request.Headers.TryGetValues("x-goog-api-key", out var googKeys);
            request.Headers.TryGetValues("x-api-key", out var antKeys);
            Requests.Add((request.RequestUri, (googKeys ?? antKeys)?.FirstOrDefault(), body));
            return _responder(request);
        }
    }

    /// <summary>Builds the real pipeline: HttpClient -> EgressFirewallHandler -> stub, so every
    /// test also proves the client's own egress pin admits its provider host.</summary>
    private static (HttpClient Client, EgressFirewallHandler Firewall, StubHttpHandler Stub) BuildPipeline(
        Func<HttpRequestMessage, HttpResponseMessage> responder)
    {
        var stub = new StubHttpHandler(responder);
        var firewall = new EgressFirewallHandler { InnerHandler = stub };
        return (new HttpClient(firewall), firewall, stub);
    }

    private static HttpResponseMessage GeminiSseResponse(string text)
    {
        string sse = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"" + text + "\"}]},\"index\":0}]}\n\n";
        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(sse, Encoding.UTF8, "text/event-stream")
        };
    }

    private static async Task<string> DrainAsync(IAsyncEnumerable<string> stream)
    {
        var sb = new StringBuilder();
        await foreach (var chunk in stream)
            sb.Append(chunk);
        return sb.ToString();
    }

    // ---------------------------------------------------------------- Gemini client contract

    [Fact]
    public async Task GeminiClient_ReadsOnboardingVaultKey_AndSendsCorrectRequestShape()
    {
        var vault = new InMemoryVault();
        // The exact key name the onboarding wizard has always written - THE regression contract.
        await vault.StoreSecretStringAsync("GoogleGeminiApiKey", "test-gemini-key-123");
        Assert.Equal("GoogleGeminiApiKey", GeminiStreamClient.ApiKeyVaultKey);

        var (http, firewall, stub) = BuildPipeline(_ => GeminiSseResponse("Hello from Gemini"));
        var client = new GeminiStreamClient(http, firewall, vault);

        string output = await DrainAsync(client.StreamAnalysisAsync("gemini-2.5-pro", "system", "user telemetry"));

        Assert.Contains("Hello from Gemini", output);
        var req = Assert.Single(stub.Requests);
        Assert.Equal(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
            req.Uri!.ToString());
        Assert.Equal("test-gemini-key-123", req.ApiKeyHeader);
        Assert.Contains("systemInstruction", req.Body);
        Assert.Contains("user telemetry", req.Body);
    }

    [Fact]
    public async Task GeminiClient_NoCredentials_YieldsLabeledSimulation_AndNeverTouchesNetwork()
    {
        var vault = new InMemoryVault();
        var (http, firewall, stub) = BuildPipeline(_ => throw new InvalidOperationException("must not be called"));
        var client = new GeminiStreamClient(http, firewall, vault);

        var availability = await client.CheckAvailabilityAsync("gemini-2.5-pro");
        Assert.False(availability.IsLive);

        string output = await DrainAsync(client.StreamAnalysisAsync("gemini-2.5-pro", "system", "line1\nline2"));

        Assert.Contains("SIMULATED OUTPUT", output);
        Assert.Contains("NOT an interpretation", output);
        // The retired fake stream fabricated findings under this heading; it must stay dead.
        Assert.DoesNotContain("Diagnostic output processed successfully", output);
        Assert.Empty(stub.Requests);
    }

    [Fact]
    public async Task GeminiClient_HttpError_SurfacesLoudFailure_InsteadOfCannedText()
    {
        var vault = new InMemoryVault();
        await vault.StoreSecretStringAsync(GeminiStreamClient.ApiKeyVaultKey, "bad-key");

        var (http, firewall, _) = BuildPipeline(_ => new HttpResponseMessage(HttpStatusCode.Forbidden)
        {
            Content = new StringContent("{\"error\":{\"message\":\"API key not valid\"}}", Encoding.UTF8, "application/json")
        });
        var client = new GeminiStreamClient(http, firewall, vault);

        string output = await DrainAsync(client.StreamAnalysisAsync("gemini-2.5-flash", "s", "u"));

        Assert.Contains("MODEL REQUEST FAILED (HTTP 403)", output);
        Assert.Contains("API key not valid", output);
        Assert.DoesNotContain("SIMULATED OUTPUT", output);
    }

    [Fact]
    public async Task GeminiClient_ValidateApiKey_DistinguishesLiveSuccessFromRejection()
    {
        var vault = new InMemoryVault();
        var (goodHttp, goodFirewall, goodStub) = BuildPipeline(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("{\"models\":[]}", Encoding.UTF8, "application/json")
        });
        var goodClient = new GeminiStreamClient(goodHttp, goodFirewall, vault);

        var ok = await goodClient.ValidateApiKeyAsync("live-key");
        Assert.True(ok.IsValid);
        var probe = Assert.Single(goodStub.Requests);
        Assert.Equal("https://generativelanguage.googleapis.com/v1beta/models?pageSize=1", probe.Uri!.ToString());
        Assert.Equal("live-key", probe.ApiKeyHeader);

        var (badHttp, badFirewall, _) = BuildPipeline(_ => new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("{\"error\":{\"message\":\"API key not valid\"}}", Encoding.UTF8, "application/json")
        });
        var badClient = new GeminiStreamClient(badHttp, badFirewall, vault);

        var rejected = await badClient.ValidateApiKeyAsync("dead-key");
        Assert.False(rejected.IsValid);
        Assert.Contains("HTTP 400", rejected.Message);

        var empty = await badClient.ValidateApiKeyAsync("   ");
        Assert.False(empty.IsValid);
    }

    // ---------------------------------------------------------------- router selection policy

    [Fact]
    public async Task Router_PrefersClaude_WhenAnthropicKeyPresent()
    {
        var vault = new InMemoryVault();
        await vault.StoreSecretStringAsync(ClaudeStreamClient.ApiKeyVaultKey, "sk-ant-test");
        await vault.StoreSecretStringAsync(GeminiStreamClient.ApiKeyVaultKey, "gemini-test");

        var (http, firewall, _) = BuildPipeline(_ => new HttpResponseMessage(HttpStatusCode.OK));
        var router = new ModelClientRouter(
            new ClaudeStreamClient(http, firewall, vault),
            new GeminiStreamClient(http, firewall, vault));

        var availability = await router.CheckAvailabilityAsync("gemini-2.5-pro");

        Assert.True(availability.IsLive);
        Assert.Equal("Anthropic", availability.ProviderName);
    }

    [Fact]
    public async Task Router_UsesGemini_WhenItHoldsTheOnlyKey()
    {
        var vault = new InMemoryVault();
        await vault.StoreSecretStringAsync(GeminiStreamClient.ApiKeyVaultKey, "gemini-only-key");

        var (http, firewall, stub) = BuildPipeline(_ => GeminiSseResponse("routed"));
        var router = new ModelClientRouter(
            new ClaudeStreamClient(http, firewall, vault),
            new GeminiStreamClient(http, firewall, vault));

        var availability = await router.CheckAvailabilityAsync("gemini-2.5-flash");
        Assert.True(availability.IsLive);
        Assert.Equal("Google Gemini", availability.ProviderName);

        string output = await DrainAsync(router.StreamAnalysisAsync("gemini-2.5-flash", "s", "u"));
        Assert.Contains("routed", output);
        Assert.All(stub.Requests, r => Assert.Equal("generativelanguage.googleapis.com", r.Uri!.Host));
    }

    [Theory]
    [InlineData("sk-ant-api03-abc123", "Anthropic.ApiKey")]
    [InlineData("  sk-ant-padded  ", "Anthropic.ApiKey")]
    [InlineData("AIzaSyD-fake-google-key", "GoogleGeminiApiKey")]
    [InlineData("  AIzaPadded  ", "GoogleGeminiApiKey")]
    [InlineData("something-unrecognized", "Anthropic.ApiKey")]
    public void ProviderKeyClassifier_RoutesKeysToTheSlotTheirClientReads(string pastedKey, string expectedVaultKey)
    {
        var (vaultKey, providerName) = ProviderKeyClassifier.Classify(pastedKey);

        Assert.Equal(expectedVaultKey, vaultKey);
        Assert.False(string.IsNullOrWhiteSpace(providerName));
        // The classifier must stay welded to the client constants - a drift here recreates
        // the original stored-under-a-name-nothing-reads bug.
        Assert.True(
            vaultKey == ClaudeStreamClient.ApiKeyVaultKey || vaultKey == GeminiStreamClient.ApiKeyVaultKey);
    }

    [Fact]
    public async Task Router_NoKeysAnywhere_ReportsBothRecoveryOptions()
    {
        var vault = new InMemoryVault();
        var (http, firewall, stub) = BuildPipeline(_ => throw new InvalidOperationException("must not be called"));
        var router = new ModelClientRouter(
            new ClaudeStreamClient(http, firewall, vault),
            new GeminiStreamClient(http, firewall, vault));

        var availability = await router.CheckAvailabilityAsync("any-model");

        Assert.False(availability.IsLive);
        Assert.Contains("Anthropic", availability.UnavailableReason);
        Assert.Contains("Gemini", availability.UnavailableReason);
        Assert.Empty(stub.Requests);
    }
}
