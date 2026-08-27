using System.Collections.Generic;
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
/// Exercises the REAL HTTP request-building and SSE-parsing path of <see cref="ClaudeStreamClient"/>
/// against a stub transport. This is the regression guard that was structurally missing before: the
/// previous Vertex client's malformed URL rotted precisely because no test ever sent a request
/// through it. If the endpoint path breaks again, these tests fail instead of a customer.
/// </summary>
public class ModelStreamClientTests
{
    // Deterministic in-memory credential vault (no DPAPI, no process env).
    private sealed class InMemoryVault : ICredentialVault
    {
        private readonly Dictionary<string, string> _store = new();

        public Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default)
        {
            _store[key] = Encoding.UTF8.GetString(secretBytes);
            return Task.CompletedTask;
        }

        public Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default)
            => Task.FromResult<byte[]?>(_store.TryGetValue(key, out var v) ? Encoding.UTF8.GetBytes(v) : null);

        public Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default)
            => Task.FromResult<string?>(_store.TryGetValue(key, out var v) ? v : null);

        public Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default)
        {
            _store[key] = secretString;
            return Task.CompletedTask;
        }

        public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            _store.Remove(key);
            return Task.CompletedTask;
        }
    }

    // Captures the outgoing request and returns a canned Anthropic SSE stream.
    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly string _sseBody;
        public HttpRequestMessage? Captured { get; private set; }

        public StubHandler(string sseBody) => _sseBody = sseBody;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Captured = request;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_sseBody, Encoding.UTF8, "text/event-stream")
            });
        }
    }

    private const string SseBody =
        "event: content_block_delta\n" +
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n" +
        "\n" +
        "event: content_block_delta\n" +
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n" +
        "\n" +
        "event: message_stop\n" +
        "data: {\"type\":\"message_stop\"}\n";

    [Fact]
    public async Task StreamAnalysis_WithKey_HitsAnthropicEndpoint_AndYieldsTextDeltas()
    {
        var handler = new StubHandler(SseBody);
        var httpClient = new HttpClient(handler);
        var vault = new InMemoryVault();
        await vault.StoreSecretStringAsync(ClaudeStreamClient.ApiKeyVaultKey, "sk-ant-test-key");

        var client = new ClaudeStreamClient(httpClient, new EgressFirewallHandler(), vault);

        var sb = new StringBuilder();
        await foreach (var chunk in client.StreamAnalysisAsync("gemini-2.5-pro", "system", "user"))
        {
            sb.Append(chunk);
        }

        Assert.Equal("Hello world", sb.ToString());
        Assert.NotNull(handler.Captured);
        // Regression guard against endpoint-path rot.
        Assert.Equal("https://api.anthropic.com/v1/messages", handler.Captured!.RequestUri!.ToString());
        Assert.True(handler.Captured.Headers.Contains("x-api-key"));
        Assert.True(handler.Captured.Headers.Contains("anthropic-version"));
    }

    [Fact]
    public async Task CheckAvailability_WithNoKey_ReportsNotLive()
    {
        var httpClient = new HttpClient(new StubHandler(SseBody));
        var client = new ClaudeStreamClient(httpClient, new EgressFirewallHandler(), new InMemoryVault());

        var availability = await client.CheckAvailabilityAsync("gemini-2.5-pro");

        Assert.False(availability.IsLive);
        Assert.Equal("Anthropic", availability.ProviderName);
        Assert.False(string.IsNullOrEmpty(availability.UnavailableReason));
    }

    [Fact]
    public async Task StreamAnalysis_WithNoKey_YieldsLabeledSimulatedOutput_NotFabricatedFindings()
    {
        var httpClient = new HttpClient(new StubHandler(SseBody));
        var client = new ClaudeStreamClient(httpClient, new EgressFirewallHandler(), new InMemoryVault());

        var sb = new StringBuilder();
        await foreach (var chunk in client.StreamAnalysisAsync("gemini-2.5-pro", "system", "user"))
        {
            sb.Append(chunk);
        }

        string output = sb.ToString();
        Assert.Contains("SIMULATED", output);
        // It must state plainly that no interpretation happened - never invent findings.
        Assert.Contains("NOT an interpretation", output);
    }
}
