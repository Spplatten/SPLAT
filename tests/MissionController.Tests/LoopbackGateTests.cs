using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Workflow;
using MissionController.Infrastructure.Network.Triggers;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The loopback trigger surface. Reaching 127.0.0.1 is not authority: on a shared workstation any
/// local account can POST to it, and so can any page the operator's browser happens to load.
///
/// The gate that landed first returned true whenever no token was configured, which is the default,
/// so a host that had never set SPLAT_API_KEY was exactly as open as before it existed - while the
/// test asserting a 401 for a wrong token still passed. These pin the properties that were missing.
/// </summary>
public class LoopbackGateTests : IDisposable
{
    private const int Port = 5691;

    private readonly InMemoryWorkflowRegistry _registry = new();
    private readonly EmbeddedWebhookListener _listener;
    private readonly HttpClient _client = new();

    public LoopbackGateTests()
    {
        // No token supplied and none in the environment: the state the old gate left wide open.
        _listener = new EmbeddedWebhookListener(
            Port,
            _registry,
            new WorkflowExecutionEngine(allowSimulatedExecution: true));
        _listener.Start();
    }

    public void Dispose()
    {
        _client.Dispose();
        _listener.Dispose();
    }

    private HttpRequestMessage Request(HttpMethod method, string path, string? token = null, string? host = null)
    {
        var request = new HttpRequestMessage(method, $"http://127.0.0.1:{Port}{path}");
        if (token is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        if (host is not null)
        {
            request.Headers.Host = host;
        }
        return request;
    }

    private async Task RegisterEchoWorkflowAsync()
    {
        await _registry.RegisterWorkflowAsync(new WorkflowGraph(
            WorkflowId: "flow-gate-target",
            Name: "Gate Target",
            Description: "Reachable only with the token.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("echo", "Echo", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'ack'")
            },
            Edges: new List<WorkflowEdge>()));
    }

    [Fact]
    public void AListenerGivenNoToken_MintsOneRatherThanRunningOpen()
    {
        Assert.False(string.IsNullOrWhiteSpace(_listener.AuthToken));
        Assert.Equal(64, _listener.AuthToken.Length);
    }

    [Fact]
    public async Task AnUnauthenticatedCaller_CannotListWorkflows()
    {
        var response = await _client.SendAsync(Request(HttpMethod.Get, "/api/v1/workflows"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AnUnauthenticatedCaller_CannotExecuteAWorkflow()
    {
        await RegisterEchoWorkflowAsync();

        var request = Request(HttpMethod.Post, "/api/v1/workflows/flow-gate-target/execute");
        request.Content = new StringContent("{}", Encoding.UTF8, "application/json");

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain("success", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AnUnauthenticatedCaller_CannotFireAWebhook()
    {
        bool fired = false;
        _listener.RegisterWebhookHandler("flow-gate-target", _ => { fired = true; return Task.CompletedTask; });

        var request = Request(HttpMethod.Post, "/webhook/flow-gate-target");
        request.Content = new StringContent("{}", Encoding.UTF8, "application/json");

        var response = await _client.SendAsync(request);

        // Only /api/v1 was gated before, so this shorter path reached the same executor unchecked.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(fired, "the webhook handler must not run for an unauthenticated caller.");
    }

    [Fact]
    public async Task AWrongToken_IsRefused()
    {
        var response = await _client.SendAsync(
            Request(HttpMethod.Get, "/api/v1/workflows", token: new string('a', 64)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ARequestWithARebondHostHeader_IsRefusedEvenWithTheToken()
    {
        // DNS rebinding lets a page reach 127.0.0.1 under an attacker-chosen name. The Host header
        // is what survives that trip, so it is checked before the token is considered.
        var response = await _client.SendAsync(
            Request(HttpMethod.Get, "/api/v1/workflows", token: _listener.AuthToken, host: "evil.example.com"));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task TheCorrectToken_IsAccepted()
    {
        await RegisterEchoWorkflowAsync();

        var response = await _client.SendAsync(
            Request(HttpMethod.Get, "/api/v1/workflows", token: _listener.AuthToken));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("flow-gate-target", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task HealthStaysOpen_SoALivenessProbeNeedsNoSecret()
    {
        var response = await _client.SendAsync(Request(HttpMethod.Get, "/health"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("healthy", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task AnOversizedBody_IsRefusedBeforeItIsBuffered()
    {
        await RegisterEchoWorkflowAsync();

        var request = Request(HttpMethod.Post, "/api/v1/workflows/flow-gate-target/execute", token: _listener.AuthToken);
        request.Content = new StringContent(new string('x', 2 * 1024 * 1024), Encoding.UTF8, "application/json");

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    // ---------------------------------------------------------------- OAuth CSRF state

    private sealed class InMemoryVault : ICredentialVault
    {
        public readonly Dictionary<string, string> Secrets = new(StringComparer.OrdinalIgnoreCase);

        public Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default)
        {
            Secrets[key] = Encoding.UTF8.GetString(secretBytes);
            return Task.CompletedTask;
        }

        public Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default) =>
            Task.FromResult(Secrets.TryGetValue(key, out var v) ? Encoding.UTF8.GetBytes(v) : null);

        public Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default) =>
            Task.FromResult(Secrets.TryGetValue(key, out var v) ? v : null);

        public Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default)
        {
            Secrets[key] = secretString;
            return Task.CompletedTask;
        }

        public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            Secrets.Remove(key);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task AnOAuthCallbackWithTheWrongState_VaultsNothing()
    {
        var vault = new InMemoryVault();
        var coordinator = new OAuthCallbackCoordinator(_listener, vault);

        string state = OAuthCallbackCoordinator.NewState();
        coordinator.BuildAuthorizationUrl("tiktok", "https://example.test/auth", "client", new[] { "ads.read" }, state);

        // Arm the handler, then send the callback an attacker would craft: a real-looking code,
        // and a state SPLAT never issued.
        _ = coordinator.AwaitTokenAsync("tiktok", timeoutSeconds: 5);
        coordinator.BuildAuthorizationUrl("tiktok", "https://example.test/auth", "client", new[] { "ads.read" }, state);

        var forged = await _client.GetAsync(
            $"http://127.0.0.1:{Port}/oauth/callback/tiktok?code=ATTACKER_CODE&state=not-the-issued-state");

        Assert.Equal(HttpStatusCode.OK, forged.StatusCode);
        Assert.Contains("Refused", await forged.Content.ReadAsStringAsync());
        Assert.Empty(vault.Secrets);
    }

    [Fact]
    public async Task AnOAuthCallbackWithTheIssuedState_IsAccepted()
    {
        var vault = new InMemoryVault();
        var coordinator = new OAuthCallbackCoordinator(_listener, vault);

        string state = OAuthCallbackCoordinator.NewState();
        _ = coordinator.AwaitTokenAsync("tiktok", timeoutSeconds: 5);
        coordinator.BuildAuthorizationUrl("tiktok", "https://example.test/auth", "client", new[] { "ads.read" }, state);

        var accepted = await _client.GetAsync(
            $"http://127.0.0.1:{Port}/oauth/callback/tiktok?code=REAL_CODE&state={state}");

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Contains("Captured", await accepted.Content.ReadAsStringAsync());
        Assert.True(vault.Secrets.ContainsKey("oauth_token_tiktok"));

        // Single use: replaying the same callback finds nothing pending.
        vault.Secrets.Clear();
        var replay = await _client.GetAsync(
            $"http://127.0.0.1:{Port}/oauth/callback/tiktok?code=REAL_CODE&state={state}");

        Assert.Contains("Refused", await replay.Content.ReadAsStringAsync());
        Assert.Empty(vault.Secrets);
    }
}
