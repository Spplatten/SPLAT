using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Workflow;

namespace MissionController.Infrastructure.Network.Triggers;

public sealed class EmbeddedWebhookListener : IDisposable
{
    private readonly int _port;
    private readonly HttpListener _listener;
    private readonly ConcurrentDictionary<string, Func<IReadOnlyDictionary<string, string>, Task>> _webhookHandlers;
    private readonly ConcurrentDictionary<string, Func<string, string, Task<bool>>> _oauthHandlers;
    private readonly IWorkflowRegistry? _workflowRegistry;
    private readonly IWorkflowExecutionEngine? _executionEngine;
    private readonly string _apiToken;
    private CancellationTokenSource? _cts;
    private Task? _listenerTask;

    public bool IsRunning => _listener.IsListening;
    public string BaseUrl => $"http://127.0.0.1:{_port}/";

    /// <summary>
    /// The bearer token every gated route requires. Read it to configure a client; it is minted per
    /// process unless one was supplied, and it is never written to a log or a response body.
    /// </summary>
    public string AuthToken => _apiToken;

    public EmbeddedWebhookListener(
        int port = 5678,
        IWorkflowRegistry? workflowRegistry = null,
        IWorkflowExecutionEngine? executionEngine = null,
        string? apiToken = null)
    {
        _port = port;
        _workflowRegistry = workflowRegistry;
        _executionEngine = executionEngine;
        // Fail closed by construction. A caller-supplied token wins, then the environment, and
        // failing both the listener mints its own - so there is no configuration in which this
        // endpoint answers an unauthenticated caller.
        string? configured = apiToken ?? Environment.GetEnvironmentVariable("SPLAT_API_KEY");
        _apiToken = string.IsNullOrWhiteSpace(configured)
            ? Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()
            : configured;
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
        _webhookHandlers = new ConcurrentDictionary<string, Func<IReadOnlyDictionary<string, string>, Task>>(StringComparer.OrdinalIgnoreCase);
        _oauthHandlers = new ConcurrentDictionary<string, Func<string, string, Task<bool>>>(StringComparer.OrdinalIgnoreCase);
    }

    public void RegisterWebhookHandler(string workflowId, Func<IReadOnlyDictionary<string, string>, Task> handler)
    {
        _webhookHandlers[workflowId] = handler;
    }

    public void RegisterOAuthHandler(string provider, Func<string, string, Task<bool>> handler)
    {
        _oauthHandlers[provider] = handler;
    }

    public void Start()
    {
        if (_listener.IsListening) return;

        try
        {
            _listener.Start();
            _cts = new CancellationTokenSource();
            _listenerTask = Task.Run(() => ListenLoopAsync(_cts.Token));
        }
        catch (HttpListenerException)
        {
            // Port might be in use or unauthorized on restricted machines
        }
    }

    public void Stop()
    {
        if (!_listener.IsListening) return;

        _cts?.Cancel();
        try
        {
            _listener.Stop();
        }
        catch { }
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener.IsListening)
        {
            try
            {
                var context = await _listener.GetContextAsync();
                _ = Task.Run(() => HandleRequestAsync(context), ct);
            }
            catch (HttpListenerException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception)
            {
                // Continue listening
            }
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context)
    {
        var request = context.Request;
        var response = context.Response;

        try
        {
            var rawPath = request.Url?.AbsolutePath.Trim('/') ?? string.Empty;
            var segments = rawPath.Split('/', StringSplitOptions.RemoveEmptyEntries);

            // 1. Health check: GET / or GET /health
            if (segments.Length == 0 || (segments.Length == 1 && segments[0].Equals("health", StringComparison.OrdinalIgnoreCase)))
            {
                await WriteJsonResponseAsync(response, 200, new { status = "healthy", server = "SPLAT Flow Trigger Engine", port = _port });
                return;
            }

            // 2. Webhook Route: POST /webhook/{workflowId}
            if (segments.Length >= 2 && segments[0].Equals("webhook", StringComparison.OrdinalIgnoreCase))
            {
                // This route runs a registered workflow, exactly as /api/v1/.../execute does, so it
                // carries the same gate. Only /api/v1 was checked before, which left the shorter
                // path an unauthenticated way to reach the same executor.
                if (!IsAuthorized(request))
                {
                    await WriteUnauthorizedAsync(response);
                    return;
                }

                string workflowId = segments[1];
                if (request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
                {
                    string? body = await ReadBoundedBodyAsync(request, response);
                    if (body is null) return;

                    var payload = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        { "body", body },
                        { "contentType", request.ContentType ?? "text/plain" },
                        { "timestamp", DateTime.UtcNow.ToString("o") }
                    };

                    if (_webhookHandlers.TryGetValue(workflowId, out var handler))
                    {
                        await handler(payload);
                        await WriteJsonResponseAsync(response, 200, new { status = "accepted", workflowId, timestamp = DateTime.UtcNow });
                    }
                    else
                    {
                        await WriteJsonResponseAsync(response, 404, new { error = "Workflow webhook not registered", workflowId });
                    }
                    return;
                }
            }

            // 3. OAuth Callback Route: GET /oauth/callback/{provider}
            if (segments.Length >= 3 &&
                segments[0].Equals("oauth", StringComparison.OrdinalIgnoreCase) &&
                segments[1].Equals("callback", StringComparison.OrdinalIgnoreCase))
            {
                string provider = segments[2];
                string code = request.QueryString["code"] ?? string.Empty;
                string state = request.QueryString["state"] ?? string.Empty;

                bool handled = false;
                if (!string.IsNullOrEmpty(code) && _oauthHandlers.TryGetValue(provider, out var oauthHandler))
                {
                    handled = await oauthHandler(code, state);
                }

                string html = $@"<!doctype html>
<html>
<head>
  <meta charset='utf-8'>
  <title>SPLAT OAuth Handshake</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B1220; color: #F4F7FB; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
    .card {{ background: #111B2E; border: 1px solid #263853; border-radius: 8px; padding: 2rem 3rem; text-align: center; max-width: 480px; box-shadow: 0 18px 50px rgba(0,0,0,0.5); }}
    h1 {{ color: #4CC2FF; font-size: 1.5rem; margin-top: 0; }}
    p {{ color: #A9B7CA; line-height: 1.5; }}
    .badge {{ display: inline-block; background: rgba(76,194,255,0.1); border: 1px solid #4CC2FF; color: #4CC2FF; border-radius: 4px; padding: 0.3rem 0.6rem; font-size: 0.8rem; margin-top: 1rem; }}
  </style>
</head>
<body>
  <div class='card'>
    <h1>{(handled ? "OAuth Handshake Captured" : "OAuth Handshake Refused")}</h1>
    <p>Callback received for <strong>{WebUtility.HtmlEncode(provider)}</strong>.</p>
    <p>{(handled
        ? "The token has been deposited into the SPLAT Windows DPAPI Credential Vault. You may close this browser window."
        : "Nothing was vaulted: no handler was waiting for this provider, or the callback did not match the request SPLAT issued. You may close this browser window.")}</p>
    <div class='badge'>SPLAT Zero-Trust Governance Active</div>
  </div>
</body>
</html>";

                byte[] htmlBytes = Encoding.UTF8.GetBytes(html);
                response.ContentType = "text/html; charset=utf-8";
                response.ContentLength64 = htmlBytes.Length;
                response.StatusCode = 200;
                await response.OutputStream.WriteAsync(htmlBytes);
                response.OutputStream.Close();
                return;
            }

            // 4. REST API Gateway: /api/v1/...
            if (segments.Length >= 2 &&
                segments[0].Equals("api", StringComparison.OrdinalIgnoreCase) &&
                segments[1].Equals("v1", StringComparison.OrdinalIgnoreCase))
            {
                if (!IsAuthorized(request))
                {
                    await WriteUnauthorizedAsync(response);
                    return;
                }

                // GET /api/v1/health or GET /api/v1/status
                if (segments.Length == 3 && (segments[2].Equals("health", StringComparison.OrdinalIgnoreCase) || segments[2].Equals("status", StringComparison.OrdinalIgnoreCase)))
                {
                    await WriteJsonResponseAsync(response, 200, new
                    {
                        status = "healthy",
                        version = "1.0.0",
                        authenticated = true,
                        substrate = "SPLAT Zero-Trust Execution Engine",
                        platform = Environment.OSVersion.Platform.ToString(),
                        port = _port,
                        timestamp = DateTime.UtcNow
                    });
                    return;
                }

                // POST /api/v1/execute
                if (segments.Length == 3 && segments[2].Equals("execute", StringComparison.OrdinalIgnoreCase))
                {
                    if (request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
                    {
                        string? body = await ReadBoundedBodyAsync(request, response);
                        if (body is null) return;
                        using var jsonDoc = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
                        var root = jsonDoc.RootElement;

                        string command = root.TryGetProperty("command", out var cmd) ? cmd.GetString() ?? "" : "";
                        string runtime = root.TryGetProperty("runtime", out var rt) ? rt.GetString() ?? "powershell" : "powershell";
                        string workflowId = root.TryGetProperty("workflowId", out var wId) ? wId.GetString() ?? "" : "";

                        if (!string.IsNullOrEmpty(command) && _executionEngine != null)
                        {
                            var dynamicNode = new WorkflowNode(
                                NodeId: "cmd-exec",
                                Name: "Direct REST Command Execution",
                                NodeType: WorkflowNodeType.SandboxedScript,
                                Configuration: new Dictionary<string, string> { { "Runtime", runtime } },
                                ScriptCommand: command);

                            var dynamicGraph = new WorkflowGraph(
                                WorkflowId: $"dyn-{Guid.NewGuid():N}",
                                Name: "Ad-Hoc REST Command Execution",
                                Description: "Direct execution via authenticated REST API",
                                Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
                                Nodes: new List<WorkflowNode> { dynamicNode },
                                Edges: new List<WorkflowEdge>());

                            var result = await _executionEngine.ExecuteAsync(dynamicGraph, new Dictionary<string, string>(), "RestApiGateway");
                            string outText = result.NodeOutputs.TryGetValue("cmd-exec", out var val) ? val : string.Empty;
                            await WriteJsonResponseAsync(response, result.Success ? 200 : 500, new
                            {
                                success = result.Success,
                                executionId = result.ExecutionId,
                                command,
                                runtime,
                                output = outText,
                                logs = result.ExecutionLogs,
                                failureReason = result.FailureReason
                            });
                            return;
                        }

                        if (!string.IsNullOrEmpty(workflowId) && _workflowRegistry != null && _executionEngine != null)
                        {
                            var workflow = await _workflowRegistry.GetWorkflowByIdAsync(workflowId);
                            if (workflow != null)
                            {
                                var payload = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                                if (root.TryGetProperty("payload", out var plElem) && plElem.ValueKind == JsonValueKind.Object)
                                {
                                    foreach (var prop in plElem.EnumerateObject())
                                    {
                                        payload[prop.Name] = prop.Value.ToString();
                                    }
                                }
                                var result = await _executionEngine.ExecuteAsync(workflow, payload, "RestApiGateway");
                                await WriteJsonResponseAsync(response, result.Success ? 200 : 500, new
                                {
                                    workflowId = result.WorkflowId,
                                    executionId = result.ExecutionId,
                                    success = result.Success,
                                    nodeOutputs = result.NodeOutputs,
                                    logs = result.ExecutionLogs,
                                    failureReason = result.FailureReason
                                });
                                return;
                            }
                        }

                        await WriteJsonResponseAsync(response, 400, new { error = "Request body must include either 'command' or 'workflowId'." });
                        return;
                    }
                }

                // GET /api/v1/workflows
                if (segments.Length == 3 && segments[2].Equals("workflows", StringComparison.OrdinalIgnoreCase))
                {
                    if (request.HttpMethod.Equals("GET", StringComparison.OrdinalIgnoreCase))
                    {
                        if (_workflowRegistry != null)
                        {
                            var workflows = await _workflowRegistry.GetAllWorkflowsAsync();
                            var summary = new List<object>();
                            foreach (var w in workflows)
                            {
                                summary.Add(new
                                {
                                    id = w.WorkflowId,
                                    name = w.Name,
                                    description = w.Description,
                                    triggerType = w.Trigger.Type.ToString(),
                                    nodeCount = w.Nodes.Count,
                                    edgeCount = w.Edges.Count
                                });
                            }
                            await WriteJsonResponseAsync(response, 200, new { workflows = summary });
                        }
                        else
                        {
                            await WriteJsonResponseAsync(response, 200, new { workflows = Array.Empty<object>() });
                        }
                        return;
                    }
                }

                // POST /api/v1/workflows/{id}/execute
                if (segments.Length == 5 &&
                    segments[2].Equals("workflows", StringComparison.OrdinalIgnoreCase) &&
                    segments[4].Equals("execute", StringComparison.OrdinalIgnoreCase))
                {
                    string workflowId = segments[3];
                    if (request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
                    {
                        string? body = await ReadBoundedBodyAsync(request, response);
                        if (body is null) return;
                        var payload = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        try
                        {
                            if (!string.IsNullOrWhiteSpace(body) && body.TrimStart().StartsWith("{"))
                            {
                                using var jsonDoc = JsonDocument.Parse(body);
                                foreach (var prop in jsonDoc.RootElement.EnumerateObject())
                                {
                                    payload[prop.Name] = prop.Value.ToString();
                                }
                            }
                            else if (!string.IsNullOrWhiteSpace(body))
                            {
                                payload["body"] = body;
                            }
                        }
                        catch
                        {
                            payload["raw"] = body;
                        }

                        if (_workflowRegistry != null && _executionEngine != null)
                        {
                            var workflow = await _workflowRegistry.GetWorkflowByIdAsync(workflowId);
                            if (workflow != null)
                            {
                                var result = await _executionEngine.ExecuteAsync(workflow, payload, "RestApiGateway");
                                await WriteJsonResponseAsync(response, result.Success ? 200 : 500, new
                                {
                                    workflowId = result.WorkflowId,
                                    executionId = result.ExecutionId,
                                    success = result.Success,
                                    nodeOutputs = result.NodeOutputs,
                                    logs = result.ExecutionLogs,
                                    failureReason = result.FailureReason
                                });
                                return;
                            }
                        }

                        // Check if a webhook handler was registered for this workflow
                        if (_webhookHandlers.TryGetValue(workflowId, out var customHandler))
                        {
                            await customHandler(payload);
                            await WriteJsonResponseAsync(response, 200, new
                            {
                                workflowId,
                                status = "executed_via_handler",
                                timestamp = DateTime.UtcNow
                            });
                            return;
                        }

                        await WriteJsonResponseAsync(response, 404, new { error = "Workflow not found", workflowId });
                        return;
                    }
                }
            }

            await WriteJsonResponseAsync(response, 404, new { error = "Route not found" });
        }
        catch (Exception ex)
        {
            try
            {
                await WriteJsonResponseAsync(response, 500, new { error = ex.Message });
            }
            catch { }
        }
    }

    /// <summary>
    /// Gate for every route that can read or run something.
    ///
    /// There is no unauthenticated mode. An earlier version returned true when no token was
    /// configured, which meant a host that had not set SPLAT_API_KEY - the default - was exactly as
    /// open as before the gate existed, while the test asserting a 401 for a wrong token still
    /// passed. <see cref="AuthToken"/> is minted at construction when none is supplied, so "no
    /// token configured" is not a reachable state.
    /// </summary>
    private bool IsAuthorized(HttpListenerRequest request)
    {
        // A browser can be pointed at 127.0.0.1 by any page the operator loads, and DNS rebinding
        // makes the target name attacker-chosen. Requiring the loopback literal in Host means a
        // rebound name reaches the listener and is refused before the token is even considered.
        string host = request.Headers["Host"] ?? string.Empty;
        if (!host.Equals($"127.0.0.1:{_port}", StringComparison.OrdinalIgnoreCase) &&
            !host.Equals($"localhost:{_port}", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string authHeader = request.Headers["Authorization"] ?? string.Empty;
        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) &&
            TokenMatches(authHeader.Substring("Bearer ".Length).Trim()))
        {
            return true;
        }

        return TokenMatches(request.Headers["X-SPLAT-API-KEY"] ?? string.Empty);
    }

    /// <summary>
    /// Fixed-time comparison. <c>string.Equals</c> returns at the first differing character, which
    /// over a loopback socket a local process can time well enough to recover the token byte by
    /// byte - and a local process is exactly the caller this gate exists to stop.
    /// </summary>
    private bool TokenMatches(string presented)
    {
        if (string.IsNullOrEmpty(presented))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(presented),
            Encoding.UTF8.GetBytes(_apiToken));
    }

    private static Task WriteUnauthorizedAsync(HttpListenerResponse response) =>
        WriteJsonResponseAsync(response, 401, new
        {
            error = "Unauthorized: invalid or missing SPLAT API authorization token.",
            detail = "Supply 'Authorization: Bearer <token>' or 'X-SPLAT-API-KEY: <token>', from EmbeddedWebhookListener.AuthToken."
        });

    /// <summary>
    /// Cap on a trigger body, in bytes. HttpListener will otherwise stream whatever a caller sends
    /// straight into a string; an unauthenticated request could exhaust memory before the gate above
    /// it even ran, and an authenticated one has no business posting a gigabyte of trigger payload.
    /// Returns null when the request was refused, having already written the response.
    /// </summary>
    private const long MaxRequestBodyBytes = 1 * 1024 * 1024;

    private static async Task<string?> ReadBoundedBodyAsync(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (request.ContentLength64 > MaxRequestBodyBytes)
        {
            await WriteJsonResponseAsync(response, 413, new
            {
                error = "Request body too large.",
                maxBytes = MaxRequestBodyBytes
            });
            return null;
        }

        // A chunked request declares no length, so the read itself is bounded rather than trusted.
        var buffer = new char[8192];
        var builder = new StringBuilder();
        using var reader = new StreamReader(request.InputStream, request.ContentEncoding);

        int read;
        while ((read = await reader.ReadAsync(buffer, 0, buffer.Length)) > 0)
        {
            builder.Append(buffer, 0, read);
            if (builder.Length > MaxRequestBodyBytes)
            {
                await WriteJsonResponseAsync(response, 413, new
                {
                    error = "Request body exceeded the limit while streaming.",
                    maxBytes = MaxRequestBodyBytes
                });
                return null;
            }
        }

        return builder.ToString();
    }

    private static async Task WriteJsonResponseAsync(HttpListenerResponse response, int statusCode, object data)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(data));
        response.StatusCode = statusCode;
        response.ContentType = "application/json";
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes);
        response.OutputStream.Close();
    }

    public void Dispose()
    {
        Stop();
        try
        {
            _listener.Close();
        }
        catch { }
        _cts?.Dispose();
    }
}
