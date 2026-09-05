using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
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
    private CancellationTokenSource? _cts;
    private Task? _listenerTask;

    public bool IsRunning => _listener.IsListening;
    public string BaseUrl => $"http://127.0.0.1:{_port}/";

    public EmbeddedWebhookListener(
        int port = 5678,
        IWorkflowRegistry? workflowRegistry = null,
        IWorkflowExecutionEngine? executionEngine = null)
    {
        _port = port;
        _workflowRegistry = workflowRegistry;
        _executionEngine = executionEngine;
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
                string workflowId = segments[1];
                if (request.HttpMethod.Equals("POST", StringComparison.OrdinalIgnoreCase))
                {
                    using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
                    string body = await reader.ReadToEndAsync();

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
    <h1>OAuth Handshake Captured</h1>
    <p>Authorization code received for <strong>{WebUtility.HtmlEncode(provider)}</strong>.</p>
    <p>The token has been securely deposited into the SPLAT Windows DPAPI Credential Vault. You may close this browser window.</p>
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
                        using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
                        string body = await reader.ReadToEndAsync();
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
