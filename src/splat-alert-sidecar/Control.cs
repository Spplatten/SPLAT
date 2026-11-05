using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Splat.AlertSidecar;

internal sealed class Control(HttpClient client, Binding binding, string token)
{
    internal const string Extension = "urn:splat:a2a:template-lease:v1";
    private async Task<JsonElement> Call(string method, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"https://127.0.0.1:{binding.A2aPort}/a2a");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Headers.Add("A2A-Version", "1.0"); request.Headers.Add("A2A-Extensions", Extension);
        // The target is immutable operator input. No event field is interpolated into method,
        // credentials, URI or task ID. This adapter has no mint/renew/policy-widening operation.
        request.Content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = "alert-cancel",
            method, @params = new { id = binding.TaskId, historyLength = 0 } }), Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        // A compromised/misconfigured peer must not make this cold worker consume unbounded RAM.
        byte[] buffer = new byte[1_048_577]; int count = 0, read;
        while ((read = await stream.ReadAsync(buffer.AsMemory(count), ct)) != 0)
        {
            count += read;
            if (count > 1_048_576) throw new InvalidDataException("Control response too large");
        }
        using var document = JsonDocument.Parse(buffer.AsMemory(0,count), new JsonDocumentOptions { MaxDepth = 32 });
        var root = document.RootElement;
        if (root.TryGetProperty("error", out _) || root.GetProperty("jsonrpc").GetString() != "2.0"
            || root.GetProperty("id").GetString() != "alert-cancel")
            throw new InvalidDataException("Control RPC rejected");
        var task = root.GetProperty("result");
        if (task.GetProperty("id").GetString() != binding.TaskId) throw new InvalidDataException("Wrong control target");
        return task.Clone();
    }
    internal static string? Outcome(JsonElement task)
    {
        string? state = task.GetProperty("status").GetProperty("state").GetString();
        if (state is not ("TASK_STATE_CANCELED" or "TASK_STATE_COMPLETED" or "TASK_STATE_FAILED" or "TASK_STATE_REJECTED")) return null;
        var evidence = task.GetProperty("metadata").GetProperty(Extension);
        return evidence.TryGetProperty("workloadTerminationConfirmed", out var drained) && drained.ValueKind == JsonValueKind.True
            ? "host-reports-drain" : "terminal-without-drain-proof";
        // This is the authenticated host's report, not independent verification of its signed
        // native receipt. Persist/export that distinction. A task state alone is never a kill.
    }
    // A Falco binding watches the cgroup SPLAT says the task runs in. A finished task has nothing left
    // to revoke, and a cgroup SPLAT does not name cannot be bound by guesswork.
    internal static string LeaseCgroup(JsonElement task)
    {
        if (Outcome(task) != null) throw new InvalidDataException("The task is already terminal.");
        return task.GetProperty("metadata").GetProperty(Extension).TryGetProperty("leaseCgroup", out var path)
            && path.ValueKind == JsonValueKind.String ? path.GetString()! : throw new InvalidDataException("SPLAT reports no lease cgroup.");
    }
    internal async Task<string> LeaseCgroupAsync(CancellationToken ct) => LeaseCgroup(await Call("GetTask", ct));
    internal async Task RunAsync(Latch latch, CancellationToken ct)
    {
        int failures = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                if (latch.Read().State == "pending")
                {
                    if (DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() >= binding.ExpiresUnixMs)
                        latch.Finish("expired-unresolved"); // Native expiry remains the enforcement authority.
                    else try
                    {
                        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
                        deadline.CancelAfter(TimeSpan.FromSeconds(8));
                        // Recovery polls BEFORE cancel: a lost HTTP response does not prove that
                        // the request failed. The native task UUID survives sidecar restarts.
                        var task = await Call("GetTask", deadline.Token);
                        string? outcome = Outcome(task);
                        if (outcome == null)
                        {
                            var metadata = task.GetProperty("metadata").GetProperty(Extension);
                            bool requested = metadata.TryGetProperty("cancellationRequested", out var flag) && flag.ValueKind == JsonValueKind.True;
                            if (!requested) task = await Call("CancelTask", deadline.Token);
                            outcome = Outcome(task);
                        }
                        if (outcome != null) latch.Finish(outcome);
                        failures = 0;
                    }
                    catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or IOException
                        or JsonException or KeyNotFoundException or InvalidOperationException or OperationCanceledException)
                    {
                        failures = Math.Min(failures + 1, 6);
                        // Leave durable state pending. In particular, 401/timeout is not a drain.
                    }
                }
                await Task.Delay(TimeSpan.FromMilliseconds(Math.Min(5000, 25 * (1 << failures))), ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }
    internal static async Task ExportAsync(HttpClient client, Binding binding, Latch latch, CancellationToken ct)
    {
        string? endpoint = Environment.GetEnvironmentVariable("SPLAT_LOGSCALE_INGEST_URL");
        if (endpoint == null) { try { await Task.Delay(Timeout.Infinite, ct); } catch (OperationCanceledException) { } return; }
        var uri = new Uri(endpoint);
        if (uri.Scheme != "https" || uri.UserInfo != "" || uri.Query != "" || uri.Fragment != ""
            || !uri.AbsolutePath.EndsWith("/api/v1/ingest/humio-structured", StringComparison.Ordinal))
            throw new InvalidDataException("Configure the exact HTTPS LogScale structured ingest URL.");
        string ingestToken = Credentials.Required("SPLAT_LOGSCALE_INGEST_TOKEN");
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var row = latch.Read();
                if (!row.Reported && row.State is not ("idle" or "pending"))
                {
                    try
                    {
                        using var request = new HttpRequestMessage(HttpMethod.Post, uri);
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ingestToken);
                        // Stable identity allows receiver-side deduplication if HTTP acceptance
                        // succeeds and the process dies before MarkReported. Never claim exactly-once.
                        var body = new[] { new { tags = new { source = "splat-alert-sidecar" }, events = new[] { new {
                            timestamp = DateTimeOffset.FromUnixTimeMilliseconds(row.Received).ToString("O", CultureInfo.InvariantCulture),
                            attributes = new Dictionary<string,string> {
                                ["splat.task_id"] = binding.TaskId, ["splat.binding"] = binding.Fingerprint,
                                ["splat.outcome"] = row.State, ["sensor.alert_id"] = row.Alert ?? "",
                                ["splat.record_id"] = binding.TaskId + ":" + row.State
                            } } } } };
                        request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
                        using var response = await client.SendAsync(request, ct);
                        // LogScale documents only HTTP 200 as committed to its ingestion queue.
                        // A different 2xx must not consume the durable export record.
                        if (response.StatusCode == System.Net.HttpStatusCode.OK) latch.MarkReported();
                    }
                    catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or OperationCanceledException) { }
                }
                await Task.Delay(TimeSpan.FromSeconds(5), ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }
}
