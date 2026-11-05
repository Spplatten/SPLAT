using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace Splat.AlertSidecar;

// Separate the HTTP boundary from process startup so the real handler can be exercised without
// opening a listening socket. This is the exact handler registered with Kestrel, not a test shim.
internal sealed class AlertIngress : IDisposable
{
    private readonly Binding _binding;
    private readonly Latch _latch;
    private readonly byte[] _authDigest;
    private readonly FalconAdapter? _falcon;
    private readonly FalcoAdapter? _falco;
    private readonly SemaphoreSlim _admissions = new(4);
    internal string Path => _falcon != null ? "/v1/falcon/alerts" : _falco != null ? "/v1/falco/alerts" : "/v1/alerts";
    internal AlertIngress(Binding binding,Latch latch,byte[] authDigest,FalconAdapter? falcon=null,FalcoAdapter? falco=null)
    {
        if (authDigest.Length != 32 || (binding.Falcon != null) != (falcon != null) || (binding.Falco != null) != (falco != null))
            throw new InvalidDataException("Binding, adapter mode and authentication must agree.");
        _binding=binding; _latch=latch; _authDigest=(byte[])authDigest.Clone(); _falcon=falcon; _falco=falco;
    }
    internal async Task HandleAsync(HttpContext http)
    {
        http.Response.Headers.CacheControl="no-store";
        if (!http.Request.IsHttps || http.Request.Host.Host != "127.0.0.1" || http.Request.Host.Port != _binding.ListenPort
            || http.Request.Headers.ContainsKey("Origin") || http.Request.Headers.Authorization.Count != 1
            || !CryptographicOperations.FixedTimeEquals(_authDigest,Credentials.Digest(http.Request.Headers.Authorization.ToString())))
        { http.Response.StatusCode=401; return; }
        // A Falcon-bound process must not also expose the weaker normalized route with its token.
        if (http.Request.Path != Path) { http.Response.StatusCode=404; return; }
        if (http.Request.Method != "POST") { http.Response.StatusCode=405; return; }
        if (http.Request.ContentType?.Split(';')[0].Trim() != "application/json" || http.Request.Headers.ContainsKey("Content-Encoding"))
        { http.Response.StatusCode=415; return; }
        // A node-wide sensor sends bursts. A second of queueing turns a burst into latency where an
        // immediate refusal turned it into a lost alert; past Kestrel's 16 connections the sender is
        // refused before this runs, which no handler can observe.
        bool slot;
        try { slot=await _admissions.WaitAsync(TimeSpan.FromSeconds(1),http.RequestAborted); }
        catch (OperationCanceledException) { return; }
        if (!slot)
        {
            http.Response.StatusCode=429;
            // An authenticated event turned away unread may have been this lease's. Fail-closed means
            // treating that like a sensor drop.
            if (_falco?.FailClosed == true && DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() is var at && at < _binding.ExpiresUnixMs)
                try { _latch.Admit("sidecar-saturated",at,at); } catch (Exception ex) when (ex is SqliteException or IOException) { http.Response.StatusCode=503; }
            return;
        }
        byte[] bytes=ArrayPool<byte>.Shared.Rent(16385);
        try
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(http.RequestAborted);
            deadline.CancelAfter(TimeSpan.FromSeconds(3));
            int used=0,n;
            while ((n=await http.Request.Body.ReadAsync(bytes.AsMemory(used,16385-used),deadline.Token)) != 0)
            {
                used+=n;
                if (used>16384) { http.Response.StatusCode=413; return; }
            }
            using var doc=StrictJson.Parse(bytes.AsMemory(0,used));
            long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string? id; long observed;
            if (_falco != null) (id,observed)=_falco.Classify(doc.RootElement,now);
            else
            {
                var alert=_falcon is null ? doc.RootElement.Deserialize<Alert>(Binding.Json) : _falcon.Normalize(doc.RootElement,now);
                if (alert == null || !_binding.Matches(alert,now)) { http.Response.StatusCode=409; return; }
                (id,observed)=(alert.AlertId,alert.ObservedUnixMs);
            }
            // Authentic traffic about other leases, nodes and rules is a shared sensor's normal case.
            if (id == null) { http.Response.StatusCode=204; return; }
            // Commit before acknowledgement. Only a validated event can reach the mailbox. Raw
            // provider payloads are never persisted here, exported or passed to native enforcement.
            _latch.Admit(id,observed,now);
            http.Response.StatusCode=202;
            await http.Response.WriteAsJsonAsync(new { accepted=true,taskId=_binding.TaskId,
                meaning="Cancellation signal persisted; workload termination is not confirmed." },http.RequestAborted);
        }
        catch (JsonException) { http.Response.StatusCode=400; }
        catch (InvalidDataException) { http.Response.StatusCode=409; }
        catch (Microsoft.AspNetCore.Http.BadHttpRequestException ex) { http.Response.StatusCode=ex.StatusCode; }
        catch (OperationCanceledException) { if (!http.RequestAborted.IsCancellationRequested) http.Response.StatusCode=408; }
        catch (Exception ex) when (ex is SqliteException or IOException) { http.Response.StatusCode=503; }
        finally { ArrayPool<byte>.Shared.Return(bytes,clearArray:true); _admissions.Release(); }
    }
    public void Dispose() { _admissions.Dispose(); CryptographicOperations.ZeroMemory(_authDigest); }
}
