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
    private readonly TrustedAdmissionRegistrar? _registrar;
    private readonly SemaphoreSlim _admissions = new(4);
    internal string Path => _falcon is null ? "/v1/alerts" : "/v1/falcon/alerts";
    internal AlertIngress(Binding binding,Latch latch,byte[] authDigest,FalconAdapter? falcon=null,
        TrustedAdmissionRegistrar? registrar=null)
    {
        if (authDigest.Length != 32 || (binding.Falcon != null) != (falcon != null)
            || latch.BindingFingerprint != binding.Fingerprint)
            throw new InvalidDataException("Binding, adapter mode and authentication must agree.");
        _binding=binding; _latch=latch; _authDigest=(byte[])authDigest.Clone(); _falcon=falcon;
        if (registrar != null && (falcon == null || !registrar.MatchesBinding(binding)))
            throw new InvalidDataException("Registrar and fixed task/mailbox binding disagree.");
        _registrar=registrar;
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
        if (!_admissions.Wait(0)) { http.Response.StatusCode=429; return; }
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
            if (_registrar != null)
            {
                var observation=_falcon!.Observe(doc.RootElement);
                if (!_registrar.AdmitToMailbox(Guid.ParseExact(_binding.TaskId,"N"),observation,_latch))
                { http.Response.StatusCode=409; return; }
            }
            else
            {
                var alert=_falcon is null ? doc.RootElement.Deserialize<Alert>(Binding.Json) : _falcon.Normalize(doc.RootElement,now);
                if (alert == null || !_binding.Matches(alert,now)) { http.Response.StatusCode=409; return; }
                _latch.Admit(alert.AlertId,alert.ObservedUnixMs,now);
            }
            // Commit before acknowledgement. Only a validated event can reach the mailbox. Raw
            // provider payloads are never persisted here, exported or passed to native enforcement.
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
