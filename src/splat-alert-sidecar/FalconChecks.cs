using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO.Pipelines;
using Microsoft.Data.Sqlite;

namespace Splat.AlertSidecar;

internal static class FalconChecks
{
    internal static async Task RunAsync(string directory,Action<bool> check)
    {
        // Synthetic contract fixtures, NOT a representation of a captured live tenant stream.
        // Paths are deliberately configured rather than assumed to match all Falcon products.
        long now=DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var profile=new FalconProfile(1,"EppDetectionSummaryEvent","/metadata/eventType",
            "/metadata/customerIDString","/event/agent","/event/processInstanceId","/event/rule",
            "/event/id","/metadata/eventTime","unix-ms");
        byte[] bytes=JsonSerializer.SerializeToUtf8Bytes(profile,Binding.Json);
        string hash=Convert.ToHexString(SHA256.HashData(bytes));
        var identity=new FalconIdentity("tenant-1","agent-1","18446744073709551615",now-5000,hash);
        var binding=new Binding(Guid.NewGuid().ToString("N"),"node",Guid.NewGuid(),123,77,9000,
            "falcon","test-rule",now+120000,19443,19444,identity);
        binding.Check(now);
        var adapter=new FalconAdapter(binding,bytes);
        byte[] Event(string tenant="tenant-1",string agent="agent-1",string process="18446744073709551615",
            string type="EppDetectionSummaryEvent",string rule="test-rule",long? timestamp=null) =>
            JsonSerializer.SerializeToUtf8Bytes(new { metadata=new { eventType=type,customerIDString=tenant,eventTime=timestamp??now },
                @event=new { agent,processInstanceId=process,rule,id="detection-1",untrustedTaskId="not-the-target" } });
        Alert Normalize(byte[] data) { using var d=StrictJson.Parse(data); return adapter.Normalize(d.RootElement,now); }
        void Refused(Action action)
        {
            bool rejected=false;
            try { action(); } catch (Exception ex) when (ex is InvalidDataException or JsonException) { rejected=true; }
            check(rejected);
        }
        var normalized=Normalize(Event());
        check(binding.Matches(normalized,now));
        check(normalized.Pid==77 && normalized.StartTicks==9000 && normalized.Boot==binding.Boot);
        Refused(()=>Normalize(Event(tenant:"other")));
        Refused(()=>Normalize(Event(agent:"other")));
        Refused(()=>Normalize(Event(process:"77"))); // OS PID cannot replace a vendor process-instance key.
        Refused(()=>Normalize(Event(type:"DetectionSummaryEvent")));
        Refused(()=>Normalize(Event(rule:"other")));
        Refused(()=>Normalize(Event(timestamp:now-5001))); // Still fresh, but before this admission.
        Refused(()=>Normalize(Event(timestamp:now+2001)));
        Refused(()=>new FalconAdapter(binding,bytes.Concat(new byte[]{32}).ToArray()));
        Refused(()=>new FalconAdapter(binding with { Falcon=null },bytes));
        Refused(()=>new AlertIngress(binding,new Latch(System.IO.Path.Combine(directory,"missing-adapter.sqlite"),binding.Fingerprint),new byte[32]));
        Refused(()=>StrictJson.Parse(Encoding.UTF8.GetBytes("{\"event\":{\"agent\":\"good\",\"agent\":\"bad\"}}")));
        Refused(()=>StrictJson.Parse(Encoding.UTF8.GetBytes("[]")));
        Refused(()=>Normalize(Encoding.UTF8.GetBytes("{}")));
        var numeric=Encoding.UTF8.GetString(Event()).Replace("\"18446744073709551615\"","18446744073709551615",StringComparison.Ordinal);
        check(Normalize(Encoding.UTF8.GetBytes(numeric)).AlertId=="detection-1");
        Refused(()=>Normalize(Encoding.UTF8.GetBytes(numeric.Replace("18446744073709551615","1.8446744073709552E19",StringComparison.Ordinal))));
        Refused(()=>new FalconProfile(1,"event","/x","/x","/a","/p","/r","/i","/t","unix-ms").Check());
        Refused(()=>JsonPointer.Check("/bad~2escape"));
        using (var escaped=StrictJson.Parse(Encoding.UTF8.GetBytes("{\"a/b\":{\"~c\":\"exact\"}}")))
            check(JsonPointer.Read(escaped.RootElement,"/a~1b/~0c").GetString()=="exact");
        using (var seconds=JsonDocument.Parse("1800000000"))
            check(FalconAdapter.Timestamp(seconds.RootElement,"unix-s")==1800000000000);
        using (var overflow=JsonDocument.Parse("9223372036854775807"))
            Refused(()=>FalconAdapter.Timestamp(overflow.RootElement,"unix-s"));
        using (var iso=JsonDocument.Parse("\"2026-11-04T12:00:00Z\""))
            check(FalconAdapter.Timestamp(iso.RootElement,"iso8601")==new DateTimeOffset(2026,11,4,12,0,0,TimeSpan.Zero).ToUnixTimeMilliseconds());
        using (var noZone=JsonDocument.Parse("\"2026-11-04T12:00:00\""))
            Refused(()=>FalconAdapter.Timestamp(noZone.RootElement,"iso8601"));

        // Fixed independent value from the pre-Falcon binding contract. Old mailbox identities
        // must not change simply because an optional vendor adapter was added to the executable.
        var legacy=new Binding("00112233445566778899aabbccddeeff","node",Guid.Parse("11111111-2222-3333-4444-555555555555"),
            123,77,9000,"falco","rule",1800000000000,19443,19444);
        check(legacy.Fingerprint=="CCB3242586DAB22EFE3F0F8B3FAA4FD32678C0B7371A419C3607BF1FA0213643");
        check(binding.Fingerprint!=(binding with { Falcon=identity with { ProcessInstanceId="other" } }).Fingerprint);

        // Execute the real ingress handler over ASP.NET's request/response streams and real SQLite.
        // This verifies validation-to-mailbox behavior, not Kestrel sockets or a TLS handshake.
        using var services=new ServiceCollection().AddOptions().BuildServiceProvider();
        string auth="Bearer "+Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var mailbox=new Latch(System.IO.Path.Combine(directory,"http.sqlite"),binding.Fingerprint);
        using var ingress=new AlertIngress(binding,mailbox,Credentials.Digest(auth),adapter);
        async Task<(int Status,string Body)> Send(byte[] body,string? authorization=null,string? path=null,
            string? origin=null,string? contentType=null,string scheme="https",string? encoding=null)
        {
            var http=new DefaultHttpContext { RequestServices=services };
            http.Request.Scheme=scheme; http.Request.Method="POST"; http.Request.Path=path??ingress.Path;
            http.Request.Host=new HostString("127.0.0.1",binding.ListenPort);
            http.Request.ContentType=contentType??"application/json";
            http.Request.Headers.Authorization=authorization??auth;
            if (origin!=null) http.Request.Headers.Origin=origin;
            if (encoding!=null) http.Request.Headers.ContentEncoding=encoding;
            using var input=new MemoryStream(body); using var output=new MemoryStream();
            http.Request.Body=input; http.Response.Body=output;
            await ingress.HandleAsync(http);
            return (http.Response.StatusCode,Encoding.UTF8.GetString(output.ToArray()));
        }
        check((await Send(Event(),authorization:"Bearer wrong")).Status==401);
        check((await Send(Event(),scheme:"http")).Status==401);
        check((await Send(Event(),origin:"https://example.invalid")).Status==401);
        check((await Send(Event(),contentType:"text/plain")).Status==415);
        check((await Send(Event(),encoding:"gzip")).Status==415);
        check((await Send(new byte[16385])).Status==413);
        check((await Send(Encoding.UTF8.GetBytes("{}"))).Status==400);
        check((await Send(Event(tenant:"other"))).Status==409);
        check((await Send(Event(),path:"/v1/alerts")).Status==404);
        check(mailbox.Read().State=="idle");
        using (var abort=new CancellationTokenSource())
        {
            var pipes=new List<Pipe>(); var requests=new List<Task>(); var bodies=new List<Stream>();
            try
            {
                for (int i=0;i<4;i++)
                {
                    var pipe=new Pipe(); pipes.Add(pipe);
                    var stream=pipe.Reader.AsStream(leaveOpen:true); bodies.Add(stream);
                    var slow=new DefaultHttpContext { RequestServices=services,RequestAborted=abort.Token };
                    slow.Request.Scheme="https"; slow.Request.Method="POST"; slow.Request.Path=ingress.Path;
                    slow.Request.Host=new HostString("127.0.0.1",binding.ListenPort);
                    slow.Request.ContentType="application/json"; slow.Request.Headers.Authorization=auth;
                    slow.Request.Body=stream;
                    requests.Add(ingress.HandleAsync(slow)); // Real pipe read remains pending without a body.
                }
                check((await Send(Event())).Status==429);
                check(mailbox.Read().State=="idle");
            }
            finally
            {
                abort.Cancel(); await Task.WhenAll(requests);
                foreach (var stream in bodies) stream.Dispose();
                foreach (var pipe in pipes) { await pipe.Writer.CompleteAsync(); await pipe.Reader.CompleteAsync(); }
            }
        }
        var accepted=await Send(Event());
        check(accepted.Status==202);
        using (var response=JsonDocument.Parse(accepted.Body))
        {
            check(response.RootElement.GetProperty("taskId").GetString()==binding.TaskId);
            check(response.RootElement.GetProperty("meaning").GetString()!.Contains("not confirmed",StringComparison.Ordinal));
        }
        check(new Latch(System.IO.Path.Combine(directory,"http.sqlite"),binding.Fingerprint).Read().State=="pending");
        check((await Send(Event())).Status==202);
        check(mailbox.Read().Alert=="detection-1");
        using (var corrupt=new SqliteConnection(new SqliteConnectionStringBuilder {
            DataSource=System.IO.Path.Combine(directory,"http.sqlite"),Pooling=false }.ToString()))
        {
            corrupt.Open(); using var delete=corrupt.CreateCommand();
            delete.CommandText="DELETE FROM latch WHERE slot=1"; delete.ExecuteNonQuery();
        }
        check((await Send(Event())).Status==503); // A vanished row is never a successful duplicate.

        var oldMailbox=new Latch(System.IO.Path.Combine(directory,"legacy-http.sqlite"),legacy.Fingerprint);
        using var oldIngress=new AlertIngress(legacy,oldMailbox,Credentials.Digest(auth));
        var oldEvent=new Alert(1,"falco","old-client","rule",legacy.Node,legacy.Boot,123,77,9000,now);
        var oldHttp=new DefaultHttpContext { RequestServices=services };
        oldHttp.Request.Scheme="https"; oldHttp.Request.Method="POST"; oldHttp.Request.Path="/v1/alerts";
        oldHttp.Request.Host=new HostString("127.0.0.1",19443); oldHttp.Request.Headers.Authorization=auth;
        oldHttp.Request.ContentType="application/json";
        using var oldBody=new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(oldEvent,Binding.Json));
        using var oldResponse=new MemoryStream(); oldHttp.Request.Body=oldBody; oldHttp.Response.Body=oldResponse;
        await oldIngress.HandleAsync(oldHttp);
        check(oldHttp.Response.StatusCode==202 && oldMailbox.Read().Alert=="old-client");
        Console.WriteLine("PASS Falcon parser, actual HTTP handler/SQLite admission, pressure recovery and legacy compatibility checks.");
    }
}
