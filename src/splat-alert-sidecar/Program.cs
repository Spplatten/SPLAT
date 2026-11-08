using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Data.Sqlite;
using Splat.AlertSidecar;

if (args.Length == 1 && args[0] == "--self-test") return SelfTest.Run();
if (args.Length == 3 && args[0] == "--self-test-witness-wire") return await WitnessWireChecks.RunAsync(args[1], args[2]);
if (await FalconPilot.TryRunAsync(args) is { } pilotResult) return pilotResult;
if (await PilotOrchestrator.TryRunAsync(args) is { } orchestrated) return orchestrated;
if (FalconCommands.TryRun(args) is { } checkResult) return checkResult;
if (FalcoAdapter.TryRun(args) is { } falcoResult) return falcoResult;
if (args.Length is not (3 or 4))
{
    Console.Error.WriteLine("Usage: splat-alert-sidecar <admission-binding.json> <mailbox.sqlite> <https-certificate.pfx> [approved-falcon-profile.json]");
    Console.Error.WriteLine("Proof: --verify-cancellation <expectation.json> <task.json>; --inspect-pilot-context <context.json>");
    Console.Error.WriteLine("Pilot: --run-falcon-pilot <plan.json> <binding.json> <profile.json> <event.json> <new-output-directory>");
    Console.Error.WriteLine("Offline: --check-falcon-pilot <plan.json> <binding.json> <profile.json> <event.json>");
    Console.Error.WriteLine("Option B: --orchestrate-cancellation-pilot <request.json> <new-run-directory>");
    Console.Error.WriteLine("Falco: --check-falco-event <binding.json> <event.json>");
    return 2;
}
try
{
    using var bindingDocument = StrictJson.Parse(ConfigurationFiles.Read(args[0]));
    var binding = bindingDocument.RootElement.Deserialize<Binding>(Binding.Json)
        ?? throw new InvalidDataException("Missing binding");
    string callerToken = Credentials.Required("SPLAT_A2A_CALLER_TOKEN");
    using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(5) };
    if (binding.Falco is { } scope)
    {
        // Resolved once, before anything listens, so the mailbox, its fingerprint and every match
        // use SPLAT's answer. A pin in the file that disagrees with it stops the sidecar here.
        using var resolving = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        string lease = await new Control(client, binding, callerToken).LeaseCgroupAsync(resolving.Token);
        if (scope.LeaseCgroup is { } pinned && pinned != lease) throw new InvalidDataException("Pinned lease cgroup differs from SPLAT's.");
        binding = binding with { Falco = scope with { LeaseCgroup = lease } };
    }
    binding.Check(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    if (binding.Falco != null && args.Length == 4) throw new InvalidDataException("A Falco binding takes no Falcon profile.");
    var falcon = args.Length == 4 ? new FalconAdapter(binding,ConfigurationFiles.Read(args[3])) : null;
    if (binding.Falcon != null && falcon == null)
        throw new InvalidDataException("Falcon identity requires its pinned profile; normalized-mode downgrade refused.");
    var falco = binding.Falco != null ? new FalcoAdapter(binding) : null;
    byte[] token = Convert.FromBase64String(Credentials.Required("SPLAT_ALERT_TOKEN"));
    if (token.Length != 32) throw new InvalidDataException("SPLAT_ALERT_TOKEN must encode 32 random bytes.");
    byte[] authDigest = Credentials.Digest("Bearer " + Convert.ToBase64String(token));
    CryptographicOperations.ZeroMemory(token);
    using var certificate = X509CertificateLoader.LoadPkcs12FromFile(args[2],
        Environment.GetEnvironmentVariable("SPLAT_ALERT_CERT_PASSWORD"),
        OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
    if (!certificate.HasPrivateKey || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow
        || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow) throw new InvalidDataException("Invalid HTTPS certificate");
    string mailbox = Path.GetFullPath(args[1]);
    // One worker owns this binding, including across processes. Protect the binding, mailbox and
    // lock directory with operator ACLs; this is not protection from the machine administrator.
    using var owner = new FileStream(mailbox + ".owner", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    var latch = new Latch(mailbox, binding.Fingerprint);
    var control = new Control(client, binding, callerToken);
    var builder = WebApplication.CreateSlimBuilder();
    builder.Configuration.Sources.Clear(); builder.Logging.ClearProviders();
    builder.WebHost.ConfigureKestrel(k => {
        k.AddServerHeader = false; k.Limits.MaxRequestBodySize = 16384;
        k.Limits.MaxConcurrentConnections = 16; k.Limits.MaxRequestHeadersTotalSize = 8192;
        k.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
        k.Listen(IPAddress.Loopback, binding.ListenPort, o => { o.Protocols = HttpProtocols.Http1; o.UseHttps(certificate); });
    });
    await using var app = builder.Build();
    using var ingress = new AlertIngress(binding,latch,authDigest,falcon,falco);
    app.MapPost(ingress.Path,ingress.HandleAsync);
    using var stop = new CancellationTokenSource();
    var workers = new List<Task> { control.RunAsync(latch, stop.Token), Control.ExportAsync(client, binding, latch, stop.Token) };
    if (falco != null) workers.Add(falco.WatchAsync(latch, stop.Token));
    // A crashed worker must stop intake. Otherwise the listener could acknowledge signals that
    // no live actuator will service. Restart replays a pending row; no secret is written to disk.
    var serving = app.RunAsync();
    try { await await Task.WhenAny(workers.Append(serving)); }
    finally { stop.Cancel(); await app.StopAsync(); await Task.WhenAll(workers); }
    return 0;
}
catch (Exception ex)
{
    // Avoid credential/URL/alert disclosure through exception messages in service logs.
    Console.Error.WriteLine("Alert sidecar stopped: " + ex.GetType().Name);
    return 1;
}
