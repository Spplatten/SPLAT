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
if (FalconCommands.TryRun(args) is { } checkResult) return checkResult;
if (args.Length is not (3 or 4))
{
    Console.Error.WriteLine("Usage: splat-alert-sidecar <admission-binding.json> <mailbox.sqlite> <https-certificate.pfx> [approved-falcon-profile.json]");
    Console.Error.WriteLine("Proof: --verify-cancellation <expectation.json> <task.json>; --inspect-pilot-context <context.json>");
    Console.Error.WriteLine("Pilot: --run-falcon-pilot <plan.json> <binding.json> <profile.json> <event.json> <new-output-directory>");
    Console.Error.WriteLine("Offline: --check-falcon-pilot <plan.json> <binding.json> <profile.json> <event.json>");
    return 2;
}
try
{
    using var bindingDocument = StrictJson.Parse(ConfigurationFiles.Read(args[0]));
    var binding = bindingDocument.RootElement.Deserialize<Binding>(Binding.Json)
        ?? throw new InvalidDataException("Missing binding");
    binding.Check(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    var falcon = args.Length == 4 ? new FalconAdapter(binding,ConfigurationFiles.Read(args[3])) : null;
    if (binding.Falcon != null && falcon == null)
        throw new InvalidDataException("Falcon identity requires its pinned profile; normalized-mode downgrade refused.");
    byte[] token = Convert.FromBase64String(Credentials.Required("SPLAT_ALERT_TOKEN"));
    if (token.Length != 32) throw new InvalidDataException("SPLAT_ALERT_TOKEN must encode 32 random bytes.");
    byte[] authDigest = Credentials.Digest("Bearer " + Convert.ToBase64String(token));
    CryptographicOperations.ZeroMemory(token);
    string callerToken = Credentials.Required("SPLAT_A2A_CALLER_TOKEN");
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
    using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(5) };
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
    using var ingress = new AlertIngress(binding,latch,authDigest,falcon);
    app.MapPost(ingress.Path,ingress.HandleAsync);
    using var stop = new CancellationTokenSource();
    var controller = control.RunAsync(latch, stop.Token);
    var exporter = Control.ExportAsync(client, binding, latch, stop.Token);
    // A crashed worker must stop intake. Otherwise the listener could acknowledge signals that
    // no live actuator will service. Restart replays a pending row; no secret is written to disk.
    var serving = app.RunAsync();
    try { await await Task.WhenAny(serving, controller, exporter); }
    finally { stop.Cancel(); await app.StopAsync(); await Task.WhenAll(controller, exporter); }
    return 0;
}
catch (Exception ex)
{
    // Avoid credential/URL/alert disclosure through exception messages in service logs.
    Console.Error.WriteLine("Alert sidecar stopped: " + ex.GetType().Name);
    return 1;
}
