using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Network.Siem;

namespace MissionController.Tests;

public sealed class SiemTransportInvariantTests
{
    private static AuditLogEntry Entry => new(1, new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc),
        Guid.Empty, "template", "TEST", "hello", "operator", new string('a', 64), new string('0', 64));

    private static CefEvent Cef => new("vendor", "product", "1", "test", "name", 4,
        new Dictionary<string, string> { ["msg"] = "hello" });

    private static SiemConfiguration Endpoint(TcpListener listener, bool tls = true) =>
        new(tls ? SiemProtocol.SyslogTcpTls : SiemProtocol.Cef, "127.0.0.1",
            ((IPEndPoint)listener.LocalEndpoint).Port, tls);

    [Fact]
    public async Task UdpProbe_ReportsLocalSendOnly_AndRetainsOriginalEventTime()
    {
        using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var http = new HttpClient();
        var forwarder = new SiemForwarder(http);
        var config = new SiemConfiguration(SiemProtocol.SyslogUdp, "127.0.0.1",
            ((IPEndPoint)receiver.Client.LocalEndPoint!).Port, false);
        var check = await forwarder.ProbeConnectionAsync(config, timeout.Token);
        Assert.Equal(SiemConnectionEvidence.LocalDatagramSent, check.Evidence);
        Assert.Contains("not verified", check.Detail);
        await receiver.ReceiveAsync(timeout.Token);
        await forwarder.ForwardAuditEntryAsync(Entry, config, timeout.Token);
        string message = Encoding.UTF8.GetString((await receiver.ReceiveAsync(timeout.Token)).Buffer);
        Assert.Contains("2020-01-02T03:04:05.000000+00:00", message);
    }

    [Fact]
    public async Task TcpProbe_ExplicitlyReportsUnauthenticatedTransport()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var http = new HttpClient();
        var result = await new SiemForwarder(http).ProbeConnectionAsync(Endpoint(listener, false));
        using var peer = await listener.AcceptTcpClientAsync();
        Assert.Equal(SiemConnectionEvidence.TcpConnected, result.Evidence);
        Assert.Contains("without TLS", result.Detail);
        Assert.Contains("not verified", result.Detail);
    }

    [Fact]
    public async Task TlsProbe_StalledHandshakeDoesNotPassOnTcpConnect()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var http = new HttpClient();
        var probe = new SiemForwarder(http, operationTimeout: TimeSpan.FromMilliseconds(300))
            .ProbeConnectionAsync(Endpoint(listener));
        using var peer = await listener.AcceptTcpClientAsync();
        var result = await probe.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(result.Succeeded);
        Assert.Contains("timed out", result.Detail);
    }

    [Fact]
    public async Task TlsProbe_RejectsUntrustedCertificate()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(10));
        using var certificate = X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
        using var http = new HttpClient();
        var probe = new SiemForwarder(http).ProbeConnectionAsync(Endpoint(listener), timeout.Token);
        using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
        using var server = new SslStream(peer.GetStream(), false);
        var handshake = server.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate
        }, timeout.Token);
        var result = await probe;
        Assert.False(result.Succeeded);
        Assert.Contains("AuthenticationException", result.Detail);
        try { await handshake; }
        catch (Exception ex) when (ex is AuthenticationException or IOException) { }
    }

    [Fact]
    public async Task TlsProbe_CallerCancellationPropagates()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var http = new HttpClient();
        using var cancellation = new CancellationTokenSource();
        var probe = new SiemForwarder(http).ProbeConnectionAsync(Endpoint(listener), cancellation.Token);
        using var peer = await listener.AcceptTcpClientAsync();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);
    }

    [Fact]
    public async Task Forwarding_StalledTlsHandshakeIsBounded_AndSendsNoPlaintextEvent()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var http = new HttpClient();
        var sending = new SiemForwarder(http, operationTimeout: TimeSpan.FromMilliseconds(300))
            .ForwardAuditEntryAsync(Entry with { Details = "SENSITIVE_AUDIT_MARKER" }, Endpoint(listener));
        using var peer = await listener.AcceptTcpClientAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => sending.WaitAsync(TimeSpan.FromSeconds(5)));
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var wire = new MemoryStream();
        await peer.GetStream().CopyToAsync(wire, timeout.Token);
        Assert.DoesNotContain("SENSITIVE_AUDIT_MARKER", Encoding.UTF8.GetString(wire.ToArray()));
    }

    [Theory]
    [InlineData(SiemProtocol.SyslogTcpTls, false)]
    [InlineData(SiemProtocol.SyslogUdp, true)]
    [InlineData(SiemProtocol.MicrosoftSentinel, false)]
    [InlineData((SiemProtocol)999, true)]
    public async Task InvalidTransportConfigurationFailsInsteadOfDowngrading(SiemProtocol protocol, bool tls)
    {
        using var http = new HttpClient();
        var forwarder = new SiemForwarder(http);
        var config = new SiemConfiguration(protocol, "127.0.0.1", 1, tls);
        Assert.False((await forwarder.ProbeConnectionAsync(config)).Succeeded);
        await Assert.ThrowsAsync<ArgumentException>(() => forwarder.ForwardAuditEntryAsync(Entry, config));
        await Assert.ThrowsAsync<ArgumentException>(() => forwarder.ForwardCefEventAsync(Cef, config));
    }

    [Fact]
    public async Task Sentinel_CefCannotAccidentallyUseRawSocketPath()
    {
        using var http = new HttpClient();
        var config = new SiemConfiguration(SiemProtocol.MicrosoftSentinel, "ignored");
        await Assert.ThrowsAsync<ArgumentException>(() => new SiemForwarder(http).ForwardCefEventAsync(Cef, config));
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, SiemConnectionEvidence.IngestionApiAccepted)]
    [InlineData(HttpStatusCode.Forbidden, SiemConnectionEvidence.None)]
    [InlineData(HttpStatusCode.TooManyRequests, SiemConnectionEvidence.None)]
    public async Task Sentinel_ReportsOnlyApiAcceptance(HttpStatusCode status, SiemConnectionEvidence evidence)
    {
        using var handler = new SentinelHandler(status);
        using var http = new HttpClient(handler);
        var config = new SiemConfiguration(SiemProtocol.MicrosoftSentinel, "ignored", 443, true,
            Guid.Empty.ToString(), Convert.ToBase64String(new byte[32]));
        var result = await new SiemForwarder(http).ProbeConnectionAsync(config);
        Assert.Equal(evidence, result.Evidence);
        Assert.True(handler.SawAuthenticatedRequest);
        if (result.Succeeded) Assert.Contains("Indexing and retention are not verified", result.Detail);
    }

    [Fact]
    public void CefEscapesAllUntrustedFields_WithoutCreatingAnotherRecordOrExtension()
    {
        var value = Cef with
        {
            Name = "name|forged\r\nCEF:0|fake",
            ExtensionFields = new Dictionary<string, string> { ["msg"] = "path\\file=1\r\nsuser=admin|x" }
        };
        string formatted = SiemForwarder.FormatCef(value);
        Assert.Contains("name\\|forged\\r\\nCEF:0\\|fake", formatted);
        Assert.Contains("msg=path\\\\file\\=1\\r\\nsuser\\=admin|x", formatted);
        Assert.Equal(1, formatted.Count(c => c == '\n'));
        Assert.DoesNotContain('\r', formatted);
        Assert.Throws<ArgumentException>(() => SiemForwarder.FormatCef(Cef with
        {
            ExtensionFields = new Dictionary<string, string> { ["msg forged"] = "value" }
        }));
    }

    [Fact]
    public void SyslogRejectsHeaderInjection_AndFramesUtf8Octets()
    {
        var message = new SyslogMessage(1, 6, DateTimeOffset.UnixEpoch, "host", "app", "1", "TEST", "café\r\n<14>forged");
        string formatted = SiemForwarder.FormatRfc5424(message);
        Assert.Equal(1, formatted.Count(c => c == '\n'));
        Assert.Contains("café\\r\\n<14>forged", formatted);
        Assert.Throws<ArgumentException>(() => SiemForwarder.FormatRfc5424(message with { Hostname = "host\nforged" }));
        Assert.Throws<ArgumentException>(() => SiemForwarder.FormatRfc5424(message with
        {
            StructuredData = new Dictionary<string, IReadOnlyDictionary<string, string>>
            {
                ["bad]id"] = new Dictionary<string, string>()
            }
        }));
        Assert.Equal(Encoding.UTF8.GetBytes("5 café"), SiemForwarder.FrameSyslogTls("café\n"));
        Assert.Throws<ArgumentException>(() => SiemForwarder.FrameSyslogTls("\n"));
    }

    [Fact]
    public async Task CefForwarding_EscapesAuditDetailsExactlyOnce()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var http = new HttpClient();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var sending = new SiemForwarder(http).ForwardAuditEntryAsync(Entry with { Details = "a=b\\c" }, Endpoint(listener, false));
        using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
        using var reader = new StreamReader(peer.GetStream(), Encoding.UTF8);
        string? line = await reader.ReadLineAsync(timeout.Token);
        await sending;
        Assert.Contains("msg=a\\=b\\\\c", line);
    }

    private sealed class SentinelHandler(HttpStatusCode status) : HttpMessageHandler
    {
        public bool SawAuthenticatedRequest { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SawAuthenticatedRequest = request.RequestUri?.Scheme == "https"
                && request.RequestUri.Host == Guid.Empty + ".ods.opinsights.azure.com"
                && request.Headers.Contains("Authorization");
            return Task.FromResult(new HttpResponseMessage(status));
        }
    }
}
