using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Network.Egress;

namespace MissionController.Infrastructure.Network.Siem;

public sealed class SiemForwarder : ISiemForwarder
{
    /// <summary>
    /// Microsoft Sentinel's ingestion domain. The workspace id is operator-supplied and gets
    /// interpolated into the hostname, so it is validated against this suffix before a request is
    /// built - otherwise a workspace id containing path or host separators redirects the entire
    /// audit ledger to an attacker-chosen domain.
    /// </summary>
    private const string SentinelIngestionSuffix = ".ods.opinsights.azure.com";

    private readonly HttpClient _httpClient;
    private readonly EgressFirewallHandler? _firewallHandler;
    private readonly TimeSpan _operationTimeout;

    public SiemForwarder(HttpClient httpClient, EgressFirewallHandler? firewallHandler = null,
        TimeSpan? operationTimeout = null)
    {
        _httpClient = httpClient;
        _firewallHandler = firewallHandler;
        _operationTimeout = operationTimeout ?? TimeSpan.FromSeconds(5);
        if (_operationTimeout <= TimeSpan.Zero || _operationTimeout > TimeSpan.FromMinutes(5))
            throw new ArgumentOutOfRangeException(nameof(operationTimeout));
    }

    public async Task ForwardAuditEntryAsync(AuditLogEntry entry, SiemConfiguration config, CancellationToken cancellationToken = default)
    {
        ValidateConfiguration(config);
        using var deadline = CreateDeadline(cancellationToken);
        cancellationToken = deadline.Token;
        switch (config.Protocol)
        {
            case SiemProtocol.SyslogUdp:
            case SiemProtocol.SyslogTcpTls:
                var syslogMsg = CreateSyslogMessage(entry, config);
                string formattedSyslog = FormatRfc5424(syslogMsg);
                await SendSyslogNetworkAsync(formattedSyslog, config, cancellationToken);
                break;

            case SiemProtocol.Cef:
                var cefEvent = CreateCefEvent(entry);
                string formattedCef = FormatCef(cefEvent);
                await SendSyslogNetworkAsync(formattedCef, config, cancellationToken);
                break;

            case SiemProtocol.MicrosoftSentinel:
                await SendMicrosoftSentinelAsync(entry, config, cancellationToken);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(config));
        }
    }

    public async Task ForwardCefEventAsync(CefEvent cefEvent, SiemConfiguration config, CancellationToken cancellationToken = default)
    {
        ValidateConfiguration(config);
        if (config.Protocol == SiemProtocol.MicrosoftSentinel)
            throw new ArgumentException("Use ForwardAuditEntryAsync for Sentinel REST ingestion.", nameof(config));
        using var deadline = CreateDeadline(cancellationToken);
        string formattedCef = FormatCef(cefEvent);
        await SendSyslogNetworkAsync(formattedCef, config, deadline.Token);
    }

    /// <summary>Compatibility API: true means the probe completed, not that an event was retained.</summary>
    public async Task<bool> TestConnectionAsync(SiemConfiguration config, CancellationToken cancellationToken = default)
        => (await ProbeConnectionAsync(config, cancellationToken)).Succeeded;

    public async Task<SiemConnectionCheck> ProbeConnectionAsync(SiemConfiguration config, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CreateDeadline(cancellationToken);
        try
        {
            ValidateConfiguration(config);
            if (config.Protocol == SiemProtocol.MicrosoftSentinel)
            {
                var testEntry = new AuditLogEntry(
                    0, DateTime.UtcNow, Guid.NewGuid(), "TEST_CONN", "PING", "HealthCheck Connection Test", "SYSTEM", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000");
                await SendMicrosoftSentinelAsync(testEntry, config, deadline.Token);
                return new(SiemConnectionEvidence.IngestionApiAccepted,
                    "Sentinel ingestion API accepted the authenticated test request. Indexing and retention are not verified.");
            }

            if (config.Protocol == SiemProtocol.SyslogUdp)
            {
                using var udp = new UdpClient();
                byte[] ping = Encoding.UTF8.GetBytes("<14>1 " + DateTime.UtcNow.ToString("O") + " localhost MissionController - - - PING\n");
                await udp.SendAsync(ping, config.HostOrUrl, config.Port, deadline.Token);
                return new(SiemConnectionEvidence.LocalDatagramSent,
                    "UDP datagram submitted locally. Receiver reachability, receipt and retention are not verified.");
            }

            if (config.Protocol == SiemProtocol.SyslogTcpTls || config.Protocol == SiemProtocol.Cef)
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(config.HostOrUrl, config.Port, deadline.Token);
                if (config.UseTls)
                {
                    using var ssl = new SslStream(tcp.GetStream(), false);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = config.HostOrUrl
                    }, deadline.Token);
                    return new(SiemConnectionEvidence.TlsAuthenticated,
                        "TLS handshake and server certificate validation succeeded. Event ingestion and retention are not verified.");
                }
                return new(SiemConnectionEvidence.TcpConnected,
                    "TCP connection established without TLS. Event ingestion and retention are not verified.");
            }

            return new(SiemConnectionEvidence.None, "Unsupported SIEM protocol.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new(SiemConnectionEvidence.None, "SIEM probe timed out before completing the configured transport check.");
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or SecurityException
            or IOException or SocketException or System.Security.Authentication.AuthenticationException
            or HttpRequestException or FormatException)
        {
            // Exception messages can contain endpoint details or credential material; expose only the category.
            return new(SiemConnectionEvidence.None, $"SIEM probe failed ({ex.GetType().Name}); no successful delivery claim.");
        }
    }

    private CancellationTokenSource CreateDeadline(CancellationToken cancellationToken)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(_operationTimeout);
        return deadline;
    }

    private static void ValidateConfiguration(SiemConfiguration config)
    {
        ArgumentNullException.ThrowIfNull(config);
        if (!Enum.IsDefined(config.Protocol))
            throw new ArgumentException("Unsupported SIEM protocol.", nameof(config));
        if (config.Protocol == SiemProtocol.SyslogUdp && config.UseTls)
            throw new ArgumentException("UDP syslog does not provide TLS; select a TLS transport or explicitly disable TLS.", nameof(config));
        if ((config.Protocol == SiemProtocol.SyslogTcpTls || config.Protocol == SiemProtocol.MicrosoftSentinel) && !config.UseTls)
            throw new ArgumentException("The selected SIEM protocol requires TLS.", nameof(config));
        if (config.Protocol != SiemProtocol.MicrosoftSentinel &&
            (string.IsNullOrWhiteSpace(config.HostOrUrl) || config.Port < 1 || config.Port > 65535))
            throw new ArgumentException("A host and valid port are required.", nameof(config));
    }

    private static SyslogMessage CreateSyslogMessage(AuditLogEntry entry, SiemConfiguration config)
    {
        var structuredData = new Dictionary<string, IReadOnlyDictionary<string, string>>
        {
            ["mission@32473"] = new Dictionary<string, string>
            {
                ["id"] = entry.MissionId.ToString("D"),
                ["template"] = entry.TemplateId,
                ["operator"] = entry.OperatorIdentity,
                ["hash"] = entry.EntryHash
            }
        };

        return new SyslogMessage(
            Facility: config.Facility,
            Severity: config.DefaultSeverity,
            Timestamp: new DateTimeOffset(DateTime.SpecifyKind(entry.TimestampUtc, DateTimeKind.Utc)),
            Hostname: Environment.MachineName.ToLowerInvariant(),
            AppName: "MissionController",
            ProcessId: Environment.ProcessId.ToString(),
            MessageId: entry.Action,
            Message: entry.Details,
            StructuredData: structuredData);
    }

    private static CefEvent CreateCefEvent(AuditLogEntry entry)
    {
        int severity = entry.Action.Contains("ALERT", StringComparison.OrdinalIgnoreCase) ? 8 : 4;
        var ext = new Dictionary<string, string>
        {
            ["cs1"] = entry.TemplateId,
            ["cs1Label"] = "TemplateId",
            ["cs2"] = entry.MissionId.ToString("D"),
            ["cs2Label"] = "MissionId",
            ["suser"] = entry.OperatorIdentity,
            ["msg"] = entry.Details,
            ["deviceCustomDate1"] = entry.TimestampUtc.ToString("O"),
            ["deviceCustomDate1Label"] = "AuditTimestamp",
            ["externalId"] = entry.EntryHash
        };

        return new CefEvent(
            DeviceVendor: "EnterpriseIT",
            DeviceProduct: "MissionController",
            DeviceVersion: "2.0",
            DeviceEventClassId: entry.Action,
            Name: entry.Action,
            Severity: severity,
            ExtensionFields: ext);
    }

    public static string FormatRfc5424(SyslogMessage msg)
    {
        if (msg.Facility is < 0 or > 23 || msg.Severity is < 0 or > 7)
            throw new ArgumentException("Invalid syslog facility or severity.", nameof(msg));
        int pri = (msg.Facility * 8) + msg.Severity;
        string timestamp = msg.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
        string hostname = HeaderToken(msg.Hostname, 255);
        string appName = HeaderToken(msg.AppName, 48);
        string procId = HeaderToken(msg.ProcessId, 128);
        string msgId = HeaderToken(msg.MessageId, 32);

        var sdBuilder = new StringBuilder();
        if (msg.StructuredData != null && msg.StructuredData.Count > 0)
        {
            foreach (var (sdId, parameters) in msg.StructuredData)
            {
                ValidateStructuredName(sdId);
                sdBuilder.Append($"[{sdId}");
                foreach (var (k, v) in parameters)
                {
                    ValidateStructuredName(k);
                    string escapedVal = EscapeLines(v.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]"));
                    sdBuilder.Append($" {k}=\"{escapedVal}\"");
                }
                sdBuilder.Append(']');
            }
        }
        else
        {
            sdBuilder.Append('-');
        }

        return $"<{pri}>1 {timestamp} {hostname} {appName} {procId} {msgId} {sdBuilder} {EscapeLines(msg.Message)}\n";
    }

    public static string FormatCef(CefEvent cef)
    {
        if (cef.Severity is < 0 or > 10)
            throw new ArgumentException("CEF severity must be between 0 and 10.", nameof(cef));
        var extSb = new StringBuilder();
        foreach (var (k, v) in cef.ExtensionFields)
        {
            if (string.IsNullOrEmpty(k) || !System.Linq.Enumerable.All(k, char.IsAsciiLetterOrDigit))
                throw new ArgumentException("CEF extension keys must be ASCII letters or digits.", nameof(cef));
            extSb.Append($"{k}={EscapeLines(v.Replace("\\", "\\\\").Replace("=", "\\="))} ");
        }

        string rawExtensions = extSb.ToString().TrimEnd();
        return $"CEF:0|{CefHeader(cef.DeviceVendor)}|{CefHeader(cef.DeviceProduct)}|{CefHeader(cef.DeviceVersion)}|{CefHeader(cef.DeviceEventClassId)}|{CefHeader(cef.Name)}|{cef.Severity}|{rawExtensions}\n";
    }

    private static string EscapeLines(string value) => value.Replace("\r", "\\r").Replace("\n", "\\n");
    private static string CefHeader(string value) => EscapeLines(value.Replace("\\", "\\\\").Replace("|", "\\|"));

    private static string HeaderToken(string value, int maxLength)
    {
        if (string.IsNullOrEmpty(value)) return "-";
        if (value.Length > maxLength || System.Linq.Enumerable.Any(value, c => c < '!' || c > '~'))
            throw new ArgumentException("Invalid syslog header token.");
        return value;
    }

    private static void ValidateStructuredName(string value)
    {
        if (string.IsNullOrEmpty(value)) throw new ArgumentException("Empty syslog structured-data name.");
        HeaderToken(value, 32);
        if (value.IndexOfAny(['=', ']', '"']) >= 0)
            throw new ArgumentException("Invalid syslog structured-data name.");
    }

    /// <summary>Octet-counted TLS framing; removes the formatter's single LF terminator.</summary>
    public static byte[] FrameSyslogTls(string payload)
    {
        string message = payload.EndsWith('\n') ? payload[..^1] : payload;
        byte[] body = Encoding.UTF8.GetBytes(message);
        if (body.Length == 0) throw new ArgumentException("Empty syslog message.", nameof(payload));
        byte[] prefix = Encoding.ASCII.GetBytes(body.Length.ToString(CultureInfo.InvariantCulture) + " ");
        var frame = new byte[prefix.Length + body.Length];
        prefix.CopyTo(frame, 0);
        body.CopyTo(frame, prefix.Length);
        return frame;
    }

    private static async Task SendSyslogNetworkAsync(string payload, SiemConfiguration config, CancellationToken cancellationToken)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(payload);

        if (config.Protocol == SiemProtocol.SyslogUdp)
        {
            using var udp = new UdpClient();
            await udp.SendAsync(bytes, config.HostOrUrl, config.Port, cancellationToken);
            return;
        }

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(config.HostOrUrl, config.Port, cancellationToken);
        await using Stream stream = config.UseTls
            ? new SslStream(tcp.GetStream(), false)
            : tcp.GetStream();

        if (config.UseTls && stream is SslStream ssl)
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = config.HostOrUrl
            }, cancellationToken);
        }

        // RFC 5425 requires octet counting. CEF keeps its single-line framing for existing receivers.
        if (config.Protocol == SiemProtocol.SyslogTcpTls)
        {
            bytes = FrameSyslogTls(payload);
        }
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private async Task SendMicrosoftSentinelAsync(AuditLogEntry entry, SiemConfiguration config, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(config.WorkspaceId) || string.IsNullOrWhiteSpace(config.SharedKey))
        {
            throw new InvalidOperationException("Microsoft Sentinel requires WorkspaceId and SharedKey.");
        }

        var payloadObj = new[]
        {
            new
            {
                TimeGenerated = entry.TimestampUtc.ToString("O"),
                EntryId = entry.Id,
                MissionId = entry.MissionId.ToString("D"),
                TemplateId = entry.TemplateId,
                Action = entry.Action,
                Details = entry.Details,
                OperatorIdentity = entry.OperatorIdentity,
                EntryHash = entry.EntryHash,
                PreviousHash = entry.PreviousHash,
                SourceHost = Environment.MachineName
            }
        };

        string jsonPayload = JsonSerializer.Serialize(payloadObj);
        byte[] jsonBytes = Encoding.UTF8.GetBytes(jsonPayload);

        string dateString = DateTime.UtcNow.ToString("r", CultureInfo.InvariantCulture);
        string authSignature = BuildSentinelAuthSignature(config.WorkspaceId, config.SharedKey, jsonBytes.Length, dateString);

        string sentinelHost = BuildSentinelHost(config.WorkspaceId);
        string endpoint = $"https://{sentinelHost}/api/logs?api-version=2016-04-01";
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Add("Log-Type", config.LogType);
        request.Headers.Add("x-ms-date", dateString);
        request.Headers.Add("Authorization", authSignature);
        request.Content = new ByteArrayContent(jsonBytes);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

        // Declare the destination so the Layer-4 firewall can enforce it. Without a scope the
        // hardened client now refuses the send outright, which is the intended behaviour: audit
        // records are the most sensitive payload this app transmits and must never leave on an
        // undeclared route.
        using var scope = _firewallHandler?.BeginScope(sentinelHost);

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Builds and validates the Sentinel ingestion host from an operator-supplied workspace id.
    ///
    /// The id used to be interpolated straight into the URL, so a value carrying a '/', '@', ':' or
    /// '.' - for example "x.attacker.example.com/api/logs?j=" - moved the request's real host off
    /// Azure entirely and shipped the tamper-evident audit ledger to whoever owned that domain. A
    /// GUID is the only shape Sentinel ever issues, so anything else is rejected here rather than
    /// being handed to the URI parser to interpret.
    /// </summary>
    public static string BuildSentinelHost(string? workspaceId)
    {
        if (string.IsNullOrWhiteSpace(workspaceId) || !Guid.TryParse(workspaceId, out _))
        {
            throw new SecurityException(
                "Microsoft Sentinel forwarding blocked: WorkspaceId must be a GUID. " +
                "A workspace id containing host or path separators would redirect audit records off Azure.");
        }

        return workspaceId + SentinelIngestionSuffix;
    }

    public static string BuildSentinelAuthSignature(string workspaceId, string sharedKey, int contentLength, string dateString)
    {
        string stringToHash = $"POST\n{contentLength}\napplication/json\nx-ms-date:{dateString}\n/api/logs";
        byte[] keyBytes = Convert.FromBase64String(sharedKey);
        using var hmac = new HMACSHA256(keyBytes);
        byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToHash));
        string signature = Convert.ToBase64String(hash);
        return $"SharedKey {workspaceId}:{signature}";
    }
}
