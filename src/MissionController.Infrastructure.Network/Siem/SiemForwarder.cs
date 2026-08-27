using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Network.Siem;

public sealed class SiemForwarder : ISiemForwarder
{
    private readonly HttpClient _httpClient;

    public SiemForwarder(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task ForwardAuditEntryAsync(AuditLogEntry entry, SiemConfiguration config, CancellationToken cancellationToken = default)
    {
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
        }
    }

    public async Task ForwardCefEventAsync(CefEvent cefEvent, SiemConfiguration config, CancellationToken cancellationToken = default)
    {
        string formattedCef = FormatCef(cefEvent);
        await SendSyslogNetworkAsync(formattedCef, config, cancellationToken);
    }

    public async Task<bool> TestConnectionAsync(SiemConfiguration config, CancellationToken cancellationToken = default)
    {
        try
        {
            if (config.Protocol == SiemProtocol.MicrosoftSentinel)
            {
                if (string.IsNullOrWhiteSpace(config.WorkspaceId) || string.IsNullOrWhiteSpace(config.SharedKey))
                {
                    return false;
                }
                var testEntry = new AuditLogEntry(
                    0, DateTime.UtcNow, Guid.NewGuid(), "TEST_CONN", "PING", "HealthCheck Connection Test", "SYSTEM", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000");
                await SendMicrosoftSentinelAsync(testEntry, config, cancellationToken);
                return true;
            }

            if (config.Protocol == SiemProtocol.SyslogUdp)
            {
                using var udp = new UdpClient();
                byte[] ping = Encoding.UTF8.GetBytes("<14>1 " + DateTime.UtcNow.ToString("O") + " localhost MissionController - - - PING\n");
                await udp.SendAsync(ping, ping.Length, config.HostOrUrl, config.Port);
                return true;
            }

            if (config.Protocol == SiemProtocol.SyslogTcpTls || config.Protocol == SiemProtocol.Cef)
            {
                using var tcp = new TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                cts.CancelAfter(5000);
                await tcp.ConnectAsync(config.HostOrUrl, config.Port, cts.Token);
                return tcp.Connected;
            }

            return false;
        }
        catch
        {
            return false;
        }
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
            Timestamp: DateTimeOffset.UtcNow,
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
            ["msg"] = entry.Details.Replace("|", "\\|").Replace("=", "\\="),
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
        int pri = (msg.Facility * 8) + msg.Severity;
        string timestamp = msg.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.ffffffzzz", CultureInfo.InvariantCulture);
        string hostname = string.IsNullOrWhiteSpace(msg.Hostname) ? "-" : msg.Hostname;
        string appName = string.IsNullOrWhiteSpace(msg.AppName) ? "-" : msg.AppName;
        string procId = string.IsNullOrWhiteSpace(msg.ProcessId) ? "-" : msg.ProcessId;
        string msgId = string.IsNullOrWhiteSpace(msg.MessageId) ? "-" : msg.MessageId;

        var sdBuilder = new StringBuilder();
        if (msg.StructuredData != null && msg.StructuredData.Count > 0)
        {
            foreach (var (sdId, parameters) in msg.StructuredData)
            {
                sdBuilder.Append($"[{sdId}");
                foreach (var (k, v) in parameters)
                {
                    string escapedVal = v.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("]", "\\]");
                    sdBuilder.Append($" {k}=\"{escapedVal}\"");
                }
                sdBuilder.Append(']');
            }
        }
        else
        {
            sdBuilder.Append('-');
        }

        return $"<{pri}>1 {timestamp} {hostname} {appName} {procId} {msgId} {sdBuilder} {msg.Message}\n";
    }

    public static string FormatCef(CefEvent cef)
    {
        var extSb = new StringBuilder();
        foreach (var (k, v) in cef.ExtensionFields)
        {
            extSb.Append($"{k}={v} ");
        }

        string rawExtensions = extSb.ToString().TrimEnd();
        return $"CEF:0|{cef.DeviceVendor}|{cef.DeviceProduct}|{cef.DeviceVersion}|{cef.DeviceEventClassId}|{cef.Name}|{cef.Severity}|{rawExtensions}\n";
    }

    private static async Task SendSyslogNetworkAsync(string payload, SiemConfiguration config, CancellationToken cancellationToken)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(payload);

        if (config.Protocol == SiemProtocol.SyslogUdp)
        {
            using var udp = new UdpClient();
            await udp.SendAsync(bytes, bytes.Length, config.HostOrUrl, config.Port);
            return;
        }

        using var tcp = new TcpClient();
        await tcp.ConnectAsync(config.HostOrUrl, config.Port, cancellationToken);
        await using Stream stream = config.UseTls
            ? new SslStream(tcp.GetStream(), false)
            : tcp.GetStream();

        if (config.UseTls && stream is SslStream ssl)
        {
            await ssl.AuthenticateAsClientAsync(config.HostOrUrl);
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

        string endpoint = $"https://{config.WorkspaceId}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01";
        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Add("Log-Type", config.LogType);
        request.Headers.Add("x-ms-date", dateString);
        request.Headers.Add("Authorization", authSignature);
        request.Content = new ByteArrayContent(jsonBytes);
        request.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

        using var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
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
