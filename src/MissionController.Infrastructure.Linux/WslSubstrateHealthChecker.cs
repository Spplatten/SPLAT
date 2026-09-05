using System;
using System.IO;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Infrastructure.Linux;

public record WslSubstrateStatus(
    bool WslConfiguredForBpf,
    bool DaemonReachable,
    bool BpfLsmActive,
    bool CgroupV2Active,
    bool OverlayFsSupported,
    string KernelVersion,
    uint ActiveLeaseCount,
    string? Message,
    /// <summary>
    /// Whether the daemon holds live BPF map handles, i.e. whether a lease it accepts actually
    /// reaches the kernel. This is the field to gate on: reachable is not the same as enforcing,
    /// and the daemon used to report all three booleans above as hardcoded true regardless.
    /// A daemon that predates this field reports nothing, which reads here as not enforcing.
    /// </summary>
    bool Enforcing = false);

/// <summary>
/// Probes and validates the status of the local WSL2 kernel substrate and BPF-LSM daemon.
/// </summary>
public class WslSubstrateHealthChecker
{
    private readonly string _host;
    private readonly int _port;

    public WslSubstrateHealthChecker(string host = "127.0.0.1", int port = 50051)
    {
        _host = host;
        _port = port;
    }

    public bool IsWslConfiguredForBpf()
    {
        try
        {
            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string wslConfigPath = Path.Combine(userProfile, ".wslconfig");
            if (!File.Exists(wslConfigPath)) return false;

            string content = File.ReadAllText(wslConfigPath);
            return content.Contains("bpf", StringComparison.OrdinalIgnoreCase) &&
                   content.Contains("kernelCommandLine", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public async Task<WslSubstrateStatus> CheckHealthAsync(CancellationToken ct = default)
    {
        bool wslConfigured = IsWslConfiguredForBpf();

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(2));

            using var client = new TcpClient();
            await client.ConnectAsync(_host, _port, cts.Token);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream);
            using var writer = new StreamWriter(stream) { AutoFlush = true };

            await writer.WriteLineAsync("{\"type\":\"HEALTH_CHECK\"}");
            string? response = await reader.ReadLineAsync(cts.Token);

            if (!string.IsNullOrEmpty(response))
            {
                using var doc = JsonDocument.Parse(response);
                var root = doc.RootElement;
                bool enforcing = root.TryGetProperty("enforcing", out var enf) && enf.GetBoolean();
                return new WslSubstrateStatus(
                    WslConfiguredForBpf: wslConfigured,
                    DaemonReachable: true,
                    BpfLsmActive: root.TryGetProperty("bpfLsmActive", out var bpf) && bpf.GetBoolean(),
                    CgroupV2Active: root.TryGetProperty("cgroupV2Active", out var cg) && cg.GetBoolean(),
                    OverlayFsSupported: root.TryGetProperty("overlayFsSupported", out var ofs) && ofs.GetBoolean(),
                    KernelVersion: root.TryGetProperty("kernelVersion", out var kv) ? kv.GetString() ?? "" : "",
                    ActiveLeaseCount: root.TryGetProperty("activeLeaseCount", out var alc) ? alc.GetUInt32() : 0,
                    Message: enforcing
                        ? "SPLAT Linux substrate online and enforcing."
                        : "SPLAT Linux daemon is reachable but NOT enforcing: leases it accepts do not reach the kernel. Treat any tool it runs as uncontained.",
                    Enforcing: enforcing);
            }
        }
        catch (Exception ex)
        {
            return new WslSubstrateStatus(
                WslConfiguredForBpf: wslConfigured,
                DaemonReachable: false,
                BpfLsmActive: false,
                CgroupV2Active: false,
                OverlayFsSupported: false,
                KernelVersion: "Unknown",
                ActiveLeaseCount: 0,
                Message: $"Daemon unreachable at {_host}:{_port}: {ex.Message}");
        }

        return new WslSubstrateStatus(
            WslConfiguredForBpf: wslConfigured,
            DaemonReachable: false,
            BpfLsmActive: false,
            CgroupV2Active: false,
            OverlayFsSupported: false,
            KernelVersion: "Unknown",
            ActiveLeaseCount: 0,
            Message: "Daemon responded with empty status.");
    }
}