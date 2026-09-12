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
    bool Enforcing = false,
    /// <summary>
    /// Whether the daemon accepted this host's token and answered. False with
    /// <see cref="DaemonReachable"/> true means it is running and would not say anything — which is
    /// a different fault from an absent daemon, and from one that answers "not enforcing".
    /// </summary>
    bool Authenticated = false);

/// <summary>
/// Probes and validates the status of the local WSL2 kernel substrate and BPF-LSM daemon.
/// </summary>
public class WslSubstrateHealthChecker
{
    private readonly string _host;
    private readonly int _port;
    private readonly WslAgentToken _token;
    private readonly TimeSpan _timeout;

    /// <param name="timeout">
    /// How long the whole exchange gets. Two seconds is a policy about a status badge - a health
    /// check that has not answered by then should read as "not answering" rather than hold a UI
    /// thread - and it is wrong for every caller who is not a badge. It is a parameter because a
    /// test that shares it is asserting scheduler luck: the same loopback exchange measured 12ms
    /// alone and 363ms under the suite's own parallel load, and the one that lost that race read
    /// as an unreachable daemon, which is indistinguishable from the bug this class exists to catch.
    /// </param>
    public WslSubstrateHealthChecker(
        string host = "127.0.0.1",
        int port = 50051,
        WslAgentToken? token = null,
        TimeSpan? timeout = null)
    {
        _host = host;
        _port = port;
        _token = token ?? WslAgentToken.Default;
        _timeout = timeout ?? TimeSpan.FromSeconds(2);
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
            cts.CancelAfter(_timeout);

            using var client = new TcpClient();
            await client.ConnectAsync(_host, _port, cts.Token);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream);
            using var writer = new StreamWriter(stream) { AutoFlush = true };

            // The health check is authenticated like every other request. It reports whether this
            // host's containment is live, how many leases are running and which kernel is under
            // them - state an unauthenticated caller has no business reading, and which told an
            // attacker exactly when the daemon would run work it could not contain.
            string? token = await _token.GetAsync(cts.Token);
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { type = "HEALTH_CHECK", authToken = token ?? "" }));
            string? response = await reader.ReadLineAsync(cts.Token);

            if (!string.IsNullOrEmpty(response))
            {
                using var doc = JsonDocument.Parse(response);
                var root = doc.RootElement;

                // Reachable, but it would not answer: that is an authentication failure, not an
                // absent daemon, and reporting it as unreachable would send whoever reads this
                // looking for a process that is running. Judged on the frame type rather than on a
                // missing `enforcing` — a daemon too old to report that field still answers with a
                // HEALTH_RESPONSE, and it is handled below.
                if ((root.TryGetProperty("type", out var frameType) ? frameType.GetString() : null) != "HEALTH_RESPONSE")
                {
                    return new WslSubstrateStatus(
                        WslConfiguredForBpf: wslConfigured,
                        DaemonReachable: true,
                        BpfLsmActive: false,
                        CgroupV2Active: false,
                        OverlayFsSupported: false,
                        KernelVersion: "Unknown",
                        ActiveLeaseCount: 0,
                        Message: token is null
                            ? $"Daemon reachable, but this host could not read its token at {_token.Path}, so the health check was refused."
                            : "Daemon reachable, but it refused the health check: the token this host holds is not the one it expects.");
                }

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
                    Enforcing: enforcing,
                    // It answered, which it only does for a request carrying the token it expects.
                    Authenticated: true);
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