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
    /// Whether the daemon proved it holds this host's token and answered a request that proved it back.
    /// False with <see cref="DaemonReachable"/> true means something is listening that would not answer,
    /// or that could not prove it is the daemon — a different fault from an absent daemon, and from one
    /// that answers "not enforcing".
    /// </summary>
    bool Authenticated = false,
    /// <summary>
    /// Whether the guest holds a lease ceiling the daemon intersects every request with. Without one
    /// the token alone authorizes whatever a request names; a daemon that predates the field reports
    /// nothing, which reads here as none.
    /// </summary>
    bool CeilingPolicy = false);

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
    /// How long the exchange with the daemon gets; the token is read before it, under a budget of its
    /// own. Two seconds is a policy about a status badge - a health
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
            // The token is read first, under a budget of its own, and only then does the daemon's clock
            // start. Reading it spawns wsl.exe, which is always cold in a one-shot command - doctor,
            // provision - and slowest exactly when provision runs: straight after the `wsl --shutdown` it
            // asks for, on a guest still booting. Timed inside the daemon's two seconds, that spawn alone
            // ran out the clock, the read came back empty, an unauthenticated request went out, and a
            // daemon that was up and enforcing was reported unreachable.
            string? token;
            using (var tokenCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                tokenCts.CancelAfter(WslAgentToken.ReadBudget);
                token = await _token.GetAsync(tokenCts.Token);
            }

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(_timeout);

            using var client = new TcpClient();
            await client.ConnectAsync(_host, _port, cts.Token);
            using var stream = client.GetStream();

            // Something is listening. Without the token this host can neither check that it is the daemon
            // nor prove anything to it, so nothing is sent.
            if (string.IsNullOrEmpty(token))
            {
                return new WslSubstrateStatus(
                    WslConfiguredForBpf: wslConfigured,
                    DaemonReachable: true,
                    BpfLsmActive: false,
                    CgroupV2Active: false,
                    OverlayFsSupported: false,
                    KernelVersion: "Unknown",
                    ActiveLeaseCount: 0,
                    Message: $"Daemon reachable, but this host could not read its token at {_token.Path}, so it cannot authenticate a health check.");
            }

            // The health check is authenticated like every other request. It reports whether this host's
            // containment is live, how many leases are running and which kernel is under them - state an
            // unauthenticated caller has no business reading. And the answer is believed only from something
            // that proved it holds the token: whatever took the daemon's port could otherwise report
            // `enforcing` for a daemon that is not running.
            using var session = await WslAgentSession.OpenAsync(stream, token, cts.Token);
            await session.SendAsync(JsonSerializer.Serialize(new { type = "HEALTH_CHECK" }), cts.Token);
            string? response = await session.ReadLineAsync(cts.Token);

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
                        Message: "Daemon reachable, and it proved it holds this host's token, but it refused the health check: "
                            + (root.TryGetProperty("data", out var said) && said.GetString() is { Length: > 0 } reason
                                ? reason.Trim()
                                : "it gave no reason."));
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
                    // It answered, which it does only for a request that proved the token.
                    Authenticated: true,
                    CeilingPolicy: root.TryGetProperty("ceiling", out var ceiling) && ceiling.GetBoolean());
            }
        }
        catch (WslAgentHandshakeException ex)
        {
            // Something answered on the daemon's port and did not prove it holds the token. It is reported
            // as reachable, because something is, and as nothing more.
            return new WslSubstrateStatus(
                WslConfiguredForBpf: wslConfigured,
                DaemonReachable: true,
                BpfLsmActive: false,
                CgroupV2Active: false,
                OverlayFsSupported: false,
                KernelVersion: "Unknown",
                ActiveLeaseCount: 0,
                Message: ex.Message);
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