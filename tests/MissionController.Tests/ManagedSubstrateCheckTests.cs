using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using MissionController.Host;
using MissionController.Infrastructure.Linux;
using SplatMcp;

namespace MissionController.Tests;

/// <summary>
/// The desktop's managed report must wake the service-owned guest just as a lease does. These use
/// the real report and connection retry against a protocol stand-in; they are not a live WSL proof.
/// </summary>
public sealed class ManagedSubstrateCheckTests : IDisposable
{
    private const string Token = "0123456789abcdef";
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splat-managed-check-" + Guid.NewGuid().ToString("N"));

    private ManagedBridgeConfiguration Configuration(int port)
    {
        string state = Directory.CreateDirectory(Path.Combine(_root, "state")).FullName;
        string workspace = Directory.CreateDirectory(Path.Combine(_root, "workspace")).FullName;
        return new(1, "SplatTest", "S-1-5-21-1-2-3-1002", "SplatTest", "SplatOwnedGuest", port,
            state, workspace, new[] { "S-1-5-21-1-2-3-1001" });
    }

    private static Task<(int ExitCode, string Output)> GuestProbe(IReadOnlyList<string> args, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Assert.Equal(new[] { "-d", "SplatOwnedGuest", "-e", "sh", "-c", "uname -r; echo ---; cat /proc/cmdline" }, args);
        return Task.FromResult((0, "test-kernel\n---\nlsm=lockdown,capability,bpf"));
    }

    [Fact]
    public async Task AColdManagedCheck_StartsTheGuestBeforeReadingItsToken_OutsideTheReplyBudget()
    {
        using var daemon = new ColdDaemon(enforcing: true);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var token = new WslAgentToken(_ => Task.FromResult<string?>(daemon.Starts == 1 ? Token : null));

        var report = await ManagedBridgeHost.CheckManagedAsync(Configuration(daemon.Port), deadline.Token,
            GuestProbe, token, async ct =>
            {
                // Starting the guest alone takes longer than the health exchange's two-second budget.
                await Task.Delay(TimeSpan.FromSeconds(3), ct);
                return daemon.Start(ct);
            });

        Assert.Equal(1, daemon.Starts);
        Assert.Equal(0, report.ExitCode);
        Assert.Contains("Managed guest: SplatOwnedGuest; service: SplatTest", report.Text);
        Assert.Contains("accepted: a request from this host authenticated", report.Text);
        Assert.Contains("Verdict: a lease on this host reaches the kernel.", report.Text);
        var exchange = await daemon.Exchange!.WaitAsync(deadline.Token);
        Assert.True(exchange.Proven);
        using var request = JsonDocument.Parse(exchange.Request!);
        Assert.Equal("HEALTH_CHECK", request.RootElement.GetProperty("type").GetString());
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task StartingTheGuest_DoesNotSubstituteForAuthenticatedEnforcement(bool enforcing, bool authentic)
    {
        using var daemon = new ColdDaemon(enforcing, authentic ? Token : "fedcba9876543210");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));

        var report = await ManagedBridgeHost.CheckManagedAsync(Configuration(daemon.Port), deadline.Token,
            GuestProbe, new WslAgentToken(authToken: Token), ct => Task.FromResult(daemon.Start(ct)));

        Assert.Equal(1, daemon.Starts);
        Assert.Equal(1, report.ExitCode);
        Assert.Contains("Verdict: NOT enforcing here.", report.Text);
        var exchange = await daemon.Exchange!.WaitAsync(deadline.Token);
        Assert.Equal(authentic, exchange.Proven);
        if (!authentic) Assert.Null(exchange.Request);
    }

    [Fact]
    public async Task AFailedDaemonStart_RemainsUnreachable()
    {
        using var daemon = new ColdDaemon(enforcing: true);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        int attempts = 0;

        var report = await ManagedBridgeHost.CheckManagedAsync(Configuration(daemon.Port), deadline.Token,
            GuestProbe, new WslAgentToken(authToken: Token), _ => { attempts++; return Task.FromResult(5); });

        Assert.Equal(1, attempts);
        Assert.Equal(0, daemon.Starts);
        Assert.Equal(1, report.ExitCode);
        Assert.Contains("not reachable", report.Text);
        Assert.Contains("Verdict: NOT enforcing here.", report.Text);
    }

    private sealed class ColdDaemon : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly string _response;
        private readonly string _token;
        internal int Port { get; }
        internal int Starts { get; private set; }
        internal Task<StandInAgent.Exchange>? Exchange { get; private set; }

        internal ColdDaemon(bool enforcing, string token = Token)
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _listener.Stop();
            _listener = new TcpListener(IPAddress.Loopback, Port);
            _token = token;
            _response = JsonSerializer.Serialize(new { type = "HEALTH_RESPONSE", enforcing,
                bpfLsmActive = enforcing, cgroupV2Active = true, overlayFsSupported = true,
                kernelVersion = "test-kernel", activeLeaseCount = 0 });
        }

        internal int Start(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Starts++;
            _listener.Start();
            Exchange = ServeAsync(ct);
            return 0;
        }

        private async Task<StandInAgent.Exchange> ServeAsync(CancellationToken ct)
        {
            using var client = await _listener.AcceptTcpClientAsync(ct);
            using var stream = client.GetStream();
            return await StandInAgent.ServeAsync(stream, _token, new[] { _response }, ct);
        }

        public void Dispose() => _listener.Stop();
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
