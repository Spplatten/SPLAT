using System.Net;
using System.Net.Sockets;
using System.Text;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// `splat-mcp doctor` is what a stranger runs before trusting this host with an agent, so both of its
/// jobs are held here: it must report what THIS machine can do rather than what the product can do on
/// some other machine, and its summary of a lease must not drift from the substrate's own policy
/// tables. The probes are injected, so the report is tested without a WSL distro or a live daemon.
/// </summary>
public sealed class SubstrateDoctorTests
{

    /// <summary>
    /// A budget wide enough that losing the CPU cannot be mistaken for an unreachable daemon.
    /// See <see cref="WslSubstrateHealthChecker"/>'s constructor for why this is not the default.
    /// </summary>
    private static readonly TimeSpan ReplyBudget = TimeSpan.FromSeconds(30);
    /// <summary>Port 1 is reserved and nothing listens there.</summary>
    private static readonly WslSubstrateHealthChecker NoDaemon = new("127.0.0.1", 1, HermeticToken);

    /// <summary>Supplied outright, so no test here shells into WSL to read the real secret.</summary>
    private static WslAgentToken HermeticToken => new(authToken: "0123456789abcdef");

    /// <summary>
    /// One canned answer on loopback, given after protocol 3's handshake. The doctor's own probe does the
    /// talking, so what is under test is what it concludes from a real exchange rather than from a status
    /// object handed to it.
    /// </summary>
    internal sealed class StandInDaemon : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();

        /// <param name="token">
        /// The token it proves. One the caller does not hold plays a daemon restarted with a new secret, as
        /// seen from a host still holding the old one.
        /// </param>
        public StandInDaemon(string responseFrame, string token = "0123456789abcdef")
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start();
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _ = Task.Run(async () =>
            {
                try
                {
                    using var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                    using var stream = client.GetStream();
                    await StandInAgent.ServeAsync(stream, token, new[] { responseFrame }, _cts.Token);
                }
                catch (OperationCanceledException)
                {
                }
                catch (SocketException)
                {
                }
            });
        }

        public int Port { get; }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            _cts.Dispose();
        }
    }

    [Fact]
    public void TheSubcommand_IsOnlyEverTheFirstArgument()
    {
        Assert.IsType<McpServerCommand.Doctor>(McpServerCommand.Parse(new[] { "doctor" }));

        // Anywhere else it is an argument, not a subcommand - otherwise the value of an option could
        // quietly become one.
        Assert.IsType<McpServerCommand.UsageError>(
            McpServerCommand.Parse(new[] { "--egress=127.0.0.1:80", "doctor" }));
    }

    [Fact]
    public void TheSubcommand_KeepsTheOptionsItWasGiven()
    {
        string dir = Path.GetTempPath();

        var doctor = Assert.IsType<McpServerCommand.Doctor>(
            McpServerCommand.Parse(new[] { "doctor", "--workspace", dir, "--egress=127.0.0.1:80" }));

        Assert.Equal(Path.GetFullPath(dir), doctor.WorkspaceRoot);
        Assert.Equal("127.0.0.1:80", doctor.Egress.ToString());
    }

    [Fact]
    public async Task WithNoSubstrate_ItSaysSoAndExitsNonZero()
    {
        var report = new StringWriter();

        int exit = await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((-1, "wsl.exe not found")),
            health: NoDaemon,
            // Not this machine's ledger, which the operator may since have keyed.
            ledgerPath: Path.Combine(Path.GetTempPath(), "splat-no-ledger-" + Guid.NewGuid().ToString("N") + ".db"));

        string text = report.ToString();
        Assert.Equal(1, exit);
        Assert.Contains("not reachable", text);
        Assert.Contains("NOT enforcing", text);
        Assert.Contains(McpServerHandler.DefaultWorkspaceRoot, text);
        // The file tools do not depend on the substrate, and the report must not read as if they do.
        Assert.Contains("fs_read and fs_write are confined", text);
        // An unkeyed chain is a property of this host, not a detail to discover later.
        Assert.Contains("UNKEYED", text);
    }

    /// <summary>
    /// A host that has never served has no default workspace yet, because the server creates it on
    /// first start. On a clean machine (2026-09-18) that read as FAIL - the first line a stranger saw,
    /// printed above a verdict of enforcing.
    /// </summary>
    [Fact]
    public async Task ADefaultWorkspaceNotCreatedYet_IsNotAFailure()
    {
        string absent = Path.Combine(Path.GetTempPath(), "splat-never-served-" + Guid.NewGuid().ToString("N"));
        var report = new StringWriter();

        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((-1, "wsl.exe not found")),
            health: NoDaemon,
            defaultWorkspace: absent);

        string line = report.ToString().Split('\n').Single(l => l.Contains(absent));
        Assert.StartsWith("  ok", line);
        Assert.Contains("the server creates it when it first starts", line);
        // Reporting it must not be what creates it: the doctor serves nothing and creates nothing.
        Assert.False(Directory.Exists(absent));
    }

    [Fact]
    public async Task TheKernelAndItsBootLineAreReported_WhateverTheDaemonIsDoing()
    {
        var report = new StringWriter();

        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((0, "6.18.33.2-microsoft-standard-WSL2\n---\ninitrd=\\initrd.img lsm=landlock,yama,bpf\n")),
            health: NoDaemon);

        string text = report.ToString();
        Assert.Contains("6.18.33.2-microsoft-standard-WSL2", text);
        Assert.Contains("bpf is on the boot command line", text);
    }

    [Fact]
    public async Task AKernelWithoutBpfInItsBootLine_IsCalledOut()
    {
        var report = new StringWriter();

        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((0, "6.6.0-generic\n---\ninitrd=\\initrd.img lsm=landlock,yama\n")),
            health: NoDaemon);

        Assert.Contains("bpf is NOT on the boot command line", report.ToString());
    }

    /// <summary>
    /// The token line reports the request that was made, not `test -r` on the file.
    ///
    /// A present token is not an accepted one: a stale secret, or a daemon restarted with a new one,
    /// reads as "this host can authenticate" to a presence check while every request it makes is
    /// refused — and the doctor would then contradict the line printed directly above it.
    /// </summary>
    [Fact]
    public async Task ADaemonThatRefusesThisHostsToken_IsNotReportedAsAbleToAuthenticate()
    {
        // It proves a token, just not this host's - and it would claim enforcement if it were believed.
        using var daemon = new StandInDaemon(
            "{\"type\":\"HEALTH_RESPONSE\",\"bpfLsmActive\":true,\"cgroupV2Active\":true," +
            "\"overlayFsSupported\":false,\"kernelVersion\":\"6.18.33.2\",\"enforcing\":true,\"activeLeaseCount\":1}",
            token: "fedcba9876543210");
        var report = new StringWriter();

        int exit = await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((0, "6.18.33.2\n---\nlsm=bpf\n")),
            health: new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget));

        string text = report.ToString();
        Assert.Equal(1, exit);
        Assert.Contains("REFUSED", text);
        Assert.DoesNotContain("can authenticate", text);
        // And it must not read the silence as an answer about enforcement either.
        Assert.Contains("unknown: the daemon would not answer", text);
    }

    [Fact]
    public async Task ADaemonThatAcceptsIt_ReportsTheTokenAndTheEnforcementItAnswered()
    {
        using var daemon = new StandInDaemon(
            "{\"type\":\"HEALTH_RESPONSE\",\"bpfLsmActive\":true,\"cgroupV2Active\":true," +
            "\"overlayFsSupported\":false,\"kernelVersion\":\"6.18.33.2\",\"enforcing\":true,\"activeLeaseCount\":1}");
        var report = new StringWriter();

        int exit = await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((0, "6.18.33.2\n---\nlsm=bpf\n")),
            health: new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget));

        string text = report.ToString();
        Assert.Equal(0, exit);
        Assert.Contains("accepted: a request from this host authenticated", text);
        Assert.Contains("live: a lease reaches the kernel (1 active)", text);
    }

    [Fact]
    public async Task AnEgressPolicy_IsReportedAsTheOperatorWroteIt()
    {
        var report = new StringWriter();

        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.Parse("203.0.113.7:443")),
            report,
            wsl: (_, _) => Task.FromResult((-1, "no wsl")),
            health: NoDaemon);

        Assert.Contains("may connect only to 203.0.113.7:443", report.ToString());
    }

}
