using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The Windows side of F04. The daemon's HEALTH_RESPONSE was three hardcoded `true` values and a
/// fixed kernel string, and this reader had no independent way to check any of them - so the one
/// signal that was supposed to say "containment is live" said it unconditionally, and a reachable
/// daemon with no BPF programs loaded read as "online and operational".
///
/// The daemon now reports what it observes and adds `enforcing`. These pin the reader's half:
/// reachable is not operational, and a daemon too old to send the field is not trusted by default.
/// </summary>
public class SubstrateHealthHonestyTests
{
    /// <summary>Answers one HEALTH_CHECK with a caller-chosen body, the way the daemon would.</summary>
    private sealed class FakeDaemon : IDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cts = new();

        public int Port { get; }

        public FakeDaemon(string healthJson)
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
                    using var reader = new StreamReader(stream);
                    using var writer = new StreamWriter(stream) { AutoFlush = true };
                    await reader.ReadLineAsync(_cts.Token);
                    await writer.WriteLineAsync(healthJson);
                    await Task.Delay(200, _cts.Token);
                }
                catch { /* the test finished first */ }
            });
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
            _cts.Dispose();
        }
    }

    /// <summary>
    /// A token supplied outright, so these tests never shell into WSL to read the real one. The
    /// health check is authenticated, and what is under test here is what the checker believes
    /// about an answer - not how this host obtains its secret.
    /// </summary>
    private static WslAgentToken HermeticToken => new(authToken: "0123456789abcdef");

    private const string EnforcingBody =
        """{"type":"HEALTH_RESPONSE","bpfLsmActive":true,"cgroupV2Active":true,"overlayFsSupported":true,"kernelVersion":"6.18.33.2-microsoft-standard-WSL2","enforcing":true,"activeLeaseCount":0}""";

    private const string MockedBody =
        """{"type":"HEALTH_RESPONSE","bpfLsmActive":false,"cgroupV2Active":true,"overlayFsSupported":true,"kernelVersion":"6.18.33.2-microsoft-standard-WSL2","enforcing":false,"activeLeaseCount":0}""";

    /// <summary>Exactly what the daemon sent before this change: all true, no `enforcing`.</summary>
    private const string LegacyOptimisticBody =
        """{"type":"HEALTH_RESPONSE","bpfLsmActive":true,"cgroupV2Active":true,"overlayFsSupported":true,"kernelVersion":"6.18.33.2-2","activeLeaseCount":0}""";

    [Fact]
    public async Task AnEnforcingDaemon_ReadsAsEnforcing()
    {
        using var daemon = new FakeDaemon(EnforcingBody);
        var status = await new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken).CheckHealthAsync();

        Assert.True(status.DaemonReachable);
        Assert.True(status.Enforcing);
        Assert.Contains("enforcing", status.Message);
        Assert.Equal("6.18.33.2-microsoft-standard-WSL2", status.KernelVersion);
    }

    [Fact]
    public async Task AReachableDaemonThatEnforcesNothing_DoesNotReadAsOperational()
    {
        using var daemon = new FakeDaemon(MockedBody);
        var status = await new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken).CheckHealthAsync();

        // Reachable, and useless for containment. The old message said "online and operational"
        // for exactly this response.
        Assert.True(status.DaemonReachable);
        Assert.False(status.Enforcing);
        Assert.False(status.BpfLsmActive);
        Assert.Contains("NOT enforcing", status.Message);
        Assert.Contains("uncontained", status.Message);
    }

    [Fact]
    public async Task ADaemonTooOldToReportEnforcement_IsNotTrusted()
    {
        using var daemon = new FakeDaemon(LegacyOptimisticBody);
        var status = await new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken).CheckHealthAsync();

        // The absent field must default to "not enforcing". Defaulting the other way would let a
        // daemon predating this change keep asserting containment by saying nothing.
        Assert.True(status.DaemonReachable);
        Assert.False(status.Enforcing);
        Assert.Contains("NOT enforcing", status.Message);
    }

    [Fact]
    public async Task AnUnreachableDaemon_ReportsNeitherReachableNorEnforcing()
    {
        // Port 1 is reserved and nothing listens there.
        var status = await new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken).CheckHealthAsync();

        Assert.False(status.DaemonReachable);
        Assert.False(status.Enforcing);
    }
}
