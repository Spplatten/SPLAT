using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Wire-level tests for the Windows-to-guest bridge, run against a stand-in listener in this
/// process. No WSL, no daemon, no root - the point is the bytes on the socket, which is where the
/// bridge was broken: it wrote UTF-8 WITH a byte order mark, so the daemon answered every single
/// request with "Invalid JSON request: expected value at line 1 column 1". Nothing caught it,
/// because nothing had ever run the two halves against each other.
/// </summary>
public class WslLeasedExecutorWireTests
{

    /// <summary>
    /// A budget wide enough that losing the CPU cannot be mistaken for an unreachable daemon.
    /// See <see cref="WslSubstrateHealthChecker"/>'s constructor for why this is not the default.
    /// </summary>
    private static readonly TimeSpan ReplyBudget = TimeSpan.FromSeconds(30);
    /// <summary>
    /// A stand-in for the daemon's 0600 token. Supplied directly so these tests keep testing the
    /// wire and nothing else - the bridge otherwise reads the real secret out of the guest through
    /// `wsl.exe -u root`, which is neither available nor relevant here.
    /// </summary>
    private const string TestToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>
    /// Every child this bridge starts must be handed its own standard input.
    ///
    /// Without the redirect, `wsl.exe` INHERITS the host's stdin - and in `splat-mcp` that is the
    /// JSON-RPC channel, so the child pumps the client's own bytes into the guest and the next
    /// request arrives truncated. Found on 2026-09-11 by probe-last-hop.ps1, whose sixth request
    /// reached the server as a lone "{" and came back as a parse error. Both call sites did it, and
    /// the daemon-liveness one runs on EVERY leased execution.
    ///
    /// Asserted on the source, because reproducing it needs a real WSL and a real daemon, and this
    /// suite has to pass on a fresh checkout with neither.
    /// </summary>
    [Fact]
    public void EveryChildProcessTheBridgeStarts_GetsItsOwnStdin()
    {
        foreach (string declaration in ChildProcessDeclarations())
        {
            Assert.True(
                declaration.Contains("RedirectStandardInput = true", StringComparison.Ordinal),
                "A ProcessStartInfo in Infrastructure.Linux does not redirect standard input, so the child "
                + "inherits the host's. Under splat-mcp that is the MCP client's JSON-RPC stream, and wsl.exe "
                + "consumes it:\n" + declaration);
        }
    }

    /// <summary>
    /// Every child this bridge starts runs as root, so each is one program named by an absolute path
    /// under /bin, and never a shell.
    ///
    /// The daemon bootstrap was `/bin/bash -l -c` around a loop that ran the first splat-agent it found
    /// at /tmp/splat_agent_target or in this repository's target/. The guest's /tmp is world-writable,
    /// so any unprivileged process in it - a leased workload included - could have left a file there
    /// for root to run. Asserted on the source for the same reason as the stdin redirect above.
    /// </summary>
    [Fact]
    public void EveryChildProcessTheBridgeStarts_IsOneProgramUnderBin_NeverAShell()
    {
        foreach (string declaration in ChildProcessDeclarations())
        {
            Match program = Regex.Match(declaration, @"Arguments = \$?""-u root -e /(?:usr/)?bin/(?<name>[a-z]+) ");
            Assert.True(program.Success, "A child of the bridge is not one program under /bin, run with -e:\n" + declaration);
            Assert.DoesNotContain(program.Groups["name"].Value, new[] { "sh", "bash", "dash", "env" });
        }
    }

    /// <summary>
    /// Each ProcessStartInfo initializer in the bridge. Every file in the project, not just the executor:
    /// the token read moved to its own class once the health check needed it too, and a guard that named
    /// one file would have stopped covering it at exactly that moment.
    /// </summary>
    private static List<string> ChildProcessDeclarations()
    {
        string project = Path.Combine(RepositoryRoot(), "src", "MissionController.Infrastructure.Linux");
        var declarations = Directory.EnumerateFiles(project, "*.cs", SearchOption.AllDirectories)
            .SelectMany(file => File.ReadAllText(file).Split("new ProcessStartInfo").Skip(1))
            // Up to the Process.Start that consumes it. Not to the closing brace, which a string literal
            // inside an initializer can contain.
            .Select(block => block[..Math.Max(0, block.IndexOf("Process.Start", StringComparison.Ordinal))])
            .ToList();

        Assert.NotEmpty(declarations);
        return declarations;
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    private static LeaseSpec SampleLease() => new(
        MissionId: Guid.NewGuid(),
        WorkingDirectory: "/tmp",
        AllowNetwork: true,
        AllowedEgressIps: new List<string> { "10.1.2.3" },
        AllowedEgressPorts: new List<uint> { 443 },
        ReadOnlyFs: true,
        ProtectedInodes: new List<InodeIdentifierModel>(),
        AllowedExecInodes: new List<InodeIdentifierModel>(),
        LeaseDurationSeconds: 15,
        Limits: new LeaseResourceLimits(64 * 1024 * 1024, 25, 20));

    /// <summary>A loopback port with nothing listening on it, so a connection to it is refused.</summary>
    private static int UnusedPort()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    /// <summary>
    /// Captures the raw request bytes and replies with the given frames.
    ///
    /// A connection that closes without sending anything - a bridge that refused before it had a
    /// request to send - is skipped, so a request that does follow is still captured and answered.
    /// </summary>
    private static async Task<byte[]> RunStandInDaemonAsync(TcpListener listener, params string[] responseFrames)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();

            var buffer = new byte[8192];
            int read;
            try
            {
                read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length));
            }
            catch (IOException)
            {
                continue; // Hung up mid-read.
            }

            if (read == 0)
            {
                continue; // Connected, said nothing, closed.
            }

            foreach (var frame in responseFrames)
            {
                await stream.WriteAsync(Encoding.UTF8.GetBytes(frame + "\n"));
                await stream.FlushAsync();
            }

            return buffer[..read];
        }

        return Array.Empty<byte>();
    }

    /// <summary>
    /// The health check is a request like any other, so it carries the token.
    ///
    /// It was open until 2026-09-11, on the grounds that a liveness probe should not need a secret.
    /// But it answers with `enforcing`, the kernel version and the live lease count — so it told an
    /// unauthenticated caller exactly when this daemon would run work it could not contain.
    /// </summary>
    [Fact]
    public async Task TheHealthCheck_PresentsTheDaemonsToken()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"HEALTH_RESPONSE\",\"bpfLsmActive\":true,\"cgroupV2Active\":true," +
            "\"overlayFsSupported\":false,\"kernelVersion\":\"6.18.33.2\",\"enforcing\":true,\"activeLeaseCount\":2}");

        var checker = new WslSubstrateHealthChecker("127.0.0.1", port, new WslAgentToken(authToken: TestToken), ReplyBudget);
        var status = await checker.CheckHealthAsync();

        string request = Encoding.UTF8.GetString(await daemon);
        listener.Stop();

        Assert.Contains("\"HEALTH_CHECK\"", request);
        Assert.Contains(TestToken, request);
        Assert.True(status.Enforcing);
        Assert.Equal(2u, status.ActiveLeaseCount);
    }

    /// <summary>
    /// A refused health check is a live daemon that would not answer, not an absent one: reporting
    /// it as unreachable would send whoever reads it looking for a process that is running.
    /// </summary>
    [Fact]
    public async Task ARefusedHealthCheck_ReadsAsReachableButUnauthenticated()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"STDERR\",\"data\":\"SPLAT refused the request: missing or invalid authToken.\\n\"}");

        var checker = new WslSubstrateHealthChecker("127.0.0.1", port, new WslAgentToken(authToken: TestToken), ReplyBudget);
        var status = await checker.CheckHealthAsync();

        await daemon;
        listener.Stop();

        Assert.True(status.DaemonReachable);
        Assert.False(status.Enforcing);
        Assert.Contains("refused the health check", status.Message);
    }

    [Fact]
    public async Task TheRequestIsPlainUtf8WithNoByteOrderMark()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"STDOUT\",\"data\":\"ok\\n\"}",
            "{\"type\":\"EXIT\",\"exitCode\":0}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken);
        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        byte[] request = await daemon;
        listener.Stop();

        Assert.True(request.Length >= 3, "the bridge sent nothing");
        Assert.False(
            request[0] == 0xEF && request[1] == 0xBB && request[2] == 0xBF,
            "the request begins with a UTF-8 BOM; the daemon rejects it as invalid JSON at column 1");
        Assert.Equal((byte)'{', request[0]);

        Assert.Equal(0, result.ExitCode);
        Assert.False(result.TimedOut);
        Assert.Contains("ok", result.StandardOutput);
    }

    /// <summary>
    /// The lease is the policy, so every field the kernel enforces has to survive the wire. These
    /// were hardcoded on the daemon side until 2026-09-03; a template could name one approved
    /// destination and the kernel would never hear about it.
    /// </summary>
    [Fact]
    public async Task TheDeclaredLeaseTravelsIntactToTheDaemon()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");

        var lease = SampleLease();
        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken);
        await executor.ExecuteLeasedAsync(lease, "/usr/bin/curl", new[] { "--max-time", "3" });

        byte[] request = await daemon;
        listener.Stop();

        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(request).Trim());
        var root = doc.RootElement;

        Assert.Equal("EXECUTE_TOOL", root.GetProperty("type").GetString());
        Assert.Equal(2, root.GetProperty("protocolVersion").GetInt32());
        Assert.Equal("/usr/bin/curl", root.GetProperty("command").GetString());

        // argv, not a pre-quoted string. The daemon used to split whatever arrived on whitespace,
        // which cannot recover quoting - so the arguments had to stop being a string on the wire.
        var argv = root.GetProperty("argv");
        Assert.Equal(2, argv.GetArrayLength());
        Assert.Equal("--max-time", argv[0].GetString());
        Assert.Equal("3", argv[1].GetString());

        // The compiled policy travels as paths, resolvable in the guest. Both lists were dropped
        // from the envelope entirely, so the daemon fell back to its own hardcoded defaults.
        Assert.True(root.TryGetProperty("protectedPaths", out _));
        Assert.True(root.TryGetProperty("allowedExecPaths", out _));
        Assert.Equal(lease.MissionId.ToString(), root.GetProperty("missionId").GetString());
        Assert.True(root.GetProperty("allowNetwork").GetBoolean());
        Assert.True(root.GetProperty("readOnlyFs").GetBoolean());
        Assert.Equal("10.1.2.3", root.GetProperty("allowedEgressIps")[0].GetString());
        Assert.Equal(15, root.GetProperty("leaseDurationSeconds").GetInt32());
        Assert.Equal(64 * 1024 * 1024, root.GetProperty("limits").GetProperty("maxMemoryBytes").GetInt64());
    }

    /// <summary>
    /// The daemon refuses any EXECUTE_TOOL that does not present its token, so the bridge has to
    /// carry one. Before F07 the daemon ran commands as root for anyone who could open a loopback
    /// socket, and the envelope had no field for a credential at all.
    /// </summary>
    [Fact]
    public async Task TheRequestCarriesTheAuthToken()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken);
        await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        byte[] request = await daemon;
        listener.Stop();

        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(request).Trim());
        Assert.Equal(TestToken, doc.RootElement.GetProperty("authToken").GetString());
    }

    /// <summary>
    /// No token, no request. Sending an unauthenticated envelope and letting the daemon refuse it
    /// would work, but it turns a configuration problem into a containment-shaped error message;
    /// the bridge knows perfectly well that it has nothing to present.
    /// </summary>
    [Fact]
    public async Task WithoutATokenTheBridgeRefusesRatherThanSendingAnUnauthenticatedRequest()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");

        try
        {
            // A path no daemon ever wrote, so the guest read finds nothing either.
            var executor = new WslLeasedExecutor(
                "127.0.0.1", port, authTokenPath: "/nonexistent/splat/agent.token");

            var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

            // This class reports transport failures rather than throwing, so the refusal arrives
            // the same way every other one does.
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("auth token", result.StandardError, StringComparison.OrdinalIgnoreCase);

            // The property that matters: nothing reached the wire. The bridge stopped before it
            // could send an envelope the daemon would only have refused anyway.
            var finished = await Task.WhenAny(daemon, Task.Delay(500));
            Assert.True(
                finished != daemon || (await daemon).Length == 0,
                "an EXECUTE_TOOL envelope went out without a token");
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Reading the token spawns wsl.exe, cold on the first lease a host asks for, and that read was
    /// timed against the lease: a slow one came back as a token that could not be read. The shortest
    /// lease the bridge times is five seconds and this read takes six, so the lease goes ahead only if
    /// its clock starts when the request is sent.
    /// </summary>
    [Fact]
    public async Task ASlowTokenRead_IsNotChargedToTheLease()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        _ = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");

        var slowToken = new WslAgentToken(async ct =>
        {
            await Task.Delay(TimeSpan.FromSeconds(6), ct);
            return TestToken;
        });

        try
        {
            var result = await new WslLeasedExecutor("127.0.0.1", port, slowToken)
                .ExecuteLeasedAsync(SampleLease() with { LeaseDurationSeconds = 1 }, "/usr/bin/id", Array.Empty<string>());

            Assert.True(result.ExitCode == 0 && !result.TimedOut, result.StandardError);
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Only a refused connection means nothing is listening, and what starts then is the installed
    /// service, once. The bridge used to decide from a 200 ms race, and a connect that lost it ran a
    /// root bootstrap whether or not a daemon was already listening.
    /// </summary>
    [Fact]
    public async Task ARefusedConnection_StartsTheService_AndADaemonThatAnswersIsNeverStarted()
    {
        int port = UnusedPort();
        var listener = new TcpListener(IPAddress.Loopback, port);
        int starts = 0;

        var executor = new WslLeasedExecutor("127.0.0.1", port, new WslAgentToken(authToken: TestToken), ct =>
        {
            starts++;
            listener.Start();
            _ = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");
            return Task.FromResult(0);
        });

        try
        {
            var first = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());
            Assert.True(first.ExitCode == 0, first.StandardError);

            // It answers now, and a daemon that answers is never started again.
            var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");
            var second = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());
            Assert.True(second.ExitCode == 0, second.StandardError);
            Assert.Contains("EXECUTE_TOOL", Encoding.UTF8.GetString(await daemon));

            Assert.Equal(1, starts);
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// A service that is not there is a step the user has not taken yet, so the refusal names the
    /// command that takes it - and it is a refusal, not a lease that expired: nothing ran.
    /// </summary>
    [Fact]
    public async Task WhenTheServiceIsNotInstalled_TheRefusalNamesTheCommandThatInstallsIt()
    {
        var executor = new WslLeasedExecutor("127.0.0.1", UnusedPort(), new WslAgentToken(authToken: TestToken),
            // systemctl's exit code for a unit it cannot find, as measured in this guest on 2026-09-13.
            _ => Task.FromResult(5));

        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        Assert.NotEqual(0, result.ExitCode);
        Assert.False(result.TimedOut);
        Assert.Contains("splat-mcp provision --apply", result.StandardError);
    }

    /// <summary>
    /// A kernel denial must reach the caller as a structured event, not just as text in stderr -
    /// it is what the audit ledger records and what the UI shows as containment holding.
    /// </summary>
    [Fact]
    public async Task AKernelViolationSurfacesAsAStructuredEvent()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"VIOLATION\",\"cgroupId\":4020,\"pid\":8540,\"hook\":2,\"detail\":44904," +
            "\"detailText\":\"file_open: denied access to protected sensitive file (inode 44904)\",\"comm\":\"cat\"}",
            "{\"type\":\"EXIT\",\"exitCode\":1}");

        var seen = new List<LeaseViolationEvent>();
        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken);
        var result = await executor.ExecuteLeasedAsync(
            SampleLease(), "/bin/cat", new[] { "/etc/shadow" },
            violations: new Progress<LeaseViolationEvent>(v => { lock (seen) { seen.Add(v); } }));

        await daemon;
        listener.Stop();

        Assert.Equal(1, result.ExitCode);
        // Progress<T> marshals through the synchronisation context, so give it a moment to land.
        for (int i = 0; i < 50 && seen.Count == 0; i++)
        {
            await Task.Delay(20);
        }

        var violation = Assert.Single(seen);
        Assert.Equal(8540u, violation.ProcessId);
        Assert.Equal(44904ul, violation.Detail);
        Assert.Equal("cat", violation.ProcessComm);
        Assert.Contains("protected", violation.DetailText, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The daemon's EXIT frame carries no cgroup accounting, so the bridge must report absence
    /// rather than deriving numbers. It previously returned MaxMemoryBytes/4 as "peak memory" -
    /// arithmetic on a constant, sealed into the ledger as an observation.
    /// </summary>
    [Fact]
    public async Task ResourceMetricsAreReportedAsUnavailableRatherThanInvented()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken);
        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        await daemon;
        listener.Stop();

        // Assert the run actually succeeded first: metrics are null on the timeout path too, so
        // without this the test would pass even if the bridge never reached the daemon at all.
        Assert.Equal(0, result.ExitCode);
        Assert.False(result.TimedOut);

        Assert.Null(result.FinalMetrics.PeakMemoryBytes);
        Assert.Null(result.FinalMetrics.TotalCpuKernelTimeMs);
        Assert.Null(result.FinalMetrics.ActiveProcessCount);
    }
}
