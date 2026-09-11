using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
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
        string path = Path.Combine(
            RepositoryRoot(), "src", "MissionController.Infrastructure.Linux", "WslLeasedExecutor.cs");
        var declarations = File.ReadAllText(path)
            .Split("new ProcessStartInfo")
            .Skip(1)
            // Up to the Process.Start that consumes it. Not to the closing brace: one of these
            // initializers carries a shell snippet containing "};" inside a string literal.
            .Select(block => block[..Math.Max(0, block.IndexOf("Process.Start", StringComparison.Ordinal))])
            .ToList();

        Assert.NotEmpty(declarations);
        foreach (string declaration in declarations)
        {
            Assert.True(
                declaration.Contains("RedirectStandardInput = true", StringComparison.Ordinal),
                "A ProcessStartInfo in WslLeasedExecutor.cs does not redirect standard input, so the child "
                + "inherits the host's. Under splat-mcp that is the MCP client's JSON-RPC stream, and wsl.exe "
                + "consumes it:\n" + declaration);
        }
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

    /// <summary>
    /// Captures the raw request bytes and replies with the given frames.
    ///
    /// The executor opens a liveness probe connection before the real one and closes it without
    /// sending anything, so a single Accept would consume the probe and leave the actual request
    /// unanswered. Keep accepting until a connection actually says something.
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
                continue; // Probe hung up mid-read.
            }

            if (read == 0)
            {
                continue; // The liveness probe: connected, said nothing, closed.
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
