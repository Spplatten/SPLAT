using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
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

    /// <summary>
    /// Stands in for the idle wsl.exe session a lease holds, and counts it. These tests talk to a
    /// stand-in daemon in this process, so none of them may boot the real guest.
    /// </summary>
    private sealed class GuestHold : IDisposable
    {
        private int _opened;
        private int _released;

        public int Opened => Volatile.Read(ref _opened);

        public bool IsHeld => Volatile.Read(ref _opened) > Volatile.Read(ref _released);

        public IDisposable Open()
        {
            Interlocked.Increment(ref _opened);
            return this;
        }

        public void Dispose() => Interlocked.Increment(ref _released);
    }

    private static IDisposable NoGuest() => new GuestHold().Open();

    /// <summary>
    /// WSL stops a distro about fifteen seconds after its last Windows-side session ends, and systemd
    /// stops the daemon with it: on a machine with no WSL window open, a 75-second lease was killed 15
    /// seconds in (2026-09-18). So the bridge holds a session from before it connects until the lease
    /// is over, and lets it go then.
    /// </summary>
    [Fact]
    public async Task TheGuestIsHeldAwakeForTheWholeLease_AndReleasedAfter()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var hold = new GuestHold();
        bool heldWhenReached = false;

        var daemon = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            heldWhenReached = hold.IsHeld;
            using var stream = client.GetStream();
            return await StandInAgent.ServeAsync(stream, TestToken, new[] { "{\"type\":\"EXIT\",\"exitCode\":0}" });
        });

        var result = await new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: hold.Open)
            .ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());
        await daemon;
        listener.Stop();

        Assert.True(result.ExitCode == 0, result.StandardError);
        Assert.True(heldWhenReached, "the daemon was reached with nothing holding the guest awake");
        Assert.Equal(1, hold.Opened);
        Assert.False(hold.IsHeld, "the session outlived the lease");
    }

    [Fact]
    public async Task ALeaseThatFails_StillLetsTheGuestGo()
    {
        var hold = new GuestHold();
        var executor = new WslLeasedExecutor("127.0.0.1", UnusedPort(), new WslAgentToken(authToken: TestToken),
            _ => Task.FromResult(5), holdGuestAwake: hold.Open);

        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        Assert.NotEqual(0, result.ExitCode);
        Assert.Equal(1, hold.Opened);
        Assert.False(hold.IsHeld, "a failed lease kept the guest awake");
    }

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
    /// Plays the daemon, protocol 3 handshake and all, on the next connection that says anything, and
    /// replies to its request with the given frames.
    ///
    /// A connection that closes without sending anything - a bridge that refused before it had a
    /// request to send - is skipped, so a request that does follow is still captured and answered.
    /// </summary>
    private static async Task<StandInAgent.Exchange> RunStandInDaemonAsync(TcpListener listener, params string[] responseFrames)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();

            var exchange = await StandInAgent.ServeAsync(stream, TestToken, responseFrames);
            if (exchange.Raw.Length > 0)
            {
                return exchange;
            }
        }

        return new StandInAgent.Exchange(Array.Empty<byte>(), null, false);
    }

    /// <summary>
    /// The health check is a request like any other, so it proves the token - and it never carries the
    /// token itself. It was open until 2026-09-11, on the grounds that a liveness probe should not need a
    /// secret, and until protocol 3 it put the secret in the request.
    /// </summary>
    [Fact]
    public async Task TheHealthCheck_ProvesTheToken_WithoutSendingIt()
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

        var exchange = await daemon;
        listener.Stop();

        Assert.True(exchange.Proven, "the health check did not prove the token");
        Assert.Contains("\"HEALTH_CHECK\"", exchange.Request ?? "");
        Assert.DoesNotContain(TestToken, Encoding.UTF8.GetString(exchange.Raw));
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
            "{\"type\":\"STDERR\",\"data\":\"SPLAT refused the request: a reason of this test's choosing.\"}");

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

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        byte[] request = (await daemon).Raw;
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
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task TheDeclaredLeaseTravelsIntactToTheDaemon(bool allowScratchExec)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");

        var lease = SampleLease() with { OverlayFs = new OverlayFsSpec(true, "/unused", "/unused", allowScratchExec) };
        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        await executor.ExecuteLeasedAsync(lease, "/usr/bin/curl", new[] { "--max-time", "3" });

        var exchange = await daemon;
        listener.Stop();

        Assert.True(exchange.Proven, "the lease did not prove the token");
        using var doc = JsonDocument.Parse(exchange.Request ?? "");
        var root = doc.RootElement;

        Assert.Equal("EXECUTE_TOOL", root.GetProperty("type").GetString());
        Assert.Equal(3, root.GetProperty("protocolVersion").GetInt32());
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
        Assert.True(root.GetProperty("overlayFs").GetProperty("enableCow").GetBoolean());
        Assert.Equal(allowScratchExec, root.GetProperty("overlayFs").GetProperty("allowScratchExec").GetBoolean());
    }

    /// <summary>
    /// The daemon refuses any request that does not prove the token, and the token itself never travels.
    /// Protocol 2 carried it in every request, so the bridge handed it to whatever answered on the port.
    /// </summary>
    [Fact]
    public async Task TheTokenNeverCrossesTheWire_OnlyProofsOfIt()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        var exchange = await daemon;
        listener.Stop();

        Assert.Equal(0, result.ExitCode);
        Assert.True(exchange.Proven, "the request did not prove the token");
        Assert.DoesNotContain(TestToken, Encoding.UTF8.GetString(exchange.Raw));
        using var doc = JsonDocument.Parse(exchange.Request ?? "");
        Assert.False(doc.RootElement.TryGetProperty("authToken", out _), "the request still names the token");
    }

    /// <summary>
    /// Anything on the daemon's port that cannot prove it holds the token is sent the handshake's nonce and
    /// nothing else: not the lease, not the command, and not the token. On 2026-09-13 a listener run as
    /// nobody on a free loopback port received what Windows sent it, and under protocol 2 that was the token.
    /// </summary>
    [Fact]
    public async Task AnImpostorOnTheDaemonsPort_IsSentNothingButTheNonce()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        // It has no token, so the proof it offers is made under a guess.
        var impostor = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            return await StandInAgent.ImpersonateAsync(stream, clientNonce =>
            {
                byte[] serverNonce = RandomNumberGenerator.GetBytes(WslAgentSession.ProofBytes);
                byte[] guess = Encoding.UTF8.GetBytes("a guess at the token");
                return StandInAgent.Challenge(serverNonce, WslAgentSession.DaemonProof(guess, clientNonce, serverNonce));
            });
        });

        try
        {
            var result = await new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest)
                .ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());
            string[] sent = StandInAgent.Frames(await impostor);

            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("did not prove it holds this host's token", result.StandardError);
            string hello = Assert.Single(sent);
            Assert.Contains("\"HELLO\"", hello);
            Assert.DoesNotContain(TestToken, hello);
        }
        finally
        {
            listener.Stop();
        }
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
                "127.0.0.1", port, authTokenPath: "/nonexistent/splat/agent.token", holdGuestAwake: NoGuest);

            var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

            // This class reports transport failures rather than throwing, so the refusal arrives
            // the same way every other one does.
            Assert.NotEqual(0, result.ExitCode);
            Assert.Contains("auth token", result.StandardError, StringComparison.OrdinalIgnoreCase);

            // The property that matters: nothing reached the wire. The bridge stopped before it
            // could send an envelope the daemon would only have refused anyway.
            var finished = await Task.WhenAny(daemon, Task.Delay(500));
            Assert.True(
                finished != daemon || (await daemon).Raw.Length == 0,
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
            var result = await new WslLeasedExecutor("127.0.0.1", port, slowToken, holdGuestAwake: NoGuest)
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
        }, holdGuestAwake: NoGuest);

        try
        {
            var first = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());
            Assert.True(first.ExitCode == 0, first.StandardError);

            // It answers now, and a daemon that answers is never started again.
            var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":0}");
            var second = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());
            Assert.True(second.ExitCode == 0, second.StandardError);
            Assert.Contains("EXECUTE_TOOL", (await daemon).Request ?? "");

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
            _ => Task.FromResult(5), holdGuestAwake: NoGuest);

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
        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
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
    /// The daemon frames a tool's output in 64 KiB pieces so the guest never holds it whole. This host
    /// held it whole, in a StringBuilder with no ceiling. The result is now capped per stream and says
    /// so; a streaming consumer still receives every byte.
    /// </summary>
    [Fact]
    public async Task OutputPastTheCap_IsDroppedFromTheResult_AndSaidSo_WhileStreamingSeesItAll()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        const int frameChars = 64 * 1024;
        int frameCount = WslLeasedExecutor.MaxCapturedCharsPerStream / frameChars + 4;
        string data = new string('x', frameChars);
        var frames = new List<string>();
        for (int i = 0; i < frameCount; i++)
        {
            frames.Add("{\"type\":\"STDOUT\",\"data\":\"" + data + "\"}");
        }
        frames.Add("{\"type\":\"EXIT\",\"exitCode\":0}");
        var daemon = RunStandInDaemonAsync(listener, frames.ToArray());

        var streamed = new CountingProgress();
        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/yes", Array.Empty<string>(), stdout: streamed);

        await daemon;
        listener.Stop();

        Assert.Equal(0, result.ExitCode);
        Assert.Equal((long)frameCount * frameChars, streamed.Chars);
        Assert.Contains("[OUTPUT_TRUNCATED]", result.StandardOutput, StringComparison.Ordinal);
        Assert.True(
            result.StandardOutput.Length < WslLeasedExecutor.MaxCapturedCharsPerStream + 256,
            $"the result kept {result.StandardOutput.Length} characters");
        Assert.DoesNotContain("[OUTPUT_TRUNCATED]", result.StandardError, StringComparison.Ordinal);
    }

    /// <summary>
    /// A full ring buffer loses refusal records. The kernel program counts those losses and the daemon reports
    /// the count in EXIT; a result that omitted it would present an incomplete violation list as complete.
    /// The record's own number and kernel clock ride along on each violation.
    /// </summary>
    [Fact]
    public async Task DroppedKernelRecords_AreSaidInTheResult_AndEachViolationCarriesItsNumber()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"VIOLATION\",\"cgroupId\":4020,\"pid\":8540,\"hook\":1,\"detail\":1633," +
            "\"detailText\":\"bprm_check_security: denied execution of unleased binary (inode 1633)\",\"comm\":\"sh\"," +
            "\"timestampMs\":1758300000000,\"ktimeNs\":123456789,\"seq\":41}",
            "{\"type\":\"EXIT\",\"exitCode\":1,\"violationsDropped\":3}");

        var seen = new List<LeaseViolationEvent>();
        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(
            SampleLease(), "/bin/sh", new[] { "-c", "ls" },
            violations: new Progress<LeaseViolationEvent>(v => { lock (seen) { seen.Add(v); } }));

        await daemon;
        listener.Stop();

        Assert.Equal(1, result.ExitCode);
        Assert.Contains("[KERNEL_EVENTS_DROPPED] 3", result.StandardError, StringComparison.Ordinal);
        for (int i = 0; i < 50 && seen.Count == 0; i++)
        {
            await Task.Delay(20);
        }

        var violation = Assert.Single(seen);
        Assert.Equal(41ul, violation.Sequence);
        Assert.Equal(123456789ul, violation.KernelTimeNs);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1758300000000).UtcDateTime, violation.TimestampUtc);
    }

    /// <summary>
    /// A lease's receipt says whether it is the whole of what the kernel refused.
    ///
    /// The count comes from the kernel's own per-cgroup map rather than from the frames that
    /// arrived, and EXIT carries both so they can be compared. Before this the bridge could only
    /// report what it received, so a refusal whose frame was lost and a lease that was never denied
    /// anything produced the same result - which is what the root probe of 2026-09-25 hit: it scored
    /// its UDP check false while that same run's violation list held `socket_sendmsg: denied
    /// outbound datagram to unapproved IPv4 1.1.1.1`. The wall held; the receipt did not say so.
    ///
    /// Asserted in both directions, because a field that is only ever true proves nothing.
    /// </summary>
    [Theory]
    [InlineData(2, 2, true, false)]
    [InlineData(2, 1, false, true)]
    public async Task TheLeaseSays_WhetherItsRefusalListIsTheWholeOfWhatTheKernelRefused(
        int counted, int reported, bool complete, bool expectTheNote)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"LEASE\",\"cgroupId\":4021,\"enforcing\":true,\"workloadUid\":65534}",
            "{\"type\":\"EXIT\",\"exitCode\":0,\"violationsDropped\":0," +
            $"\"violationsCounted\":{counted},\"violationsReported\":{reported}," +
            $"\"violationsComplete\":{(complete ? "true" : "false")}}}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(
            SampleLease(), "/bin/sh", new[] { "-c", "ls" });

        await daemon;
        listener.Stop();

        Assert.NotNull(result.Lease);
        Assert.Equal((ulong)counted, result.Lease!.ViolationsCounted);
        Assert.Equal((ulong)reported, result.Lease!.ViolationsReported);
        Assert.Equal(complete, result.Lease!.ViolationsComplete);

        // The operator watching the run is told too, not only a record reader afterwards.
        Assert.Equal(
            expectTheNote,
            result.StandardError.Contains("[KERNEL_EVENTS_INCOMPLETE]", StringComparison.Ordinal));
    }

    /// <summary>
    /// A daemon that predates the count sends neither field, and the outcome reports unknown rather
    /// than a confident zero - which would be the same defect wearing the other mask.
    /// </summary>
    [Fact]
    public async Task ADaemonThatCannotCountRefusals_ReportsUnknown_NotNoneRefused()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"LEASE\",\"cgroupId\":4022,\"enforcing\":true,\"workloadUid\":65534}",
            "{\"type\":\"EXIT\",\"exitCode\":0,\"violationsDropped\":0}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(
            SampleLease(), "/bin/sh", new[] { "-c", "ls" });

        await daemon;
        listener.Stop();

        Assert.NotNull(result.Lease);
        Assert.Null(result.Lease!.ViolationsCounted);
        Assert.Null(result.Lease!.ViolationsComplete);
        Assert.DoesNotContain("[KERNEL_EVENTS_INCOMPLETE]", result.StandardError, StringComparison.Ordinal);
    }

    /// <summary>
    /// The guest's signature over its outcome reaches the host unaltered (roadmap 2.5).
    ///
    /// Carried as four opaque strings and stored exactly as they arrived. This host is the party the
    /// signature exists to constrain, so it does not normalise, re-encode or rebuild any of them -
    /// a host that "helpfully" canonicalised the signed text would break every verification and
    /// look like tampering, which in a sense it would be.
    /// </summary>
    [Fact]
    public async Task TheGuestsSignatureOverItsOutcome_ReachesTheHostVerbatim()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        const string canonical = "splat-lease-outcome/1|mission=m-1|cgroup=4021|enforcing=true|uid=65534|exit=0";
        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"LEASE\",\"cgroupId\":4021,\"enforcing\":true,\"workloadUid\":65534}",
            "{\"type\":\"EXIT\",\"exitCode\":0,\"violationsDropped\":0,\"violationsCounted\":0," +
            "\"violationsReported\":0,\"violationsComplete\":true," +
            $"\"outcomeCanonical\":\"{canonical}\"," +
            "\"outcomeSignature\":\"c2lnbmF0dXJl\",\"outcomeKeyId\":\"abc123\",\"outcomePublicKey\":\"cHVibGlj\"}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(
            SampleLease(), "/bin/sh", new[] { "-c", "ls" });

        await daemon;
        listener.Stop();

        Assert.NotNull(result.Lease);
        Assert.Equal(canonical, result.Lease!.SignedOutcome);
        Assert.Equal("c2lnbmF0dXJl", result.Lease!.OutcomeSignature);
        Assert.Equal("abc123", result.Lease!.OutcomeKeyId);
        Assert.Equal("cHVibGlj", result.Lease!.OutcomePublicKey);
    }

    /// <summary>
    /// A daemon with no key signs nothing, and the outcome says so rather than carrying an empty
    /// signature a reader might mistake for one that was checked.
    /// </summary>
    [Fact]
    public async Task ADaemonWithNoKey_LeavesTheOutcomeUnsigned()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(
            listener,
            "{\"type\":\"LEASE\",\"cgroupId\":4023,\"enforcing\":true,\"workloadUid\":65534}",
            "{\"type\":\"EXIT\",\"exitCode\":0,\"violationsDropped\":0}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(
            SampleLease(), "/bin/sh", new[] { "-c", "ls" });

        await daemon;
        listener.Stop();

        Assert.NotNull(result.Lease);
        Assert.Null(result.Lease!.SignedOutcome);
        Assert.Null(result.Lease!.OutcomeSignature);
    }

    /// <summary>Counts what a streaming consumer received, on whatever thread it arrived.</summary>
    private sealed class CountingProgress : IProgress<string>
    {
        public long Chars;

        public void Report(string value) => System.Threading.Interlocked.Add(ref Chars, value.Length);
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

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
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

    [Fact]
    public async Task CallerCancellation_IsNotReportedAsLeaseTimeout()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var barrier = new TaskCompletionSource<bool>();
        var daemon = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var raw = new MemoryStream();
            byte[]? clientNonce = StandInAgent.ClientNonce(await StandInAgent.ReadLineAsync(stream, raw, default));
            byte[] key = Encoding.UTF8.GetBytes(TestToken);
            byte[] serverNonce = RandomNumberGenerator.GetBytes(WslAgentSession.ProofBytes);
            await StandInAgent.WriteLineAsync(stream, StandInAgent.Challenge(serverNonce, WslAgentSession.DaemonProof(key, clientNonce!, serverNonce, provesFrames: true), framesProven: true), default);
            string? frame = await StandInAgent.ReadLineAsync(stream, raw, default);
            barrier.SetResult(true);
            try
            {
                await Task.Delay(10000);
            }
            catch (Exception) { }
            return true;
        });

        using var callerCts = new CancellationTokenSource();
        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);

        var executeTask = executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>(), ct: callerCts.Token);
        await barrier.Task;
        callerCts.Cancel();

        var result = await executeTask;
        listener.Stop();

        Assert.False(result.TimedOut, "Caller cancellation was misreported as lease timeout");
        Assert.Equal("CallerCancelled", result.TerminalReason);
        Assert.Equal(-3, result.ExitCode);
        Assert.Contains("[EXECUTION_CANCELLED]", result.StandardError);
        Assert.DoesNotContain("Process killed by kernel/daemon", result.StandardError);
    }

    [Fact]
    public async Task AbruptDisconnect_IsNotSuccess_AndReportsDisconnect()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, Array.Empty<string>());

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        await daemon;
        listener.Stop();

        Assert.NotEqual(0, result.ExitCode);
        Assert.False(result.TimedOut);
        Assert.Equal("AbruptDisconnect", result.TerminalReason);
        Assert.Contains("[DAEMON_DISCONNECTED]", result.StandardError);
    }

    [Fact]
    public async Task ExplicitExit_PreservesCodeAndTerminalReason()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = RunStandInDaemonAsync(listener, "{\"type\":\"EXIT\",\"exitCode\":42}");

        var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: TestToken, holdGuestAwake: NoGuest);
        var result = await executor.ExecuteLeasedAsync(SampleLease(), "/usr/bin/id", Array.Empty<string>());

        await daemon;
        listener.Stop();

        Assert.Equal(42, result.ExitCode);
        Assert.False(result.TimedOut);
        Assert.Equal("ExplicitExit", result.TerminalReason);
    }
}
