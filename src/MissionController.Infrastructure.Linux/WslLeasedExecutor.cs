using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Linux;

/// <summary>
/// Executes a sandboxed command inside the WSL2 / eBPF guest daemon over Hyper-V VSOCK / TCP transport.
/// Handles structured tool output streaming and surfaces in-kernel BPF-LSM violation events.
/// </summary>
public class WslLeasedExecutor : ILeasedExecutor
{
    private readonly string _host;
    private readonly int _port;

    /// <summary>
    /// The daemon's shared secret. Read once a connection to the daemon is open, never before: the file
    /// does not exist until the daemon has started once.
    /// </summary>
    private readonly WslAgentToken _token;

    /// <summary>What runs when a connection is refused; its exit code says whether the daemon started.</summary>
    private readonly Func<CancellationToken, Task<int>> _startDaemon;

    /// <summary>
    /// For reaching a daemon whose port refused the first connection: long enough to boot a stopped
    /// guest, have systemd start the service and let the daemon load its BPF programs before it binds;
    /// bounded, so a service that starts and then exits refuses the lease instead of holding it open.
    /// </summary>
    private static readonly TimeSpan DaemonStartBudget = TimeSpan.FromSeconds(30);

    /// <summary>For the handshake, which a live daemon answers at once; see <see cref="OpenSessionAsync"/>.</summary>
    private static readonly TimeSpan HandshakeBudget = TimeSpan.FromSeconds(10);

    /// <param name="authTokenPath">
    /// Where the daemon keeps its shared secret inside the guest.
    /// </param>
    /// <remarks>
    /// There was a <c>useVsock</c> parameter here that was stored and never read. AF_VSOCK is the
    /// transport that would let the daemon identify its peer instead of trusting a shared secret
    /// (see auth.rs), but none of it is implemented, and a constructor flag that silently does
    /// nothing reads as a capability the caller can select.
    /// </remarks>
    public WslLeasedExecutor(
        string host = "127.0.0.1",
        int port = 50051,
        string authTokenPath = "/etc/splat/agent.token",
        string? authToken = null)
        // The shared default unless this caller named its own path or token, so one host reads the
        // secret once however many components talk to the daemon.
        : this(host, port, authTokenPath == WslAgentToken.DefaultPath && string.IsNullOrWhiteSpace(authToken)
            ? WslAgentToken.Default
            : new WslAgentToken(authTokenPath, authToken))
    {
    }

    /// <param name="token">The daemon's secret, for a host or a test that obtains it its own way.</param>
    /// <param name="startDaemon">
    /// What to run when nothing is listening; by default `systemctl start splat-agent` as root in the
    /// guest. Replaceable so that a test can stand in for the service instead of starting the real one.
    /// </param>
    public WslLeasedExecutor(string host, int port, WslAgentToken token, Func<CancellationToken, Task<int>>? startDaemon = null)
    {
        ArgumentNullException.ThrowIfNull(token);
        _host = host;
        _port = port;
        _token = token;
        _startDaemon = startDaemon ?? StartInstalledServiceAsync;
    }

    public async Task<ProcessExecutionResult> ExecuteLeasedAsync(
        LeaseSpec lease,
        string command,
        IReadOnlyList<string> argv,
        IProgress<string>? stdout = null,
        IProgress<string>? stderr = null,
        IProgress<LeaseViolationEvent>? violations = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentNullException.ThrowIfNull(argv);
        ArgumentException.ThrowIfNullOrWhiteSpace(command);

        var stopwatch = Stopwatch.StartNew();
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();
        int exitCode = -1;
        bool timedOut = false;

        try
        {
            // Nothing before the request is the workload, so none of it is charged to the lease. Its clock
            // used to start here and pay for starting the daemon, the connect and a cold wsl.exe token
            // read, so a slow start came back as an expired lease and a slow read as a missing token.
            using var client = await ConnectToDaemonAsync(ct);
            using var stream = client.GetStream();

            // The daemon refuses a caller that cannot prove it holds the token, so a bridge that cannot read
            // one has nothing to prove and should say why rather than get a bare refusal.
            string? authToken;
            using (var tokenCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                tokenCts.CancelAfter(WslAgentToken.ReadBudget);
                authToken = await _token.GetAsync(tokenCts.Token);
            }

            if (string.IsNullOrEmpty(authToken))
            {
                throw new InvalidOperationException(
                    $"Could not read the SPLAT daemon auth token at {_token.Path} inside WSL. " +
                    "The daemon generates it on first run as root; without it no lease can be requested.");
            }

            // Whatever answered must prove it holds the token before a byte of the lease is sent to it.
            using var session = await OpenSessionAsync(stream, authToken, ct);

            // 1. Serialize Lease Request Envelope
            var payload = new
            {
                type = "EXECUTE_TOOL",
                protocolVersion = WslAgentSession.ProtocolVersion,
                missionId = lease.MissionId.ToString(),
                command = command,
                argv,
                workingDirectory = lease.WorkingDirectory,
                allowNetwork = lease.AllowNetwork,
                allowedEgressIps = lease.AllowedEgressIps,
                allowedEgressPorts = lease.AllowedEgressPorts,
                readOnlyFs = lease.ReadOnlyFs,
                // The compiled policy, as PATHS. The lease carries InodeIdentifierModel, but a
                // Windows-side inode number means nothing in the guest - TemplatePolicyCompiler
                // already fills them with (0, 0, path), which says the path was always the payload.
                // These were dropped from the envelope entirely, so the daemon fell back to its own
                // hardcoded defaults and the compiled policy was not the authorization source for
                // this path at all.
                protectedPaths = lease.ProtectedInodes.Select(i => i.SourcePath).ToArray(),
                allowedExecPaths = lease.AllowedExecInodes.Select(i => i.SourcePath).ToArray(),
                leaseDurationSeconds = lease.LeaseDurationSeconds,
                limits = new
                {
                    maxMemoryBytes = lease.Limits.MaxMemoryBytes,
                    maxCpuPercent = lease.Limits.MaxCpuPercent,
                    maxPids = lease.Limits.MaxPids
                },
                overlayFs = lease.OverlayFs != null ? new
                {
                    enableCow = lease.OverlayFs.EnableCow,
                    lowerDir = lease.OverlayFs.LowerDir,
                    scratchDir = lease.OverlayFs.ScratchDir
                } : null
            };

            string jsonPayload = JsonSerializer.Serialize(payload);

            // The lease's clock starts with the request it times.
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, lease.LeaseDurationSeconds)));
            await session.SendAsync(jsonPayload, cts.Token);

            // 2. Stream Inbound Output Chunks
            while (!cts.Token.IsCancellationRequested)
            {
                string? line = await session.ReadLineAsync(cts.Token);
                if (line == null) break;

                if (string.IsNullOrWhiteSpace(line)) continue;

                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    string chunkType = root.TryGetProperty("type", out var typeProp) ? typeProp.GetString() ?? "" : "";

                    switch (chunkType)
                    {
                        case "STDOUT":
                            if (root.TryGetProperty("data", out var dataProp))
                            {
                                string text = dataProp.GetString() ?? "";
                                stdoutBuilder.Append(text);
                                stdout?.Report(text);
                            }
                            break;

                        case "STDERR":
                            if (root.TryGetProperty("data", out var errDataProp))
                            {
                                string text = errDataProp.GetString() ?? "";
                                stderrBuilder.Append(text);
                                stderr?.Report(text);
                            }
                            break;

                        case "VIOLATION":
                            // In-Kernel BPF-LSM -EPERM Violation Streamed from RingBuffer
                            ulong cgid = root.TryGetProperty("cgroupId", out var cgProp) ? cgProp.GetUInt64() : 0;
                            uint pid = root.TryGetProperty("pid", out var pidProp) ? pidProp.GetUInt32() : 0;
                            int hookVal = root.TryGetProperty("hook", out var hookProp) ? hookProp.GetInt32() : 0;
                            ulong detail = root.TryGetProperty("detail", out var detailProp) ? detailProp.GetUInt64() : 0;
                            string detailText = root.TryGetProperty("detailText", out var dtProp) ? dtProp.GetString() ?? "" : "";
                            string comm = root.TryGetProperty("comm", out var commProp) ? commProp.GetString() ?? "" : "";

                            var vEvent = new LeaseViolationEvent(
                                CgroupId: cgid,
                                ProcessId: pid,
                                Hook: (KernelViolationHook)hookVal,
                                Detail: detail,
                                DetailText: detailText,
                                ProcessComm: comm,
                                TimestampUtc: DateTime.UtcNow);

                            violations?.Report(vEvent);
                            stderr?.Report($"[KERNEL -EPERM BLOCK] [{comm} pid {pid}] {detailText}\n");
                            break;

                        case "EXIT":
                            if (root.TryGetProperty("exitCode", out var exitProp))
                            {
                                exitCode = exitProp.GetInt32();
                            }
                            return new ProcessExecutionResult(
                                ExitCode: exitCode,
                                StandardOutput: stdoutBuilder.ToString(),
                                StandardError: stderrBuilder.ToString(),
                                TimedOut: false,
                                // The guest daemon's EXIT frame carries no cgroup accounting, so
                                // nothing here was measured. This previously returned
                                // MaxMemoryBytes/4 as peak memory and half the wall clock as each
                                // CPU figure - arithmetic on constants, surfaced through
                                // MissionChunkType.Metric as observed values and sealed into the
                                // ledger as evidence. Report the absence instead; when the daemon
                                // starts reporting cgroup counters, populate these from the frame.
                                FinalMetrics: JobResourceMetrics.Unavailable);
                    }
                }
                catch (JsonException)
                {
                    // Plaintext fallback chunk
                    stdoutBuilder.AppendLine(line);
                    stdout?.Report(line + "\n");
                }
            }
        }
        catch (OperationCanceledException)
        {
            timedOut = true;
            stderrBuilder.AppendLine("[EXECUTION_TIMEOUT] Lease duration expired. Process killed by kernel/daemon.");
        }
        catch (Exception ex)
        {
            stderrBuilder.AppendLine($"[DAEMON_COMMUNICATION_ERROR] {ex.Message}");
        }

        stopwatch.Stop();
        return new ProcessExecutionResult(
            ExitCode: timedOut ? -2 : exitCode,
            StandardOutput: stdoutBuilder.ToString(),
            StandardError: stderrBuilder.ToString(),
            TimedOut: timedOut,
            // Timeout / transport-failure path: the run was cut short, so there is even less to
            // report than on the EXIT path. Nothing measured, nothing claimed.
            FinalMetrics: JobResourceMetrics.Unavailable);
    }

    /// <summary>
    /// Protocol 3's handshake, under a budget of its own. A live daemon answers it at once, so a listener
    /// that accepts the connection and then says nothing is refused rather than left holding the lease open.
    /// </summary>
    private static async Task<WslAgentSession> OpenSessionAsync(Stream stream, string token, CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(HandshakeBudget);
        try
        {
            return await WslAgentSession.OpenAsync(stream, token, budget.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"Waited {HandshakeBudget.TotalSeconds:0} seconds for the daemon to answer the protocol "
                + $"{WslAgentSession.ProtocolVersion} handshake.");
        }
    }

    /// <summary>
    /// An open connection to the daemon, starting the installed service first if nothing is listening.
    ///
    /// This used to race a probe connect against 200 ms and, whenever the probe lost - which load makes
    /// likely - run a root script that launched the first splat-agent it found at
    /// /tmp/splat_agent_target or in this repository's target/, if pgrep saw none running. A connect
    /// that loses a race is not an absent daemon; and the guest's /tmp is world-writable, so any
    /// unprivileged process in it, a leased workload included, could leave a file there for root to
    /// run. Now only a refused connection means nothing is listening, and the one thing started is the
    /// unit `splat-mcp provision` installs, whose binary is root's own under /opt/splat.
    /// </summary>
    private async Task<TcpClient> ConnectToDaemonAsync(CancellationToken ct)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(DaemonStartBudget);

        // What the budget is being spent on, so running out of it names the step that never finished.
        string waitingFor = $"an answer from {_host}:{_port}";
        bool started = false;

        try
        {
            while (true)
            {
                var client = new TcpClient();
                try
                {
                    await client.ConnectAsync(_host, _port, budget.Token);
                    return client;
                }
                catch (Exception ex)
                {
                    client.Dispose();
                    if (ex is not SocketException { SocketErrorCode: SocketError.ConnectionRefused })
                    {
                        throw;
                    }
                }

                if (!started)
                {
                    waitingFor = "`systemctl start splat-agent` in WSL to return";
                    int exit = await _startDaemon(budget.Token);
                    if (exit != 0)
                    {
                        throw new InvalidOperationException(
                            $"Nothing is listening at {_host}:{_port}, and `systemctl start splat-agent` in WSL exited {exit}"
                            + (exit == 5 ? " - the service is not installed." : ".")
                            + " `splat-mcp provision --apply` installs and starts it.");
                    }

                    started = true;
                    waitingFor = $"splat-agent to listen at {_host}:{_port} once started; `journalctl -u splat-agent` in WSL says why it did not";
                }

                // Windows paces this already - a refused loopback connect takes it about two seconds - but
                // not every host refuses that slowly.
                await Task.Delay(TimeSpan.FromMilliseconds(250), budget.Token);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"Waited {DaemonStartBudget.TotalSeconds:0} seconds for {waitingFor}.");
        }
    }

    /// <summary>
    /// `systemctl start splat-agent` as root in the guest, booting the guest first if it has stopped, and
    /// its exit code: 0 once the unit is running, 5 when it is not installed.
    /// </summary>
    private static async Task<int> StartInstalledServiceAsync(CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "wsl.exe",
            // An absolute path and no shell: this runs as root, so nothing in it is looked up.
            Arguments = "-u root -e /bin/systemctl start splat-agent",
            UseShellExecute = false,
            // All three. Under splat-mcp this process's stdin and stdout are the JSON-RPC channel: an
            // inherited stdin is consumed by wsl.exe, and anything written to an inherited stdout lands
            // in the middle of a reply.
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("wsl.exe did not start.");
        proc.StandardInput.Close();

        // Drained, not read: the exit code is the answer, and the journal has the detail.
        await Task.WhenAll(
            proc.StandardOutput.ReadToEndAsync(ct),
            proc.StandardError.ReadToEndAsync(ct),
            proc.WaitForExitAsync(ct));
        return proc.ExitCode;
    }
}