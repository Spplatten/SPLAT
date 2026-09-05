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
    private readonly bool _useVsock;
    private readonly string _authTokenPath;

    /// <summary>
    /// The daemon's shared secret, cached for the life of this executor.
    ///
    /// Fetched through `wsl.exe -u root cat`, because the file is mode 0600 and root-owned: that is
    /// what stops an unprivileged process INSIDE the guest from issuing itself a lease, which is the
    /// threat the daemon's gate exists to close. It does not stop another Windows process running as
    /// this same user, and the daemon's own header says so.
    /// </summary>
    private string? _cachedToken;
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    public WslLeasedExecutor(
        string host = "127.0.0.1",
        int port = 50051,
        bool useVsock = false,
        string authTokenPath = "/etc/splat/agent.token",
        string? authToken = null)
    {
        _host = host;
        _port = port;
        _useVsock = useVsock;
        _authTokenPath = authTokenPath;
        // An explicit token, then the environment, then the guest file. The first two exist so a
        // host that already holds the secret - or a test driving the wire against a stand-in
        // listener - never has to shell into WSL to learn something it was told.
        _cachedToken = !string.IsNullOrWhiteSpace(authToken)
            ? authToken
            : Environment.GetEnvironmentVariable("SPLAT_AGENT_TOKEN");
    }

    /// <summary>The envelope version this bridge speaks; the daemon refuses anything else.</summary>
    private const int ProtocolVersion = 2;

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

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, lease.LeaseDurationSeconds)));

        try
        {
            await EnsureDaemonRunningAsync(cts.Token);

            using var client = new TcpClient();
            
            // Connect to guest daemon (AF_VSOCK port mapped or loopback mirrored)
            await client.ConnectAsync(_host, _port, cts.Token);
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.UTF8);
            // UTF-8 WITHOUT a byte order mark. `Encoding.UTF8` emits one, so StreamWriter prepended
            // EF BB BF to the first write and the daemon answered every request with
            // "Invalid JSON request: expected value at line 1 column 1". A BOM is meaningless on a
            // socket and fatal to a line-delimited JSON protocol.
            using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
            {
                AutoFlush = true
            };

            // The daemon refuses an EXECUTE_TOOL that does not present its token, so a bridge that
            // cannot read one has nothing to send and should say why rather than get a bare refusal.
            string? authToken = await GetAuthTokenAsync(cts.Token);
            if (string.IsNullOrEmpty(authToken))
            {
                throw new InvalidOperationException(
                    $"Could not read the SPLAT daemon auth token at {_authTokenPath} inside WSL. " +
                    "The daemon generates it on first run as root; without it no lease can be requested.");
            }

            // 1. Serialize Lease Request Envelope
            var payload = new
            {
                type = "EXECUTE_TOOL",
                protocolVersion = ProtocolVersion,
                authToken,
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
            await writer.WriteLineAsync(jsonPayload.AsMemory(), cts.Token);

            // 2. Stream Inbound Output Chunks
            while (!cts.Token.IsCancellationRequested)
            {
                string? line = await reader.ReadLineAsync(cts.Token);
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
    /// Reads the daemon's token out of the guest, once per executor.
    ///
    /// Read AFTER EnsureDaemonRunningAsync, never before: the file does not exist until the daemon
    /// has started once, so fetching it first would fail on every clean machine.
    /// </summary>
    private async Task<string?> GetAuthTokenAsync(CancellationToken ct)
    {
        if (_cachedToken is { Length: > 0 })
        {
            return _cachedToken;
        }

        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_cachedToken is { Length: > 0 })
            {
                return _cachedToken;
            }

            var psi = new ProcessStartInfo
            {
                FileName = "wsl.exe",
                // -u root because the token is 0600 and root-owned. Reading it any other way would
                // mean the file was readable to an unprivileged guest process, which is the state
                // the daemon warns about at startup.
                Arguments = $"-u root -e /bin/cat {_authTokenPath}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null)
            {
                return null;
            }

            string output = await proc.StandardOutput.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);

            if (proc.ExitCode != 0)
            {
                return null;
            }

            // WSL hands back UTF-16-ish noise on some hosts; keep only the hex the daemon emits.
            string token = new string(output.Where(Uri.IsHexDigit).ToArray());
            _cachedToken = token.Length > 0 ? token : null;
            return _cachedToken;
        }
        catch
        {
            return null;
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private async Task EnsureDaemonRunningAsync(CancellationToken ct)
    {
        try
        {
            using var probe = new TcpClient();
            var connectTask = probe.ConnectAsync(_host, _port, ct).AsTask();
            if (await Task.WhenAny(connectTask, Task.Delay(200, ct)) == connectTask && probe.Connected)
            {
                return;
            }
        }
        catch
        {
            // Daemon is not responding; attempt to bootstrap it in WSL2
        }

        try
        {
            // Loopback only. This previously launched the daemon with `--listen 0.0.0.0:50051`,
            // undoing the fix that made the daemon's own default loopback: the control plane that
            // executes leased processes was reachable from the guest's network interfaces - and on
            // the LAN under mirrored networking - as an unauthenticated way to run commands inside
            // the sandbox. Binding a containment control plane to a wildcard address is never right.
            //
            // The binary is taken from the build's CARGO_TARGET_DIR (see run-daemon.sh) with the
            // in-tree target/ as a fallback; the old path named only the latter, which the standard
            // build never produces.
            const string daemonPaths =
                "/tmp/splat_agent_target/release/splat-agent " +
                "/mnt/c/C_AGENT_BUILDER/native/splat-agent/target/release/splat-agent";

            var psi = new ProcessStartInfo
            {
                FileName = "wsl.exe",
                Arguments =
                    "-u root -e /bin/bash -l -c \"export PATH=/root/.cargo/bin:$PATH; " +
                    "if ! pgrep -x splat-agent >/dev/null; then " +
                    $"for d in {daemonPaths}; do " +
                    "[ -x \\\"$d\\\" ] && { \\\"$d\\\" --listen 127.0.0.1:50051 >/tmp/splat-agent.log 2>&1 & break; }; " +
                    "done; fi\"",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = Process.Start(psi);
            if (proc != null)
            {
                await proc.WaitForExitAsync(ct);
                await Task.Delay(400, ct);
            }
        }
        catch
        {
            // Best-effort daemon bootstrap
        }
    }
}