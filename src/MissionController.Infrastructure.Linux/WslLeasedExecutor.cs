using System;
using System.Collections.Generic;
using System.ComponentModel;
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
public partial class WslLeasedExecutor : ILeasedExecutor, ILeaseReceiptLookup
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
    /// Held for the whole of a lease, so WSL cannot stop the guest under it. WSL stops a distro about
    /// fifteen seconds after its last Windows-side session ends, and systemd stops the daemon with it:
    /// on a machine with no WSL window open, a 75-second lease was killed 15 seconds in (2026-09-18,
    /// exit -1). Neither the daemon nor the lease's own connection counts as a session; a wsl.exe does.
    /// </summary>
    private readonly Func<IDisposable> _holdGuestAwake;
    private static readonly SharedGuestHold GuestHold = new(IdleGuestSession.Open,
        session => ((IdleGuestSession)session).IsAlive);

    static WslLeasedExecutor() => AppDomain.CurrentDomain.ProcessExit += (_, _) => GuestHold.Dispose();

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
        string? authToken = null,
        Func<IDisposable>? holdGuestAwake = null)
        // The shared default unless this caller named its own path or token, so one host reads the
        // secret once however many components talk to the daemon.
        : this(host, port, authTokenPath == WslAgentToken.DefaultPath && string.IsNullOrWhiteSpace(authToken)
            ? WslAgentToken.Default
            : new WslAgentToken(authTokenPath, authToken), holdGuestAwake: holdGuestAwake)
    {
    }

    /// <param name="token">The daemon's secret, for a host or a test that obtains it its own way.</param>
    /// <param name="startDaemon">
    /// What to run when nothing is listening; by default `systemctl start splat-agent` as root in the
    /// guest. Replaceable so that a test can stand in for the service instead of starting the real one.
    /// </param>
    /// <param name="holdGuestAwake">
    /// What keeps the guest running for the length of a lease; by default an idle wsl.exe session.
    /// Replaceable so that a test against a stand-in daemon never boots the real guest.
    /// </param>
    public WslLeasedExecutor(
        string host,
        int port,
        WslAgentToken token,
        Func<CancellationToken, Task<int>>? startDaemon = null,
        Func<IDisposable>? holdGuestAwake = null)
    {
        ArgumentNullException.ThrowIfNull(token);
        _host = host;
        _port = port;
        _token = token;
        _startDaemon = startDaemon ?? StartInstalledServiceAsync;
        _holdGuestAwake = holdGuestAwake ?? GuestHold.Acquire;
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
        var stdoutBuilder = new CappedCapture();
        var stderrBuilder = new CappedCapture();
        int exitCode = -1;
        bool timedOut = false;
        string? terminalReason = null;
        // What the daemon said about the lease it installed, from its LEASE frame; the EXIT frame adds
        // whether the workspace it made is gone. Null until a daemon says, so a daemon older than the
        // frame reads back as nothing rather than as a lease it never described.
        LeaseOutcome? outcome = null;
        JobLimitsReadback? limitsReadBack = null;

        try
        {
            // Opened before the connect, so it also boots a stopped guest and holds it through the
            // daemon's start; released when this block is left, whatever the lease's outcome.
            using var awake = _holdGuestAwake();

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

            lease.ExecutionPolicy?.Validate();
            string? executionContext = lease.ExecutionContext is null ? null
                : JsonSerializer.Serialize(lease.ExecutionContext, BoundLeaseReceipt.Json);
            if (executionContext is not null && !session.FramesProven)
                throw new InvalidOperationException("Bound execution requires authenticated result frames.");
            // 1. Serialize Lease Request Envelope
            var payload = new
            {
                // Older guests reject an unknown operation; they must never ignore a restriction
                // attached to the legacy envelope and then launch with broader permissions.
                type = executionContext is not null ? "EXECUTE_BOUND" : lease.RequireEnforcing ? "EXECUTE_AGENT"
                    : lease.ExecutionPolicy is null ? "EXECUTE_TOOL" : "EXECUTE_POLICY",
                executionContext,
                executionPolicy = lease.ExecutionPolicy,
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
                // The daemon makes and removes the working directory for a governed mission: only
                // root in the guest can make one, and a directory that must already exist would send
                // the tool to /tmp instead. Absent on a daemon that predates the field, which then
                // runs the tool where the directory falls back to, and says so in its LEASE frame.
                ephemeralWorkspace = lease.EphemeralWorkspace,
                limits = new
                {
                    maxMemoryBytes = lease.Limits.MaxMemoryBytes,
                    maxCpuPercent = lease.Limits.MaxCpuPercent,
                    maxPids = lease.Limits.MaxPids
                },
                overlayFs = lease.OverlayFs != null ? new
                {
                    enableCow = lease.OverlayFs.EnableCow,
                    allowScratchExec = lease.OverlayFs.AllowScratchExec,
                    lowerDir = lease.OverlayFs.LowerDir,
                    scratchDir = lease.OverlayFs.ScratchDir
                } : null
            };

            string jsonPayload = JsonSerializer.Serialize(payload);

            // The lease's clock starts with the request it times.
            using var cts = executionContext is null ? CancellationTokenSource.CreateLinkedTokenSource(ct) : new CancellationTokenSource();
            cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, lease.LeaseDurationSeconds) + (executionContext is null ? 0 : 15)));
            await session.SendAsync(jsonPayload, cts.Token);
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            stop.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, lease.LeaseDurationSeconds)));
            Task stopped = Task.Delay(Timeout.Infinite, stop.Token);
            bool cancellationSent = false;

            // 2. Stream Inbound Output Chunks
            while (!cts.Token.IsCancellationRequested)
            {
                // Do not interrupt a partially read authenticated frame. Send cancellation on the
                // write half, then continue reading through the daemon's bounded drain receipt.
                Task<string?> pending = session.ReadLineAsync(cts.Token).AsTask();
                if (executionContext is not null && !cancellationSent && await Task.WhenAny(pending, stopped) == stopped)
                {
                    cancellationSent = true;
                    timedOut = !ct.IsCancellationRequested;
                    terminalReason = timedOut ? "LocalDeadlineExpired" : "CallerCancelled";
                    using var cancelBudget = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                    await session.SendAsync(JsonSerializer.Serialize(new { type = "CANCEL", missionId = lease.MissionId.ToString() }), cancelBudget.Token);
                    cts.CancelAfter(TimeSpan.FromSeconds(12));
                }
                string? line = await pending;
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

                        case "POLICY_APPLIED":
                            if (lease.ExecutionPolicy is null || outcome is null
                                || !root.TryGetProperty("sha256", out var policyHash)
                                || policyHash.ValueKind != JsonValueKind.String
                                || policyHash.GetString() is not { Length: 64 } hash
                                || hash.Any(c => !Uri.IsHexDigit(c))
                                || !root.TryGetProperty("landlockAbi", out var abi) || abi.GetInt32() < 5
                                || !root.TryGetProperty("syscallFilter", out var filter) || filter.GetString() != "seccomp-cbpf-v1")
                                throw new InvalidOperationException("The guest did not acknowledge a supported execution policy.");
                            outcome = outcome with { ExecutionPolicySha256 = hash };
                            break;

                        case "VIOLATION":
                            // In-Kernel BPF-LSM -EPERM Violation Streamed from RingBuffer
                            ulong cgid = root.TryGetProperty("cgroupId", out var cgProp) ? cgProp.GetUInt64() : 0;
                            uint pid = root.TryGetProperty("pid", out var pidProp) ? pidProp.GetUInt32() : 0;
                            int hookVal = root.TryGetProperty("hook", out var hookProp) ? hookProp.GetInt32() : 0;
                            ulong detail = root.TryGetProperty("detail", out var detailProp) ? detailProp.GetUInt64() : 0;
                            string detailText = root.TryGetProperty("detailText", out var dtProp) ? dtProp.GetString() ?? "" : "";
                            string comm = root.TryGetProperty("comm", out var commProp) ? commProp.GetString() ?? "" : "";
                            // The daemon's clock at the moment it drained the event, when it says so. The
                            // kernel record carries no time of its own, and this host's clock is a further
                            // remove from even that. A daemon older than the field sends none, and then
                            // this host's now is all there is.
                            DateTime stamped = root.TryGetProperty("timestampMs", out var tsProp) && tsProp.TryGetInt64(out long drainedMs)
                                ? DateTimeOffset.FromUnixTimeMilliseconds(drainedMs).UtcDateTime
                                : DateTime.UtcNow;

                            var vEvent = new LeaseViolationEvent(
                                CgroupId: cgid,
                                ProcessId: pid,
                                Hook: (KernelViolationHook)hookVal,
                                Detail: detail,
                                DetailText: detailText,
                                ProcessComm: comm,
                                TimestampUtc: stamped,
                                Sequence: root.TryGetProperty("seq", out var seqProp) ? seqProp.GetUInt64() : 0,
                                KernelTimeNs: root.TryGetProperty("ktimeNs", out var ktProp) ? ktProp.GetUInt64() : 0);

                            violations?.Report(vEvent);
                            stderr?.Report($"[KERNEL -EPERM BLOCK] [{comm} pid {pid}] {detailText}\n");
                            break;

                        case "LEASE":
                            // Read back from the guest, before the tool's first byte: what was installed,
                            // and whether it is policed. The limits are the controllers' own values only
                            // when the daemon says a real cgroup took them; on the non-enforcing path it
                            // reports the request, which is not a readback and is not recorded as one.
                            bool enforcing = root.TryGetProperty("enforcing", out var enfProp) && enfProp.ValueKind == JsonValueKind.True;
                            bool limitsRead = root.TryGetProperty("limitsReadBack", out var lrProp) && lrProp.ValueKind == JsonValueKind.True;
                            outcome = new LeaseOutcome(
                                CgroupId: root.TryGetProperty("cgroupId", out var lcg) && lcg.TryGetUInt64(out ulong lcgId) ? lcgId : 0,
                                CgroupPath: root.TryGetProperty("cgroupPath", out var cgp) ? cgp.GetString() : null,
                                Enforcing: enforcing,
                                Jailed: root.TryGetProperty("jailed", out var jp) && jp.ValueKind == JsonValueKind.True,
                                ReadOnlyFs: root.TryGetProperty("readOnlyFs", out var rop) && rop.ValueKind == JsonValueKind.True,
                                Workspace: root.TryGetProperty("workspace", out var wsp) ? wsp.GetString() : null,
                                WorkspaceCreated: root.TryGetProperty("workspaceCreated", out var wcp) && wcp.ValueKind == JsonValueKind.True,
                                WorkspaceRemoved: null,
                                WorkloadUid: root.TryGetProperty("workloadUid", out var wup) && wup.TryGetUInt32(out uint wuid) ? wuid : null);
                            if (limitsRead && root.TryGetProperty("limits", out var lim))
                            {
                                long? mem = lim.TryGetProperty("maxMemoryBytes", out var m) && m.TryGetInt64(out long memBytes) ? memBytes : null;
                                int? cpu = lim.TryGetProperty("maxCpuPercent", out var c) && c.TryGetInt32(out int cpuPct) ? cpuPct : null;
                                uint? pids = lim.TryGetProperty("maxPids", out var pp) && pp.TryGetUInt32(out uint pidCap) ? pidCap : null;
                                // The cgroup's clamps are what the kernel holds over every process in the
                                // lease, so both memory columns read the same figure; and the daemon kills
                                // the cgroup when the lease ends, which is what kill-on-close means here.
                                limitsReadBack = new JobLimitsReadback(mem, mem, cpu, pids, KillOnJobClose: true);
                            }
                            break;

                        case "EXIT":
                            if (root.TryGetProperty("exitCode", out var exitProp))
                            {
                                exitCode = exitProp.GetInt32();
                            }

                            if (root.TryGetProperty("workspaceRemoved", out var wrProp)
                                && wrProp.ValueKind is JsonValueKind.True or JsonValueKind.False)
                            {
                                bool removed = wrProp.ValueKind == JsonValueKind.True;
                                // A refusal after the workspace was made carries no LEASE frame - nothing
                                // was installed - but the daemon still says what became of the directory,
                                // and that is the one fact the caller's teardown record needs from it.
                                outcome = outcome is not null
                                    ? outcome with { WorkspaceRemoved = removed }
                                    : new LeaseOutcome(0, null, false, false, false, lease.WorkingDirectory,
                                        WorkspaceCreated: true, WorkspaceRemoved: removed, WorkloadUid: null, Installed: false);
                            }

                            // Refusals the kernel made but had no room to record while this lease ran.
                            // The VIOLATION events above are then an undercount, and a result that looked
                            // complete would be the kind of evidence this product exists not to produce.
                            ulong droppedCount = 0;
                            if (root.TryGetProperty("violationsDropped", out var droppedProp)
                                && droppedProp.TryGetUInt64(out droppedCount) && droppedCount > 0)
                            {
                                string note = $"[KERNEL_EVENTS_DROPPED] {droppedCount} kernel refusal record(s) were dropped by a full ring buffer while this lease ran; the refusals themselves still happened, and the violation list above is incomplete.";
                                stderrBuilder.Note(note);
                                stderr?.Report(note + "\n");
                            }

                            // The lease's denial count, from the kernel's own map, beside the number of
                            // VIOLATION frames that actually reached this process. A daemon that predates
                            // these fields sends neither and they stay null: unknown, never a confident zero.
                            ulong? violationsCounted =
                                root.TryGetProperty("violationsCounted", out var countedProp)
                                && countedProp.TryGetUInt64(out ulong countedValue) ? countedValue : null;
                            ulong? violationsReported =
                                root.TryGetProperty("violationsReported", out var reportedProp)
                                && reportedProp.TryGetUInt64(out ulong reportedValue) ? reportedValue : null;
                            bool? violationsComplete =
                                root.TryGetProperty("violationsComplete", out var completeProp)
                                && completeProp.ValueKind is JsonValueKind.True or JsonValueKind.False
                                    ? completeProp.ValueKind == JsonValueKind.True
                                    : null;

                            // The guest's signature over its own outcome (roadmap 2.5). Read as four
                            // opaque strings and stored as they arrived: this host is the party the
                            // signature exists to constrain, so it does not get to normalise,
                            // re-encode or rebuild any of them.
                            string? Text(string name) =>
                                root.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String
                                    ? prop.GetString()
                                    : null;

                            string? signedOutcome = Text("outcomeCanonical");
                            string? outcomeSignature = Text("outcomeSignature");
                            string? outcomeKeyId = Text("outcomeKeyId");
                            string? outcomePublicKey = Text("outcomePublicKey");

                            if (outcome is not null)
                            {
                                outcome = outcome with
                                {
                                    ViolationsCounted = violationsCounted,
                                    ViolationsReported = violationsReported,
                                    ViolationsComplete = violationsComplete,
                                    ViolationsDropped = droppedCount,
                                    SignedOutcome = signedOutcome,
                                    OutcomeSignature = outcomeSignature,
                                    OutcomeKeyId = outcomeKeyId,
                                    OutcomePublicKey = outcomePublicKey,
                                };
                            }

                            // Said on the error stream as well as carried in the outcome: a short receipt
                            // that only a record reader can discover is one the operator watching the
                            // mission run will not.
                            if (violationsComplete == false)
                            {
                                string note = $"[KERNEL_EVENTS_INCOMPLETE] the kernel counted {(violationsCounted?.ToString() ?? "an unknown number of")} refusal(s) for this lease and {(violationsReported?.ToString() ?? "an unknown number")} reached this host; the violation list above is not the whole of what was refused.";
                                stderrBuilder.Note(note);
                                stderr?.Report(note + "\n");
                            }

                            if (lease.ExecutionPolicy is not null && exitCode == 0 && outcome?.ExecutionPolicySha256 is null)
                            {
                                exitCode = -1;
                                throw new InvalidOperationException("The guest reported success without acknowledging the required execution policy.");
                            }
                            if (lease.RequireEnforcing && exitCode == 0
                                && outcome is not { Installed: true, Enforcing: true, Jailed: true })
                            {
                                exitCode = -1;
                                throw new InvalidOperationException("The guest did not confirm the enforcing jail required by this agent.");
                            }
                            if (executionContext is not null && outcome is { Installed: true })
                                outcome = BoundLeaseReceipt.Verify(lease, outcome, exitCode, root, executionContext);
                            stopwatch.Stop();
                            return new ProcessExecutionResult(
                                ExitCode: exitCode,
                                StandardOutput: stdoutBuilder.ToString(),
                                StandardError: stderrBuilder.ToString(),
                                TimedOut: timedOut,
                                // The guest daemon's EXIT frame carries no cgroup accounting, so
                                // nothing here was measured. This previously returned
                                // MaxMemoryBytes/4 as peak memory and half the wall clock as each
                                // CPU figure - arithmetic on constants, surfaced through
                                // MissionChunkType.Metric as observed values and sealed into the
                                // ledger as evidence. Report the absence instead; when the daemon
                                // starts reporting cgroup counters, populate these from the frame.
                                FinalMetrics: JobResourceMetrics.Unavailable,
                                TerminalReason: terminalReason ?? "ExplicitExit",
                                LimitsReadBack: limitsReadBack,
                                Lease: outcome);
                    }
                }
                catch (JsonException)
                {
                    if (executionContext is not null)
                        throw new InvalidOperationException("Bound execution returned an invalid authenticated frame.");
                    // Plaintext fallback chunk
                    stdoutBuilder.Append(line + "\n");
                    stdout?.Report(line + "\n");
                }
            }

            // The loop also ends, without throwing, when the deadline fires between two reads; that is
            // an expiry, not a dropped connection, so it goes through the same classification below.
            cts.Token.ThrowIfCancellationRequested();
            terminalReason = "AbruptDisconnect";
            stderrBuilder.Note("[DAEMON_DISCONNECTED] Connection closed unexpectedly before receiving an EXIT frame.");
        }
        catch (OperationCanceledException)
        {
            if (ct.IsCancellationRequested)
            {
                timedOut = false;
                terminalReason = "CallerCancelled";
                stderrBuilder.Note("[EXECUTION_CANCELLED] Execution was cancelled by the caller.");
            }
            else
            {
                timedOut = true;
                terminalReason = "LocalDeadlineExpired";
                stderrBuilder.Note("[EXECUTION_TIMEOUT] Local lease duration expired before daemon completion.");
            }
        }
        catch (Exception ex)
        {
            // An EXIT code is not success until the bound receipt has verified.
            exitCode = -1;
            terminalReason = "TransportError";
            stderrBuilder.Note($"[DAEMON_COMMUNICATION_ERROR] {ex.Message}");
        }

        stopwatch.Stop();
        int finalExitCode = timedOut ? -2 : (ct.IsCancellationRequested ? -3 : exitCode);
        return new ProcessExecutionResult(
            ExitCode: finalExitCode,
            StandardOutput: stdoutBuilder.ToString(),
            StandardError: stderrBuilder.ToString(),
            TimedOut: timedOut,
            // Timeout / transport-failure path: the run was cut short, so there is even less to
            // report than on the EXIT path. Nothing measured, nothing claimed - except what the
            // LEASE frame said before the cut, which is still what was installed.
            FinalMetrics: JobResourceMetrics.Unavailable,
            TerminalReason: terminalReason,
            LimitsReadBack: limitsReadBack,
            Lease: outcome);
    }

    /// <summary>
    /// The most of each stream a result carries. The daemon frames a tool's output in 64 KiB pieces so
    /// the guest never holds it whole; this host did, in a StringBuilder with no ceiling, so a tool that
    /// printed without end grew the MCP server by the size of its output. Streaming consumers still
    /// receive every byte through their <see cref="IProgress{T}"/>.
    /// </summary>
    public const int MaxCapturedCharsPerStream = 4 * 1024 * 1024;

    /// <summary>
    /// A bounded transcript of one stream. Past the cap the text is dropped and the drop is recorded
    /// once, in the stream it happened to, so a partial result reads as partial rather than complete.
    /// </summary>
    private sealed class CappedCapture
    {
        private readonly StringBuilder _text = new();
        private bool _truncated;

        public void Append(string text)
        {
            if (_truncated)
            {
                return;
            }

            int room = MaxCapturedCharsPerStream - _text.Length;
            if (text.Length <= room)
            {
                _text.Append(text);
                return;
            }

            _text.Append(text, 0, room);
            _text.Append($"\n[OUTPUT_TRUNCATED] More than {MaxCapturedCharsPerStream} characters were produced; the rest was not kept.\n");
            _truncated = true;
        }

        /// <summary>A diagnostic line from this bridge, kept whatever the cap: it says how the run ended.</summary>
        public void Note(string line) => _text.AppendLine(line);

        public override string ToString() => _text.ToString();
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
    public async Task<TcpClient> ConnectToDaemonAsync(CancellationToken ct)
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

    /// <summary>
    /// A wsl.exe session that does nothing until disposed: `cat` reading a pipe this process holds, so
    /// closing that pipe is its whole shutdown and nothing is left running in the guest.
    /// </summary>
    private sealed class IdleGuestSession : IDisposable
    {
        private readonly Process? _process;

        private IdleGuestSession(Process? process) => _process = process;

        internal bool IsAlive => _process is not null && !_process.HasExited;

        public static IDisposable Open()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "wsl.exe",
                // Root and an absolute path, like every child here; `-` is stdin, which is all it reads.
                Arguments = "-u root -e /bin/cat -",
                UseShellExecute = false,
                // All three, as for systemctl above: under splat-mcp this process's stdin and stdout
                // are the JSON-RPC channel.
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            try
            {
                return new IdleGuestSession(Process.Start(psi));
            }
            catch (Win32Exception)
            {
                // No wsl.exe at all: there is no guest to keep awake, and the connect will say why.
                return new IdleGuestSession(null);
            }
        }

        public void Dispose()
        {
            if (_process is null)
            {
                return;
            }

            try
            {
                // End of input: cat exits, and wsl.exe with it.
                _process.StandardInput.Close();
                if (!_process.WaitForExit(2000))
                {
                    _process.Kill(entireProcessTree: true);
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException)
            {
                // Already gone, taking its pipe with it.
            }
            finally
            {
                _process.Dispose();
            }
        }
    }
}
