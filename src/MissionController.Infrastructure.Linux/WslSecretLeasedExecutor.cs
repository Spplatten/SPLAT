using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Linux;

/// <summary>
/// Extends <see cref="WslLeasedExecutor"/> with secret-step support. The EXECUTE_TOOL frame
/// carries a <c>secretGrant</c> field; the daemon delivers the vault credential on the child's
/// sealed memfd stdin and discards stdout/stderr. All other enforcement (cgroup, BPF, jail,
/// UID isolation, seccomp) is unchanged.
/// </summary>
public sealed class WslSecretLeasedExecutor : ISecretLeasedExecutor
{
    private readonly WslLeasedExecutor _inner;

    public WslSecretLeasedExecutor(WslLeasedExecutor inner)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
    }

    public Task<ProcessExecutionResult> ExecuteLeasedAsync(
        LeaseSpec lease, string command, IReadOnlyList<string> argv,
        IProgress<string>? stdout = null, IProgress<string>? stderr = null,
        IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
        => _inner.ExecuteLeasedAsync(lease, command, argv, stdout, stderr, violations, ct);

    public async Task<ProcessExecutionResult> ExecuteSecretLeasedAsync(
        LeaseSpec lease, string command, IReadOnlyList<string> argv, string secretGrant,
        IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        ArgumentException.ThrowIfNullOrWhiteSpace(command);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretGrant);

        if (secretGrant.Length != 64)
            throw new ArgumentException("Secret grant must be exactly 64 hex characters.", nameof(secretGrant));

        var stopwatch = Stopwatch.StartNew();
        int exitCode = -1;
        bool timedOut = false;
        string? terminalReason = null;
        LeaseOutcome? leaseOutcome = null;
        var violationList = new List<LeaseViolationEvent>();

        // ConnectToDaemonAsync handles guest wake, retry on service start, and auth token read.
        using var client = await _inner.ConnectToDaemonAsync(ct);
        using var stream = client.GetStream();

        string? authToken;
        using (var tokenCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            tokenCts.CancelAfter(WslAgentToken.ReadBudget);
            authToken = await WslAgentToken.Default.GetAsync(tokenCts.Token);
        }

        if (string.IsNullOrEmpty(authToken))
            throw new InvalidOperationException("Could not read the daemon auth token for secret step.");

        WslAgentSession session;
        using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                session = await WslAgentSession.OpenAsync(stream, authToken, handshakeCts.Token);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException("Waited 10 seconds for the daemon handshake on secret step.");
            }
        }
        using var _ = session;

        // The EXECUTE_TOOL frame for a secret step: includes secretGrant, forces ephemeralWorkspace.
        var payload = new
        {
            type = "EXECUTE_TOOL",
            protocolVersion = WslAgentSession.ProtocolVersion,
            missionId = lease.MissionId.ToString(),
            command,
            argv,
            workingDirectory = lease.WorkingDirectory,
            allowNetwork = lease.AllowNetwork,
            allowedEgressIps = lease.AllowedEgressIps,
            allowedEgressPorts = lease.AllowedEgressPorts,
            readOnlyFs = lease.ReadOnlyFs,
            protectedPaths = lease.ProtectedInodes.Select(i => i.SourcePath).ToArray(),
            allowedExecPaths = lease.AllowedExecInodes.Select(i => i.SourcePath).ToArray(),
            leaseDurationSeconds = lease.LeaseDurationSeconds,
            ephemeralWorkspace = true,
            secretGrant,
            limits = new
            {
                maxMemoryBytes = lease.Limits.MaxMemoryBytes,
                maxCpuPercent = lease.Limits.MaxCpuPercent,
                maxPids = lease.Limits.MaxPids
            }
        };

        string jsonPayload = JsonSerializer.Serialize(payload);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Max(5, lease.LeaseDurationSeconds)));
        await session.SendAsync(jsonPayload, cts.Token);

        // Secret steps discard stdout/stderr but produce LEASE, VIOLATION and EXIT frames.
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
                    case "LEASE":
                        leaseOutcome = ParseLeaseOutcome(root);
                        break;

                    case "EXIT":
                        exitCode = root.TryGetProperty("exitCode", out var ecProp) ? ecProp.GetInt32() : -1;
                        timedOut = root.TryGetProperty("timedOut", out var toProp) && toProp.GetBoolean();
                        if (root.TryGetProperty("terminalReason", out var trProp))
                            terminalReason = trProp.GetString();
                        if (leaseOutcome != null)
                        {
                            string? signedOutcome = root.TryGetProperty("secretOutcomeCanonical", out var socProp) ? socProp.GetString() : null;
                            string? sig = root.TryGetProperty("secretOutcomeSignature", out var sigProp) ? sigProp.GetString() : null;
                            if (signedOutcome != null)
                                leaseOutcome = leaseOutcome with { SignedOutcome = signedOutcome, OutcomeSignature = sig };
                        }
                        break;

                    case "VIOLATION":
                    {
                        var violation = new LeaseViolationEvent(
                            CgroupId: root.TryGetProperty("cgroupId", out var vCidProp) ? vCidProp.GetUInt64() : 0,
                            ProcessId: root.TryGetProperty("pid", out var vPidProp) ? vPidProp.GetUInt32() : 0,
                            Hook: root.TryGetProperty("hook", out var hookProp) && Enum.TryParse<KernelViolationHook>(hookProp.GetString(), true, out var hook) ? hook : default,
                            Detail: root.TryGetProperty("detail", out var vdProp) ? vdProp.GetUInt64() : 0,
                            DetailText: root.TryGetProperty("detailText", out var dtProp) ? dtProp.GetString() ?? "" : "",
                            ProcessComm: root.TryGetProperty("comm", out var commProp) ? commProp.GetString() ?? "" : "",
                            TimestampUtc: DateTime.UtcNow,
                            Sequence: 0,
                            KernelTimeNs: 0);
                        violationList.Add(violation);
                        violations?.Report(violation);
                        break;
                    }
                }
            }
            catch (JsonException) { }
        }

        stopwatch.Stop();

        return new ProcessExecutionResult(
            exitCode,
            StandardOutput: "",
            StandardError: "",
            timedOut,
            JobResourceMetrics.Unavailable,
            terminalReason,
            Lease: leaseOutcome);
    }

    private static LeaseOutcome ParseLeaseOutcome(JsonElement root)
    {
        return new LeaseOutcome(
            CgroupId: root.TryGetProperty("cgroupId", out var cidProp) ? cidProp.GetUInt64() : 0,
            CgroupPath: root.TryGetProperty("cgroupPath", out var cpProp) ? cpProp.GetString() : null,
            Enforcing: root.TryGetProperty("enforcing", out var eProp) && eProp.GetBoolean(),
            Jailed: root.TryGetProperty("jailed", out var jProp) && jProp.GetBoolean(),
            ReadOnlyFs: root.TryGetProperty("readOnlyFs", out var roProp) && roProp.GetBoolean(),
            Workspace: root.TryGetProperty("workspace", out var wsProp) ? wsProp.GetString() : null,
            WorkspaceCreated: root.TryGetProperty("workspaceCreated", out var wcProp) && wcProp.GetBoolean(),
            WorkspaceRemoved: root.TryGetProperty("workspaceRemoved", out var wrProp) ? wrProp.GetBoolean() : null,
            WorkloadUid: root.TryGetProperty("workloadUid", out var wuProp) ? wuProp.GetUInt32() : null);
    }
}
