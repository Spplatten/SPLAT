using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Linux;

namespace MissionController.Host;

/// <summary>A desktop mission crosses the service boundary without obtaining the guest's token.</summary>
public sealed record ManagedLeaseRequest(LeaseSpec Lease, string Command, IReadOnlyList<string> Arguments)
{
    public const string ExecuteMethod = "splat/execute_lease";
    public const string CheckMethod = "splat/check_substrate";

    public void Validate(McpEgressPolicy egress)
    {
        // A desktop may request one disposable mission, never a service-account workspace or a
        // broader exec policy. The service's egress decision still precedes the guest's ceiling.
        if (Lease is null || Arguments is null || string.IsNullOrWhiteSpace(Command)
            || !Command.StartsWith('/') || Lease.MissionId == Guid.Empty
            || !Lease.EphemeralWorkspace || Lease.OverlayFs is { EnableCow: true } or { AllowScratchExec: true }
            || Lease.WorkingDirectory != $"{LinuxLeaseSubstrate.DefaultMissionsRoot}/{Lease.MissionId:N}"
            || Lease.AllowedExecInodes is not { Count: 1 }
            || Lease.AllowedExecInodes[0]?.SourcePath != Command
            || Lease.ProtectedInodes is null || Lease.AllowedEgressIps is null || Lease.AllowedEgressPorts is null
            || Lease.LeaseDurationSeconds is < 5 or > 300 || Lease.Limits is null
            || Lease.Limits.MaxMemoryBytes == 0 || Lease.Limits.MaxCpuPercent is < 1 or > 100
            || Lease.Limits.MaxPids is < 1 or > 512 || Arguments.Any(arg => arg is null || arg.Contains('\0')))
            throw new InvalidDataException("The managed request must describe one bounded, disposable Linux mission.");

        if (!Lease.AllowNetwork)
        {
            if (Lease.AllowedEgressIps.Count != 0 || Lease.AllowedEgressPorts.Count != 0)
                throw new InvalidDataException("A network-denied lease cannot carry endpoints.");
            return;
        }

        EgressDecision decision = egress.Authorize(Lease.AllowedEgressIps);
        if (Lease.AllowedEgressIps.Count == 0 || Lease.AllowedEgressPorts.Count == 0
            || decision.Refusal is not null || Lease.AllowedEgressPorts.Any(port => !decision.Ports.Contains(port)))
            throw new InvalidDataException("The managed lease exceeds the service's operator egress policy.");
    }
}

// Violations holds at most BoundedViolationLog.DefaultCapacity refusals; ViolationsOmitted counts the
// rest. Unbounded, a lease that kept provoking refusals could push this response past the client's
// 64 MiB frame limit and lose the whole result - exit code, receipt and all.
public sealed record ManagedLeaseResult(ProcessExecutionResult Process, IReadOnlyList<LeaseViolationEvent> Violations,
    long ViolationsOmitted = 0);
