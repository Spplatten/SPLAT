using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace SplatMcp;

/// <summary>
/// The lease executor of a Windows-only managed install, which created no WSL guest. The tools that author
/// leases refuse before reaching it (McpServerHandler.LinuxLeaseAbsent), so their records say nothing ran.
/// This is the backstop for any path that still asks for a lease: it refuses with the reason, rather than
/// handing the lease to whatever distro the service account can reach, which this deployment neither made
/// nor can vouch for.
/// </summary>
internal sealed class AbsentLinuxLease : ILeasedExecutor
{
    internal const string Reason =
        "This managed instance was installed Windows-only: it has no WSL guest, so no Linux lease can run. Nothing was executed.";

    public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
        IProgress<string>? stdout = null, IProgress<string>? stderr = null,
        IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default) =>
        Task.FromResult(new ProcessExecutionResult(-1, "", "[LINUX_LEASE_ABSENT] " + Reason, false,
            JobResourceMetrics.Unavailable, TerminalReason: "LinuxLeaseAbsent"));
}
