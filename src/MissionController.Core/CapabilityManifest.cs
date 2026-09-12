using System.Collections.Generic;
using System.Linq;
using MissionController.Core.Models;

namespace MissionController.Core;

/// <summary>Where a lease's boundary is actually drawn, in the substrate's own terms.</summary>
public enum LeaseEnforcement
{
    /// <summary>A BPF-LSM hook vetoes it in the kernel.</summary>
    Kernel,

    /// <summary>The daemon checks it in user space before or around the workload.</summary>
    Daemon,

    /// <summary>The daemon turns the request away rather than accepting a field it cannot honour.</summary>
    Refused,

    /// <summary>Reachable by a leased process, and not claimed otherwise.</summary>
    NotPoliced,
}

/// <summary>What an MCP tool's containment actually rests on.</summary>
public enum ToolEnforcement
{
    /// <summary>The Linux lease: a kernel hook decides, and the daemon must be enforcing.</summary>
    LinuxKernelLease,

    /// <summary>The Windows sensor sandbox: job object, restricted token, ACL jail, AppContainer.</summary>
    WindowsSensorSandbox,

    /// <summary>A check inside SPLAT's own process. Real, and not an operating-system boundary.</summary>
    ControlPlaneOnly,
}

public sealed record LeaseCapability(string What, LeaseEnforcement Where);

public sealed record ToolCapability(string Tool, ToolEnforcement Enforcement, string Detail);

/// <summary>How many catalog templates run inside the Windows network-denied AppContainer, and why not.</summary>
public sealed record WindowsSensorCensus(int Templates, int NetworkDenied, int NeedsNetwork, int LocalSubsystems)
{
    /// <summary>Templates whose tool keeps a network stack, for either reason.</summary>
    public int Unconfined => NeedsNetwork + LocalSubsystems;
}

/// <summary>
/// One statement of what SPLAT enforces, read by everything that claims it: <c>splat-mcp doctor</c>,
/// the description of every MCP tool, and the tests.
///
/// F24 is the finding that these were three separate copies — the CLI said one thing, the tool
/// descriptions another, and <c>native/splat-agent/SUPPORTED_POLICY.md</c> a third — so a boundary
/// could move and leave two of them behind. The tests bind this file to the substrate's document and
/// to the server's own tool list, which is what makes it one contract rather than a fourth copy.
///
/// Nothing here is counted by hand: <see cref="CensusOf"/> evaluates the shipped catalog against the
/// same predicate the mission engine launches with, because the number of templates that keep a
/// network stack is exactly the sort of fact that rots quietly in prose.
/// </summary>
public static class CapabilityManifest
{
    /// <summary>
    /// What a Linux lease enforces, refuses and leaves alone. Every phrase appears verbatim in
    /// <c>SUPPORTED_POLICY.md</c>, and a test fails if one stops appearing there.
    /// </summary>
    public static IReadOnlyList<LeaseCapability> Lease { get; } = new LeaseCapability[]
    {
        new("Executable identity", LeaseEnforcement.Kernel),
        new("Protected files", LeaseEnforcement.Kernel),
        new("IPv4 egress", LeaseEnforcement.Kernel),
        new("IPv6 egress", LeaseEnforcement.Kernel),
        new("Memory, CPU, PID ceilings", LeaseEnforcement.Daemon),
        new("Lease lifetime", LeaseEnforcement.Daemon),
        new("Caller identity", LeaseEnforcement.Daemon),
        new("Workload privilege", LeaseEnforcement.Daemon),
        new("Command coherence", LeaseEnforcement.Daemon),
        new("readOnlyFs", LeaseEnforcement.Refused),
        new("overlayFs.enableCow", LeaseEnforcement.Refused),
        new("UDP to an unconnected socket", LeaseEnforcement.NotPoliced),
        new("AF_UNIX / AF_NETLINK", LeaseEnforcement.NotPoliced),
        new("Inherited file descriptors", LeaseEnforcement.NotPoliced),
        new("Filesystem writes outside the workspace", LeaseEnforcement.NotPoliced),
        new("Ambient reads", LeaseEnforcement.NotPoliced),
    };

    /// <summary>
    /// What each MCP tool's containment rests on. A test fails if the server exposes a tool this list
    /// does not name, or names one the server does not expose — so a new tool cannot ship without
    /// someone deciding, in writing, what holds it.
    /// </summary>
    public static IReadOnlyList<ToolCapability> Tools { get; } = new ToolCapability[]
    {
        new("run_command", ToolEnforcement.LinuxKernelLease,
            "the Linux lease: exec, file and IPv4 rules vetoed by a BPF-LSM hook, and it fails rather than falling back when the daemon is not enforcing"),
        new("run_code", ToolEnforcement.LinuxKernelLease,
            "the Linux lease, the same as run_command, after a pre-flight rejection of forbidden script primitives"),
        new("fs_read", ToolEnforcement.ControlPlaneOnly,
            "a handle-based workspace check inside this process - a user-space boundary, not a kernel one"),
        new("fs_write", ToolEnforcement.ControlPlaneOnly,
            "a handle-based workspace check inside this process - a user-space boundary, not a kernel one"),
        new("diagnose_system", ToolEnforcement.WindowsSensorSandbox,
            "the Windows sensor sandbox: job object clamps, a restricted token, an ACL jail, and network denial for every template that can take it"),
        new("investigate_system", ToolEnforcement.WindowsSensorSandbox,
            "the Windows sensor sandbox, once per step of the loop"),
        new("run_agent_brain", ToolEnforcement.WindowsSensorSandbox,
            "the Windows sensor sandbox, once per mission the plan spawns"),
        new("run_governed_crew", ToolEnforcement.WindowsSensorSandbox,
            "the Windows sensor sandbox, once per crew member, with each hand-off scrubbed"),
        new("get_substrate_health", ToolEnforcement.ControlPlaneOnly, "read-only: it reports, and changes nothing"),
        new("list_diagnostic_templates", ToolEnforcement.ControlPlaneOnly, "read-only: it reports, and changes nothing"),
        new("list_governed_crews", ToolEnforcement.ControlPlaneOnly, "read-only: it reports, and changes nothing"),
        new("search_incident_memory", ToolEnforcement.ControlPlaneOnly,
            "read-only over the local index; recalled text is labelled as context, never as instructions"),
    };

    /// <summary>
    /// The same question the mission engine asks before it launches a sensor: may this tool be put in
    /// an AppContainer with no capabilities? Counted, never authored, so the docs cannot drift from
    /// the catalog they describe.
    /// </summary>
    public static WindowsSensorCensus CensusOf(IEnumerable<SingleToolTemplate> templates)
    {
        var all = templates.ToList();
        int needsNetwork = all.Count(t => t.EgressRule.ToolProcessNeedsNetwork);
        int localSubsystems = all.Count(t => !t.EgressRule.ToolProcessNeedsNetwork && t.ToolNeedsLocalSubsystems);
        return new WindowsSensorCensus(
            Templates: all.Count,
            NetworkDenied: all.Count(t => !t.EgressRule.ToolProcessNeedsNetwork && !t.ToolNeedsLocalSubsystems),
            NeedsNetwork: needsNetwork,
            LocalSubsystems: localSubsystems);
    }
}
