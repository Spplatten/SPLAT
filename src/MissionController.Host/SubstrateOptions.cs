namespace MissionController.Host;

/// <summary>
/// What a doctor run reports against. Each host fills it from its own configuration - splat-mcp from
/// its command line, the console from the environment it was started with - so the report is one
/// program, read by two doors.
/// </summary>
/// <param name="Egress">
/// The network a caller's lease may name, for a host that lets callers author leases (splat-mcp's
/// <c>--egress</c>). Null for a host whose leases are compiled from templates alone, where each lease's
/// destination is its template's and the report says so instead.
/// </param>
public sealed record DoctorOptions(
    string? WorkspaceRoot,
    McpEgressPolicy? Egress,
    string? LedgerKeyPath = null,
    string? RunRecordKeyPath = null)
{
    /// <summary>What this host runs under the lease, as its operator knows it.</summary>
    public string LeasedWork { get; init; } = "run_command and run_code";

    /// <summary>How this host's operator replaces a daemon that predates proven frames.</summary>
    public string DaemonRemedy { get; init; } = "`splat-mcp provision --apply` installs the one this executable carries";

    /// <summary>How this host's operator gives the guest a lease ceiling it lacks.</summary>
    public string CeilingRemedy { get; init; } =
        "`splat-mcp provision --apply` writes one; add --egress <list> to bound the network from there too";
}

/// <summary>
/// Provision the guest. <see cref="Apply"/> is false by default: the steps write to /etc inside the
/// guest and to the user's .wslconfig, so a dry run is what an unqualified request gets.
/// <see cref="Egress"/> is what the lease ceiling written into the guest allows a lease to reach;
/// <see cref="McpEgressPolicy.None"/> leaves the ceiling's egress unbounded.
/// </summary>
public sealed record ProvisionOptions(bool Apply, McpEgressPolicy? Egress = null)
{
    public McpEgressPolicy CeilingEgress => Egress ?? McpEgressPolicy.None;
}

/// <summary>
/// Undo a mount. <see cref="Apply"/> is false by default, for the same reason provisioning's is.
/// <see cref="ManifestPath"/> is null for the manifest the mount wrote under the data root.
/// </summary>
public sealed record UnmountOptions(bool Apply, string? ManifestPath = null);
