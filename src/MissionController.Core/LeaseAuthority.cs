using MissionController.Core.Interfaces;

namespace MissionController.Core.Models;

// Portable authority excludes workspace paths: each child receives a new private workspace.
public sealed record LeaseAuthority(IReadOnlyList<string> Executables, bool AllowNetwork,
    IReadOnlyDictionary<string, IReadOnlyList<string>> Hosts, IReadOnlyList<uint> Ports,
    IReadOnlyList<string> ProtectedPaths, bool ReadOnlyFs, LeaseResourceLimits Limits,
    uint DurationSeconds, ExecutionPolicy? ExecutionPolicy)
{
    public static LeaseAuthority From(LeaseSpec lease) => new(
        lease.AllowedExecInodes.Select(p => p.SourcePath).ToArray(), lease.AllowNetwork,
        lease.ResolvedEgressHosts ?? new Dictionary<string, IReadOnlyList<string>>(),
        lease.AllowedEgressPorts, lease.ProtectedInodes.Select(p => p.SourcePath).ToArray(),
        lease.ReadOnlyFs, lease.Limits, lease.LeaseDurationSeconds, lease.ExecutionPolicy);

    public LeaseSpec Narrow(LeaseSpec child, string command, DateTimeOffset expires)
    {
        if (Executables is null || Hosts is null || Ports is null || ProtectedPaths is null || Limits is null)
            throw new InvalidOperationException("Incomplete delegation authority.");
        var executables = child.AllowedExecInodes.Where(p => Executables.Contains(p.SourcePath, StringComparer.Ordinal)).ToArray();
        if (!executables.Any(p => p.SourcePath == command))
            throw new InvalidOperationException("Delegation does not authorize this executable.");
        var hosts = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        foreach (var host in child.ResolvedEgressHosts ?? new Dictionary<string, IReadOnlyList<string>>())
            if (Hosts.TryGetValue(host.Key, out var pins))
                hosts.Add(host.Key, host.Value.Intersect(pins, StringComparer.Ordinal).ToArray());
        var ports = child.AllowedEgressPorts.Intersect(Ports).ToArray();
        if (child.AllowNetwork && (!AllowNetwork || ports.Length == 0 || hosts.Count != child.ResolvedEgressHosts?.Count
            || hosts.Values.Any(p => p.Count == 0)))
            throw new InvalidOperationException("Delegation does not authorize every required destination.");
        uint seconds = (uint)Math.Max(0, Math.Floor((expires - DateTimeOffset.UtcNow).TotalSeconds));
        seconds = Math.Min(seconds, Math.Min(DurationSeconds, child.LeaseDurationSeconds));
        // The daemon clamps its minimum to five seconds. Never let that clamp extend a grant.
        if (seconds < 5) throw new InvalidOperationException("Delegation expires before a minimum lease can finish.");
        return child with
        {
            AllowedExecInodes = executables,
            AllowNetwork = child.AllowNetwork && AllowNetwork,
            AllowedEgressIps = hosts.Values.SelectMany(p => p).Distinct(StringComparer.Ordinal).ToArray(),
            AllowedEgressPorts = ports, ResolvedEgressHosts = hosts,
            ProtectedInodes = child.ProtectedInodes.Concat(ProtectedPaths.Select(p => new InodeIdentifierModel(0, 0, p)))
                .DistinctBy(p => p.SourcePath, StringComparer.Ordinal).ToArray(),
            ReadOnlyFs = child.ReadOnlyFs || ReadOnlyFs,
            Limits = new(Math.Min(child.Limits.MaxMemoryBytes, Limits.MaxMemoryBytes),
                Math.Min(child.Limits.MaxCpuPercent, Limits.MaxCpuPercent), Math.Min(child.Limits.MaxPids, Limits.MaxPids)),
            LeaseDurationSeconds = seconds, ExecutionPolicy = Intersect(ExecutionPolicy, child.ExecutionPolicy),
            // A template lease never delegates a mutable executable overlay.
            OverlayFs = child.OverlayFs is null ? null : child.OverlayFs with { AllowScratchExec = false }
        };
    }

    public static ExecutionPolicy? Intersect(ExecutionPolicy? parent, ExecutionPolicy? child)
    {
        parent?.Validate(); child?.Validate();
        if (parent is null) return child;
        if (child is null) return parent;
        var grants = new List<FileAccessGrant>();
        foreach (var a in parent.FileGrants)
        foreach (var b in child.FileGrants)
        {
            var narrow = a.Path == b.Path ? (a.Scope == "file" ? a : b)
                : Beneath(a, b) ? b : Beneath(b, a) ? a : null;
            var access = a.Access.Intersect(b.Access, StringComparer.Ordinal).ToArray();
            if (narrow is not null && access.Length > 0) grants.Add(narrow with { Access = access });
        }
        var policy = parent with
        {
            Syscalls = parent.Syscalls.Intersect(child.Syscalls, StringComparer.Ordinal).ToArray(),
            FileGrants = grants.GroupBy(g => g.Path, StringComparer.Ordinal).Select(g =>
                new FileAccessGrant(g.Key, g.SelectMany(f => f.Access).Distinct(StringComparer.Ordinal).ToArray(),
                    g.All(f => f.Scope == "tree") ? "tree" : "file")).ToArray()
        };
        policy.Validate();
        return policy;
    }

    private static bool Beneath(FileAccessGrant tree, FileAccessGrant grant) => tree.Scope == "tree"
        && grant.Path.StartsWith(tree.Path + "/", StringComparison.Ordinal);
}

public sealed record LeaseExecutionContext(string AgentId, string ContractSha256, string TenantId,
    string CallerId, string TaskId, string? ParentTaskId = null, string? DelegationSha256 = null,
    string? RequestingAgentId = null, string? RequestingContractSha256 = null);
