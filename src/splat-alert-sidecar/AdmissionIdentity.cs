using System.Collections.Immutable;

namespace Splat.AlertSidecar;

// Linux identities use the host PID namespace and /proc field 22 ticks, not epoch seconds.
// CgroupGeneration is a host-issued lifetime nonce while the cgroup handle is held. It is NOT
// lease_state.epoch (currently constant 1), a path, or an inode inferred from a sensor event.
internal readonly record struct NativeProcess(string Node, Guid Boot, ulong Cgroup,
    Guid CgroupGeneration, int Pid, ulong StartTicks)
{
    internal bool Valid => Binding.ValidIdentifier(Node) && Boot != Guid.Empty && Cgroup != 0
        && CgroupGeneration != Guid.Empty && Pid > 0 && StartTicks != 0;
    internal bool SameBoundary(NativeProcess other) => Node == other.Node && Boot == other.Boot
        && Cgroup == other.Cgroup && CgroupGeneration == other.CgroupGeneration;
}

// Opaque sensor identity: never parse ProcessInstance as a Windows or Linux PID. Exact profile
// hash matching prevents changing TargetProcessId/ContextProcessId semantics after admission.
internal readonly record struct SensorProcess(string Tenant, string Agent, string ProcessInstance,
    string ProfileHash)
{
    internal bool Valid => Binding.ValidIdentifier(Tenant) && Binding.ValidIdentifier(Agent)
        && Binding.ValidIdentifier(ProcessInstance) && ProfileHash is { Length: 64 }
        && ProfileHash.All(Uri.IsHexDigit) && ProfileHash == ProfileHash.ToUpperInvariant();
}

internal readonly record struct SensorObservation(SensorProcess Sensor, string Rule, string AlertId,
    long ObservedUnixMs, NativeProcess? Native = null);
internal enum AdmissionState { Admitting, Active, Draining, Evicted }
internal enum ResolutionStatus { Unique, Unknown, Ambiguous, Inactive, Stale, IdentityMismatch, ClockRollback }
internal readonly record struct AdmissionResolution(ResolutionStatus Status, Guid Task,
    NativeProcess Native, long Revision);

// Pass 1: a single-owner, exact composite-key table. This is an executable reference core for
// tests/education, not the HTTP path: it has no concurrency, lifecycle, expiry or lineage policy.
internal sealed class MinimalAdmissionRegistrar
{
    private readonly Dictionary<(NativeProcess, SensorProcess), HashSet<Guid>> _entries = new();
    internal void Register(Guid task, NativeProcess native, SensorProcess sensor)
    {
        if (task == Guid.Empty || !native.Valid || !sensor.Valid) throw new InvalidDataException("Incomplete identity.");
        if (!_entries.TryGetValue((native, sensor), out var tasks)) _entries[(native, sensor)] = tasks = new();
        tasks.Add(task);
    }
    internal Guid? Resolve(NativeProcess native, SensorProcess sensor) =>
        _entries.TryGetValue((native, sensor), out var tasks) && tasks.Count == 1 ? tasks.First() : null;
}

// These objects never cross the alert HTTP boundary. Only a trusted host/collector may call the
// writer API with native observations captured while holding kernel handles. A C# record is not
// an attestation; transporting it to another process requires authenticated, replay-fenced IPC.
internal sealed record RegisteredProcess(NativeProcess Native, SensorProcess? Sensor,
    long NotBeforeUnixMs, bool Live, NativeProcess? Parent);
internal sealed record RegisteredTask(Guid Task, NativeProcess Root, string Tenant, string Agent,
    string ProfileHash, string Rule, AdmissionState State, long CreatedUnixMs, long ExpiresUnixMs,
    long StartedTimestamp, TimeSpan Lifetime, ulong LineageSequence,
    ImmutableDictionary<NativeProcess, RegisteredProcess> Processes,
    // The PIDs of Processes' live entries, so a fork's PID-collision check is a lookup, not a scan.
    ImmutableHashSet<int> LivePids);
