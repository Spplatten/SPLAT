using System.Collections.Frozen;
using System.Collections.Immutable;

namespace Splat.AlertSidecar;

// Pass 2: bounded host-owned registrar. Reader publication is one acquire/release reference;
// readers take no monitor and allocate no per-lookup object. Writers and SQLite admission are
// serialized cold-path operations. This does NOT claim an entirely lock-free subsystem.
// Kernel enforcement never waits on this table, HTTP, JSON, SQLite or sensor availability.
internal sealed class TrustedAdmissionRegistrar
{
    private sealed record Candidate(RegisteredTask Task, RegisteredProcess Process);
    private sealed record Snapshot(ImmutableDictionary<Guid, RegisteredTask> Tasks,
        FrozenDictionary<SensorProcess, Candidate[]> Index, long Revision);
    private readonly object _writer = new();
    private readonly TimeProvider _clock;
    private readonly int _maxTasks, _maxProcesses;
    private long _wallHighWater;
    private Snapshot _snapshot = new(ImmutableDictionary<Guid, RegisteredTask>.Empty,
        new Dictionary<SensorProcess, Candidate[]>().ToFrozenDictionary(), 0);

    internal TrustedAdmissionRegistrar(TimeProvider? clock = null, int maxTasks = 1024, int maxProcesses = 16384)
    {
        if (maxTasks < 1 || maxProcesses < 1) throw new ArgumentOutOfRangeException(nameof(maxTasks));
        _clock = clock ?? TimeProvider.System; _maxTasks = maxTasks; _maxProcesses = maxProcesses;
        _wallHighWater = _clock.GetUtcNow().ToUnixTimeMilliseconds();
    }

    private bool ReadClock(out long now)
    {
        now = _clock.GetUtcNow().ToUnixTimeMilliseconds();
        long previous = Volatile.Read(ref _wallHighWater);
        while (now >= previous)
        {
            long actual = Interlocked.CompareExchange(ref _wallHighWater, now, previous);
            if (actual == previous) return true;
            previous = actual;
        }
        // Wall-clock rollback must not revive stale events. Monotonic lifetime is checked as well.
        // A concurrent later sample may conservatively reject an earlier request; never broaden it.
        return false;
    }
    private long Now() => ReadClock(out long now) ? now : throw new InvalidDataException("Clock rollback.");
    private bool Expired(RegisteredTask t, long now) => now >= t.ExpiresUnixMs
        || _clock.GetElapsedTime(t.StartedTimestamp) >= t.Lifetime;
    private RegisteredTask Writable(Guid task, long now)
    {
        if (!_snapshot.Tasks.TryGetValue(task, out var t) || t.State is AdmissionState.Draining or AdmissionState.Evicted
            || Expired(t, now)) throw new InvalidDataException("Admission is absent, closed or expired.");
        return t;
    }
    private void Publish(RegisteredTask task)
    {
        var tasks = _snapshot.Tasks.SetItem(task.Task, task);
        // Keep retired keys as tombstones. A stale sensor key must never become a different task.
        // Capacity exhaustion fails closed; Evict does not reclaim identity history for reuse.
        var index = tasks.Values.SelectMany(t => t.Processes.Values.Where(p => p.Sensor.HasValue)
            .Select(p => new Candidate(t, p))).GroupBy(c => c.Process.Sensor!.Value)
            .ToFrozenDictionary(g => g.Key, g => g.ToArray());
        Volatile.Write(ref _snapshot, new Snapshot(tasks, index, checked(_snapshot.Revision + 1)));
    }
    internal void Begin(Guid task, NativeProcess root, string tenant, string agent, string profileHash,
        string rule, long expiresUnixMs)
    {
        lock (_writer)
        {
            long now = Now();
            if (task == Guid.Empty || !root.Valid || !new SensorProcess(tenant, agent, "pending", profileHash).Valid
                || !Binding.ValidIdentifier(rule) || expiresUnixMs <= now || expiresUnixMs - now > 86_400_000
                || _snapshot.Tasks.ContainsKey(task) || _snapshot.Tasks.Count >= _maxTasks
                || _snapshot.Tasks.Values.Sum(t => t.Processes.Count) >= _maxProcesses
                || _snapshot.Tasks.Values.Any(t => t.Root.SameBoundary(root)))
                throw new InvalidDataException("Invalid, reused or over-capacity admission.");
            var process = new RegisteredProcess(root, null, now, true, null);
            Publish(new RegisteredTask(task, root, tenant, agent, profileHash, rule, AdmissionState.Admitting,
                now, expiresUnixMs, _clock.GetTimestamp(), TimeSpan.FromMilliseconds(expiresUnixMs - now), 0,
                ImmutableDictionary<NativeProcess, RegisteredProcess>.Empty.Add(root, process)));
        }
    }
    internal void BindSensor(Guid task, NativeProcess native, SensorProcess sensor)
    {
        lock (_writer)
        {
            var t = Writable(task, Now());
            if (!sensor.Valid || sensor.Tenant != t.Tenant || sensor.Agent != t.Agent || sensor.ProfileHash != t.ProfileHash
                || !t.Processes.TryGetValue(native, out var p) || !p.Live)
                throw new InvalidDataException("Sensor/native attestation does not match enrollment.");
            if (p.Sensor.HasValue)
            {
                if (p.Sensor.Value == sensor) return; // Exact retry only; rebinding a process is forbidden.
                throw new InvalidDataException("Process already bound to another sensor identity.");
            }
            // Preserve conflicting evidence and reject ALL resolutions of it, including the first
            // claimant. Silently rejecting only the second claimant would leave ambiguity usable.
            Publish(t with { Processes = t.Processes.SetItem(native, p with { Sensor = sensor }) });
            var conflicts = _snapshot.Index[sensor];
            if (conflicts.Length > 1)
            {
                foreach (var id in conflicts.Select(c => c.Task.Task).Distinct())
                {
                    var conflict = _snapshot.Tasks[id];
                    if (conflict.State != AdmissionState.Evicted)
                        Publish(conflict with { State = AdmissionState.Draining });
                }
                throw new InvalidDataException("Ambiguous sensor identity; affected admissions draining.");
            }
        }
    }
    internal void Activate(Guid task)
    {
        lock (_writer)
        {
            var t = Writable(task, Now());
            if (t.State != AdmissionState.Admitting || t.Processes.Values.Any(p => p.Live && p.Sensor is null))
                throw new InvalidDataException("Every held process needs a sensor binding before activation.");
            Publish(t with { State = AdmissionState.Active });
            // A future native launch coordinator may release its held child ONLY after this call
            // succeeds. This method does not release a process or claim that such a hold exists.
        }
    }
    internal void Fork(Guid task, NativeProcess parent, NativeProcess child, ulong sequence, long observedUnixMs)
    {
        lock (_writer)
        {
            long now = Now(); var t = Writable(task, now);
            if (sequence == 0 || t.LineageSequence == ulong.MaxValue || sequence != t.LineageSequence + 1
                || !child.Valid || !t.Root.SameBoundary(child) || t.Processes.ContainsKey(child)
                || !t.Processes.TryGetValue(parent, out var p) || !p.Live
                || child.StartTicks < parent.StartTicks || observedUnixMs < p.NotBeforeUnixMs || observedUnixMs > now
                || now - observedUnixMs > 30_000
                || t.Processes.Values.Any(x => x.Live && x.Native.Pid == child.Pid)
                || _snapshot.Tasks.Values.Sum(x => x.Processes.Count) >= _maxProcesses)
            {
                Publish(t with { State = AdmissionState.Draining });
                throw new InvalidDataException("Lineage incomplete, escaped or over capacity; drain required.");
            }
            // Kernel cgroup inheritance enforces the lease independently of telemetry. This table
            // records ONLY sequenced native fork evidence, never Falcon parent names or PPIDs.
            Publish(t with { LineageSequence = sequence,
                Processes = t.Processes.Add(child, new RegisteredProcess(child, null, observedUnixMs, true, parent)) });
        }
    }
    internal void Exit(Guid task, NativeProcess native, ulong sequence)
    {
        lock (_writer)
        {
            var t = Writable(task, Now());
            if (sequence == 0 || t.LineageSequence == ulong.MaxValue || sequence != t.LineageSequence + 1
                || !t.Processes.TryGetValue(native, out var p) || !p.Live)
            {
                Publish(t with { State = AdmissionState.Draining });
                throw new InvalidDataException("Unsequenced process exit; drain required.");
            }
            // Root exit does not mean workload drain: live children may remain. Keep their keys.
            Publish(t with { LineageSequence = sequence, Processes = t.Processes.SetItem(native, p with { Live = false }) });
        }
    }
    internal void Drain(Guid task)
    {
        lock (_writer)
        {
            if (!_snapshot.Tasks.TryGetValue(task, out var t)) throw new InvalidDataException("Unknown task.");
            if (t.State != AdmissionState.Evicted) Publish(t with { State = AdmissionState.Draining });
        }
    }
    internal void EvictExpired()
    {
        lock (_writer)
        {
            // Clock rollback closes all live registrations, rather than waiting for clock repair.
            bool clockOk = ReadClock(out long now);
            foreach (var t in _snapshot.Tasks.Values)
                if (t.State != AdmissionState.Evicted && (!clockOk || Expired(t, now)))
                    Publish(t with { State = AdmissionState.Evicted });
            // Evicted means no longer resolvable, NOT kernel termination. The lifecycle owner must
            // still revoke and verify drain. No receipt is manufactured by removing lookup access.
        }
    }
    internal AdmissionState State(Guid task) => Volatile.Read(ref _snapshot).Tasks[task].State;
    internal AdmissionResolution Resolve(SensorObservation observation)
    {
        if (!ReadClock(out long now)) return new(ResolutionStatus.ClockRollback, default, default, 0);
        return Resolve(Volatile.Read(ref _snapshot), observation, now);
    }
    private AdmissionResolution Resolve(Snapshot snapshot, SensorObservation o, long now)
    {
        AdmissionResolution Refuse(ResolutionStatus status) => new(status, default, default, snapshot.Revision);
        if (!snapshot.Index.TryGetValue(o.Sensor, out var candidates)) return Refuse(ResolutionStatus.Unknown);
        if (candidates.Length != 1) return Refuse(ResolutionStatus.Ambiguous);
        var c = candidates[0]; var t = c.Task; var p = c.Process;
        if (t.State != AdmissionState.Active || !p.Live || Expired(t, now)) return Refuse(ResolutionStatus.Inactive);
        if (o.Rule != t.Rule || !Binding.ValidIdentifier(o.AlertId) || o.Native is { } native && native != p.Native)
            return Refuse(ResolutionStatus.IdentityMismatch);
        if (o.ObservedUnixMs < p.NotBeforeUnixMs || o.ObservedUnixMs >= t.ExpiresUnixMs
            || o.ObservedUnixMs < now - 30_000 || o.ObservedUnixMs > now + 2_000)
            return Refuse(ResolutionStatus.Stale);
        return new(ResolutionStatus.Unique, t.Task, p.Native, snapshot.Revision);
    }
    internal bool MatchesBinding(Binding binding)
    {
        var snapshot = Volatile.Read(ref _snapshot);
        if (!Guid.TryParseExact(binding.TaskId, "N", out var task) || !snapshot.Tasks.TryGetValue(task, out var t)
            || binding.Falcon is not { } f) return false;
        var root = t.Root;
        return root.Node == binding.Node && root.Boot == binding.Boot && root.Cgroup == binding.Cgroup
            && root.Pid == binding.Pid && root.StartTicks == binding.StartTicks && t.Rule == binding.Rule
            && t.Tenant == f.TenantId && t.Agent == f.AgentId && t.ProfileHash == f.ProfileSha256.ToUpperInvariant()
            && t.ExpiresUnixMs == binding.ExpiresUnixMs
            && t.Processes[root].Sensor?.ProcessInstance == f.ProcessInstanceId;
    }
    internal bool AdmitToMailbox(Guid expectedTask, SensorObservation observation, Latch mailbox)
    {
        lock (_writer)
        {
            if (!ReadClock(out long now)) return false;
            var resolved = Resolve(_snapshot, observation, now);
            if (resolved.Status != ResolutionStatus.Unique || resolved.Task != expectedTask) return false;
            // Resolution and the durable insert share the writer boundary with Drain/Exit/Evict.
            // A reader's stale snapshot is never a bearer capability. After lock release the
            // queued cancellation names a non-reusable task UUID, never a kill(pid) operation.
            mailbox.Admit(observation.AlertId, observation.ObservedUnixMs, now);
            return true;
        }
    }
}
