using System.Collections.Immutable;

namespace Splat.AlertSidecar;

// Pass 2: bounded host-owned registrar. Reader publication is one acquire/release reference;
// readers take no monitor and allocate no per-lookup object. Writers and SQLite admission are
// serialized cold-path operations. This does NOT claim an entirely lock-free subsystem.
// Kernel enforcement never waits on this table, HTTP, JSON, SQLite or sensor availability.
internal sealed class TrustedAdmissionRegistrar
{
    // A claim names a bound process by identity, never by a copy of its record: Resolve reads the
    // current record from the same snapshot's Tasks. So only binding a sensor changes the index, as
    // one persistent O(log n) update. Rebuilding every claim on every fork, exit and state change was
    // quadratic in a fork-heavy task, and ran under the writer lock the mailbox commit also takes.
    private readonly record struct Claim(Guid Task, NativeProcess Native);
    private sealed record Snapshot(ImmutableDictionary<Guid, RegisteredTask> Tasks,
        ImmutableDictionary<SensorProcess, ImmutableArray<Claim>> Index, int ProcessCount, long Revision);
    private readonly object _writer = new();
    private readonly TimeProvider _clock;
    private readonly int _maxTasks, _maxProcesses;
    private long _wallHighWater;
    private Snapshot _snapshot = new(ImmutableDictionary<Guid, RegisteredTask>.Empty,
        ImmutableDictionary<SensorProcess, ImmutableArray<Claim>>.Empty, 0, 0);

    internal TrustedAdmissionRegistrar(TimeProvider? clock = null, int maxTasks = 1024, int maxProcesses = 16384)
    {
        if (maxTasks < 1 || maxProcesses < 1) throw new ArgumentOutOfRangeException(nameof(maxTasks));
        _clock = clock ?? TimeProvider.System; _maxTasks = maxTasks; _maxProcesses = maxProcesses;
        _wallHighWater = _clock.GetUtcNow().ToUnixTimeMilliseconds();
    }

    // A wall-clock step back up to this size (an NTP correction) is absorbed by reporting the mark;
    // only a larger one is rollback. Far inside the 30 s staleness window, and harmless by the clamp.
    private const long RollbackToleranceMs = 1_000;

    private bool ReadClock(out long now)
    {
        // Mark before sample: whoever published the mark sampled before this read, so on a clock
        // that has not gone back this sample is at or past it. Sampling first let a reader that a
        // concurrent reader overtook look like rollback and refuse a valid alert, which for a
        // sidecar that can only cancel means the flagged workload kept running.
        long mark = Volatile.Read(ref _wallHighWater);
        long sample = _clock.GetUtcNow().ToUnixTimeMilliseconds();
        if (mark - sample > RollbackToleranceMs) { now = mark; return false; }
        // Report the later of sample and mark, so time as the registrar sees it never runs
        // backwards: a step inside the tolerance cannot make a stale event fresh or an expired task
        // live. Monotonic lifetime is checked separately in Expired.
        while (sample > mark)
        {
            long actual = Interlocked.CompareExchange(ref _wallHighWater, sample, mark);
            if (actual == mark) { now = sample; return true; }
            mark = actual;
        }
        now = mark;
        return true;
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
    // Writers hold _writer, so reading _snapshot here and publishing its successor cannot interleave.
    private void Publish(RegisteredTask task, (SensorProcess Sensor, NativeProcess Native)? bound = null)
    {
        var current = _snapshot;
        int processes = current.ProcessCount + task.Processes.Count
            - (current.Tasks.TryGetValue(task.Task, out var previous) ? previous.Processes.Count : 0);
        var index = current.Index;
        // Keep retired claims as tombstones. A stale sensor key must never become a different task.
        // Capacity exhaustion fails closed; Evict does not reclaim identity history for reuse.
        if (bound is { } b)
        {
            var claim = new Claim(task.Task, b.Native);
            index = index.SetItem(b.Sensor, index.TryGetValue(b.Sensor, out var claims) ? claims.Add(claim) : [claim]);
        }
        Volatile.Write(ref _snapshot, new Snapshot(current.Tasks.SetItem(task.Task, task), index, processes,
            checked(current.Revision + 1)));
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
                || _snapshot.ProcessCount >= _maxProcesses
                || _snapshot.Tasks.Values.Any(t => t.Root.SameBoundary(root)))
                throw new InvalidDataException("Invalid, reused or over-capacity admission.");
            var process = new RegisteredProcess(root, null, now, true, null);
            Publish(new RegisteredTask(task, root, tenant, agent, profileHash, rule, AdmissionState.Admitting,
                now, expiresUnixMs, _clock.GetTimestamp(), TimeSpan.FromMilliseconds(expiresUnixMs - now), 0,
                ImmutableDictionary<NativeProcess, RegisteredProcess>.Empty.Add(root, process), [root.Pid]));
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
            Publish(t with { Processes = t.Processes.SetItem(native, p with { Sensor = sensor }) }, (sensor, native));
            var conflicts = _snapshot.Index[sensor];
            if (conflicts.Length > 1)
            {
                foreach (var id in conflicts.Select(c => c.Task).Distinct())
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
                || t.LivePids.Contains(child.Pid)
                || _snapshot.ProcessCount >= _maxProcesses)
            {
                Publish(t with { State = AdmissionState.Draining });
                throw new InvalidDataException("Lineage incomplete, escaped or over capacity; drain required.");
            }
            // Kernel cgroup inheritance enforces the lease independently of telemetry. This table
            // records ONLY sequenced native fork evidence, never Falcon parent names or PPIDs.
            Publish(t with { LineageSequence = sequence, LivePids = t.LivePids.Add(child.Pid),
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
            Publish(t with { LineageSequence = sequence, LivePids = t.LivePids.Remove(native.Pid),
                Processes = t.Processes.SetItem(native, p with { Live = false }) });
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
    internal object SensorIndex => Volatile.Read(ref _snapshot).Index;
    internal AdmissionResolution Resolve(SensorObservation observation)
    {
        if (!ReadClock(out long now)) return new(ResolutionStatus.ClockRollback, default, default, 0);
        return Resolve(Volatile.Read(ref _snapshot), observation, now);
    }
    private AdmissionResolution Resolve(Snapshot snapshot, SensorObservation o, long now)
    {
        AdmissionResolution Refuse(ResolutionStatus status) => new(status, default, default, snapshot.Revision);
        if (!snapshot.Index.TryGetValue(o.Sensor, out var claims)) return Refuse(ResolutionStatus.Unknown);
        if (claims.Length != 1) return Refuse(ResolutionStatus.Ambiguous);
        // Tasks and processes are kept as tombstones, never removed, so a claim always finds its record.
        var t = snapshot.Tasks[claims[0].Task]; var p = t.Processes[claims[0].Native];
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
