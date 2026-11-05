using System.Security.Cryptography;
using System.Text.Json;

namespace Splat.AlertSidecar;

internal static class RegistrarChecks
{
    // Synthetic host/collector records exercise the real registrar and HTTP->SQLite path.
    // They are deliberately NOT labelled kernel observations or live Falcon attestations.
    private sealed class Clock : TimeProvider
    {
        internal long Wall = 1_800_000_000_000, Ticks;
        // Runs once, after the next sample is taken and before it is returned: another reader
        // acting between a reader's clock sample and whatever that reader does next.
        internal Action? OnNextRead;
        public override DateTimeOffset GetUtcNow()
        {
            long wall = Wall;
            Interlocked.Exchange(ref OnNextRead, null)?.Invoke();
            return DateTimeOffset.FromUnixTimeMilliseconds(wall);
        }
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Ticks;
        internal void Advance(long ms) { Wall += ms; Ticks += ms; }
    }
    internal static async Task RunAsync(string directory, Action<bool> check)
    {
        int count = 0;
        void Verify(bool value, string name) { check(value); count++; Console.WriteLine("PASS registrar: " + name); }
        void Refused(Action action, string name)
        {
            bool refused = false;
            try { action(); } catch (InvalidDataException) { refused = true; }
            Verify(refused, name);
        }
        var clock = new Clock();
        var root = new NativeProcess("node", Guid.NewGuid(), 123, Guid.NewGuid(), 77, 9000);
        var sensor = new SensorProcess("tenant", "agent", "18446744073709551615", new string('A', 64));
        Guid task = Guid.NewGuid();
        SensorObservation Event(SensorProcess? s = null, NativeProcess? n = null, long? time = null) =>
            new(s ?? sensor, "rule", "event", time ?? clock.Wall, n);
        TrustedAdmissionRegistrar Seed(Guid? id = null, NativeProcess? native = null, int maxProcesses = 64)
        {
            var r = new TrustedAdmissionRegistrar(clock, 16, maxProcesses);
            r.Begin(id ?? task, native ?? root, sensor.Tenant, sensor.Agent, sensor.ProfileHash, "rule", clock.Wall + 60_000);
            return r;
        }
        var minimal = new MinimalAdmissionRegistrar();
        minimal.Register(task, root, sensor);
        Verify(minimal.Resolve(root, sensor) == task, "minimal exact composite lookup");
        Verify(minimal.Resolve(root with { StartTicks = 9001 }, sensor) is null, "minimal PID reuse refused");
        minimal.Register(Guid.NewGuid(), root, sensor);
        Verify(minimal.Resolve(root, sensor) is null, "minimal ambiguity refused");

        var registrar = Seed();
        Verify(registrar.State(task) == AdmissionState.Admitting, "begins in Admitting");
        Verify(registrar.Resolve(Event()).Status == ResolutionStatus.Unknown, "unknown sensor cannot enroll itself");
        Refused(() => registrar.Activate(task), "activation without sensor identity refused");
        Refused(() => registrar.BindSensor(task, root with { StartTicks = 9001 }, sensor), "recycled PID registration refused");
        Refused(() => registrar.BindSensor(task, root, sensor with { Tenant = "other" }), "cross-tenant registration refused");
        registrar.BindSensor(task, root, sensor);
        Verify(registrar.Resolve(Event()).Status == ResolutionStatus.Inactive, "bound but not active refused");
        registrar.Activate(task);
        Verify(registrar.Resolve(Event()).Task == task, "one observation resolves exactly one task");
        foreach (var bad in new[] { root with { StartTicks = 9001 }, root with { Pid = 78 },
            root with { Boot = Guid.NewGuid() }, root with { CgroupGeneration = Guid.NewGuid() },
            root with { Cgroup = 124 }, root with { Node = "other" } })
            Verify(registrar.Resolve(Event(n: bad)).Status == ResolutionStatus.IdentityMismatch, "native composite field mismatch refused");
        foreach (var bad in new[] { sensor with { Tenant = "other" }, sensor with { Agent = "other" },
            sensor with { ProcessInstance = "77" }, sensor with { ProfileHash = new string('B', 64) } })
            Verify(registrar.Resolve(Event(bad)).Status == ResolutionStatus.Unknown, "sensor composite field mismatch refused");
        Verify(registrar.Resolve(Event(time: clock.Wall - 1)).Status == ResolutionStatus.Stale, "pre-admission timestamp refused");
        Verify(registrar.Resolve(Event(time: clock.Wall + 2001)).Status == ResolutionStatus.Stale, "future timestamp refused");
        Verify(registrar.Resolve(Event() with { Rule = "other" }).Status == ResolutionStatus.IdentityMismatch, "wrong rule refused");
        Refused(() => registrar.Begin(task, root, "tenant", "agent", sensor.ProfileHash, "rule", clock.Wall + 1000), "task UUID reuse refused");
        Refused(() => registrar.Begin(Guid.NewGuid(), root, "tenant", "agent", sensor.ProfileHash, "rule", clock.Wall + 1000), "cgroup lifetime shared across tasks refused");

        var child = root with { Pid = 78, StartTicks = 9010 };
        var childSensor = sensor with { ProcessInstance = "child-instance" };
        registrar.Fork(task, root, child, 1, clock.Wall);
        Verify(registrar.Resolve(Event(childSensor)).Status == ResolutionStatus.Unknown, "unbound child sensor refused");
        registrar.BindSensor(task, child, childSensor);
        Verify(registrar.Resolve(Event(childSensor)).Task == task, "enrolled child inherits task");
        registrar.Exit(task, root, 2);
        Verify(registrar.Resolve(Event()).Status == ResolutionStatus.Inactive, "exited root refused");
        Verify(registrar.Resolve(Event(childSensor)).Task == task, "root exit does not erase child");
        var grandchild = root with { Pid = 79, StartTicks = 9020 };
        var grandSensor = sensor with { ProcessInstance = "grandchild-instance" };
        registrar.Fork(task, child, grandchild, 3, clock.Wall);
        registrar.BindSensor(task, grandchild, grandSensor);
        Verify(registrar.Resolve(Event(grandSensor)).Task == task, "grandchild resolves through exact enrolled parent");
        registrar.Exit(task, child, 4);
        var recycled = child with { StartTicks = 9030 };
        registrar.Fork(task, grandchild, recycled, 5, clock.Wall);
        var recycledSensor = sensor with { ProcessInstance = "new-child-instance" };
        registrar.BindSensor(task, recycled, recycledSensor);
        Verify(registrar.Resolve(Event(childSensor)).Status == ResolutionStatus.Inactive, "delayed old child event cannot reach recycled PID");
        Verify(registrar.Resolve(Event(recycledSensor)).Native == recycled, "new generation has independent identity");

        var gap = Seed(); gap.BindSensor(task, root, sensor); gap.Activate(task);
        Refused(() => gap.Fork(task, root, child, 2, clock.Wall), "lost fork sequence refused");
        Verify(gap.State(task) == AdmissionState.Draining, "lineage gap fences task");
        foreach (var escaped in new[] { child with { Cgroup = 124 }, child with { Boot = Guid.NewGuid() },
            child with { CgroupGeneration = Guid.NewGuid() } })
        {
            var r = Seed(); r.BindSensor(task, root, sensor); r.Activate(task);
            Refused(() => r.Fork(task, root, escaped, 1, clock.Wall), "cross-boundary child refused");
            Verify(r.State(task) == AdmissionState.Draining, "escape observation fences registration");
        }
        var unknownParent = Seed();
        Refused(() => unknownParent.Fork(task, child, grandchild, 1, clock.Wall), "unenrolled parent refused");
        var full = Seed(maxProcesses: 1);
        Refused(() => full.Fork(task, root, child, 1, clock.Wall), "lineage capacity fails closed");

        var ambiguous = Seed(); ambiguous.BindSensor(task, root, sensor); ambiguous.Activate(task);
        var secondTask = Guid.NewGuid(); var secondRoot = root with { Cgroup = 456, CgroupGeneration = Guid.NewGuid(), Pid = 88 };
        ambiguous.Begin(secondTask, secondRoot, sensor.Tenant, sensor.Agent, sensor.ProfileHash, "rule", clock.Wall + 60_000);
        Refused(() => ambiguous.BindSensor(secondTask, secondRoot, sensor), "duplicate sensor identity quarantines both tasks");
        Verify(ambiguous.Resolve(Event()).Status == ResolutionStatus.Ambiguous, "ambiguity has no winner");
        Verify(ambiguous.State(task) == AdmissionState.Draining && ambiguous.State(secondTask) == AdmissionState.Draining,
            "both conflicting tasks draining");

        var expired = Seed(); expired.BindSensor(task, root, sensor); expired.Activate(task);
        clock.Advance(30_001);
        Verify(expired.Resolve(Event(time: clock.Wall - 30_001)).Status == ResolutionStatus.Stale, "delayed observation rejected");
        clock.Advance(29_999);
        Verify(expired.Resolve(Event()).Status == ResolutionStatus.Inactive, "exact deadline rejected before sweep");
        expired.EvictExpired(); Verify(expired.State(task) == AdmissionState.Evicted, "expired registrations evicted");
        Refused(() => expired.Begin(task, root, "tenant", "agent", sensor.ProfileHash, "rule", clock.Wall + 1000), "eviction preserves UUID tombstone");
        var rollback = Seed(); rollback.BindSensor(task, root, sensor); rollback.Activate(task);
        clock.Advance(40_000);
        // A concurrent reader publishes a time 2 s later (past the tolerance) between this reader's
        // clock sample and its next step: interleaving on a loaded host, not a clock going back.
        clock.OnNextRead = () => { clock.Wall += 2_000; _ = rollback.Resolve(Event()); };
        Verify(rollback.Resolve(Event(time: clock.Wall)).Task == task, "reader overtaken by a concurrent reader resolves");
        long mark = clock.Wall;
        clock.Wall -= 5;
        Verify(rollback.Resolve(Event(time: mark)).Task == task, "wall-clock step back inside the tolerance resolves");
        Verify(rollback.Resolve(Event(time: mark - 30_001)).Status == ResolutionStatus.Stale,
            "step back cannot make a stale event fresh");
        clock.Wall = mark - 60_000;
        Verify(rollback.Resolve(Event()).Status == ResolutionStatus.ClockRollback, "wall-clock rollback refused");
        rollback.EvictExpired(); Verify(rollback.State(task) == AdmissionState.Evicted, "rollback eviction cannot revive identity");
        clock.Wall = mark;
        var monotonic = Seed(); monotonic.BindSensor(task, root, sensor); monotonic.Activate(task);
        clock.Ticks += 60_000;
        Verify(monotonic.Resolve(Event()).Status == ResolutionStatus.Inactive, "monotonic expiry independent of wall clock");

        var raced = Seed(); raced.BindSensor(task, root, sensor); raced.Activate(task);
        var mailbox = new Latch(Path.Combine(directory, "registrar-race.sqlite"), "registrar-race");
        Verify(raced.Resolve(Event()).Status == ResolutionStatus.Unique, "pre-drain snapshot resolves");
        raced.Drain(task);
        Verify(!raced.AdmitToMailbox(task, Event(), mailbox) && mailbox.Read().State == "idle", "stale resolution cannot commit after drain");
        var steady = Seed(); steady.BindSensor(task, root, sensor); steady.Activate(task);
        var observation = Event();
        int incorrect = 0;
        Parallel.For(0, 10_000, new ParallelOptions { MaxDegreeOfParallelism = 4 }, _ => {
            if (steady.Resolve(observation).Task != task) Interlocked.Increment(ref incorrect);
        });
        Verify(incorrect == 0, "concurrent readers see complete published snapshot");
        for (int i = 0; i < 1000; i++) _ = steady.Resolve(observation);
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        for (int i = 0; i < 100_000; i++) _ = steady.Resolve(observation);
        Verify(GC.GetAllocatedBytesForCurrentThread() == allocated, "100000 steady lookups allocate zero managed bytes on this thread");
        Verify(!steady.AdmitToMailbox(Guid.NewGuid(), Event(), mailbox), "fixed-task mailbox rejects another task");
        var publication = Seed(); publication.BindSensor(task, root, sensor); publication.Activate(task);
        using var started = new ManualResetEventSlim();
        using var drained = new ManualResetEventSlim();
        int staleAfterDrain = 0;
        var reader = Task.Run(() => {
            started.Set();
            while (!drained.IsSet) _ = publication.Resolve(observation);
            for (int i = 0; i < 10_000; i++)
                if (publication.Resolve(observation).Status == ResolutionStatus.Unique) staleAfterDrain++;
        });
        if (!started.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException("Reader did not start.");
        publication.Drain(task); drained.Set();
        await reader.WaitAsync(TimeSpan.FromSeconds(10));
        Verify(staleAfterDrain == 0, "concurrent publication exposes no active result after drain completes");

        await HttpChecks(directory, Verify);
        Console.WriteLine($"PASS {count} registrar checks; synthetic identity producers, no kernel/vendor qualification.");
    }

    private static async Task HttpChecks(string directory, Action<bool, string> verify)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var profile = new FalconProfile(1, "test-event", "/type", "/cid", "/aid", "/process", "/rule", "/id", "/time", "unix-ms");
        byte[] profileBytes = JsonSerializer.SerializeToUtf8Bytes(profile, Binding.Json);
        string hash = Convert.ToHexString(SHA256.HashData(profileBytes));
        var task = Guid.NewGuid();
        var root = new NativeProcess("node", Guid.NewGuid(), 123, Guid.NewGuid(), 77, 9000);
        var sensor = new SensorProcess("tenant", "agent", "root", hash);
        var registrar = new TrustedAdmissionRegistrar();
        var binding = new Binding(task.ToString("N"), root.Node, root.Boot, root.Cgroup, root.Pid, root.StartTicks,
            "falcon", "rule", now + 60_000, 19443, 19444, new FalconIdentity(sensor.Tenant, sensor.Agent, "root", now, hash));
        registrar.Begin(task, root, sensor.Tenant, sensor.Agent, hash, "rule", binding.ExpiresUnixMs);
        registrar.BindSensor(task, root, sensor);
        registrar.Activate(task);
        var child = root with { Pid = 78, StartTicks = 9010 };
        registrar.Fork(task, root, child, 1, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        registrar.BindSensor(task, child, sensor with { ProcessInstance = "child" });
        var mailbox = new Latch(Path.Combine(directory, "registrar-http.sqlite"), binding.Fingerprint);
        const string auth = "Bearer synthetic-regression-credential";
        using var ingress = new AlertIngress(binding, mailbox, Credentials.Digest(auth), new FalconAdapter(binding, profileBytes), registrar: registrar);
        bool wrongMailbox = false;
        try
        {
            using var invalid = new AlertIngress(binding,
                new Latch(Path.Combine(directory, "registrar-other.sqlite"), "wrong-binding"),
                Credentials.Digest(auth), new FalconAdapter(binding, profileBytes), registrar: registrar);
        }
        catch (InvalidDataException) { wrongMailbox = true; }
        verify(wrongMailbox, "HTTP constructor refuses mailbox for a different binding");
        using var services = new ServiceCollection().AddOptions().BuildServiceProvider();
        async Task<int> Send(string process, string tenant = "tenant")
        {
            var http = new DefaultHttpContext { RequestServices = services };
            http.Request.Scheme = "https"; http.Request.Method = "POST"; http.Request.Path = ingress.Path;
            http.Request.Host = new HostString("127.0.0.1", binding.ListenPort);
            http.Request.ContentType = "application/json"; http.Request.Headers.Authorization = auth;
            using var body = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(new { type = "test-event", cid = tenant,
                aid = "agent", process, rule = "rule", id = "event", time = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() }));
            using var output = new MemoryStream(); http.Request.Body = body; http.Response.Body = output;
            await ingress.HandleAsync(http); return http.Response.StatusCode;
        }
        verify(await Send("child", "other") == 409 && mailbox.Read().State == "idle", "HTTP cross-tenant event leaves mailbox idle");
        verify(await Send("78") == 409 && mailbox.Read().State == "idle", "HTTP bare PID leaves mailbox idle");
        verify(await Send("untracked-child") == 409 && mailbox.Read().State == "idle", "HTTP cannot enroll descendant");
        verify(await Send("child") == 202 && mailbox.Read().State == "pending", "HTTP enrolled child commits cancellation to parent task mailbox");
        registrar.Drain(task);
        verify(await Send("child") == 409, "HTTP after drain rejected");
    }
}
