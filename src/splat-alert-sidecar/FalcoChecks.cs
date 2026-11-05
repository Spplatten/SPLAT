using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Splat.AlertSidecar;

internal static class FalcoChecks
{
    // Synthetic alerts in the shape falco_outputs.cpp and Falcosidekick write, NOT a capture from a live
    // Falco. Run --check-falco-event against one real alert from the node before relying on a binding.
    internal static async Task RunAsync(string directory, Action<bool> check)
    {
        long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        string lease = FalcoScope.Prefix + Guid.NewGuid().ToString("D");
        var binding = new Binding(Guid.NewGuid().ToString("N"), "guest", Guid.Empty, 0, 0, 0, "falco",
            "Lease wrote outside its workspace", now + 120_000, 19445, 19444, Falco: new FalcoScope(lease, "revoke", 30_000));
        binding.Check(now);
        void Refused(Action action)
        {
            bool rejected = false;
            try { action(); } catch (Exception ex) when (ex is InvalidDataException or JsonException) { rejected = true; }
            check(rejected);
        }
        Binding With(Func<FalcoScope, FalcoScope> change) => binding with { Falco = change(binding.Falco!) };

        // One identity, and only SPLAT's canonical spelling of the lease.
        Refused(() => (binding with { Pid = 77 }).Check(now));
        Refused(() => (binding with { Source = "falcon" }).Check(now));
        Refused(() => With(s => s with { LeaseCgroup = null }).Check(now));
        Refused(() => With(s => s with { LeaseCgroup = FalcoScope.Prefix + lease[FalcoScope.Prefix.Length..].ToUpperInvariant() }).Check(now));
        Refused(() => With(s => s with { LeaseCgroup = lease + "/worker" }).Check(now));
        Refused(() => With(s => s with { LeaseCgroup = FalcoScope.Prefix + Guid.Empty.ToString("D") }).Check(now));
        Refused(() => With(s => s with { OnDrop = "ignore" }).Check(now));
        Refused(() => With(s => s with { MaxSilenceMs = 9_999 }).Check(now));
        With(s => s with { OnDrop = "tolerate", MaxSilenceMs = null }).Check(now);
        check(binding.Fingerprint != With(s => s with { LeaseCgroup = FalcoScope.Prefix + Guid.NewGuid().ToString("D") }).Fingerprint);
        check(binding.Fingerprint != With(s => s with { OnDrop = "tolerate" }).Fingerprint);

        // thread.cgroups as libsinsp prints it: controllers the lease does not enable show an ancestor.
        string Cgroups(string path) => $"cpuset=/ cpu={path} io=/splat_leases memory={path} pids={path}";
        check(FalcoAdapter.LeaseOf(Cgroups(lease)) == lease);
        check(FalcoAdapter.LeaseOf(Cgroups(lease + "/worker")) == lease); // a descendant is still the lease
        check(FalcoAdapter.LeaseOf(Cgroups(lease + "x")) != lease);       // a longer name is another cgroup
        check(FalcoAdapter.LeaseOf("cpu=/user.slice memory=/user.slice/session-2.scope") == null);
        Refused(() => FalcoAdapter.LeaseOf($"memory={lease} pids={FalcoScope.Prefix}{Guid.NewGuid():D}"));

        long midnight = new DateTimeOffset(2026, 11, 4, 12, 0, 0, TimeSpan.Zero).ToUnixTimeMilliseconds();
        check(FalcoAdapter.Time("2026-11-04T12:00:00.123456789Z") == midnight + 123);
        check(FalcoAdapter.Time("2026-11-04T12:00:00.1Z") == midnight + 100); // Go's RFC3339Nano trims zeros
        check(FalcoAdapter.Time("2026-11-04T12:00:00Z") == midnight);
        foreach (string bad in new[] { "2026-11-04T12:00:00+01:00", "2026-11-04T12:00:00.Z", "2026-11-04T12:00:00.1234567890Z",
            "2026-11-04T12:00:00XYZ", "2026-11-04 12:00:00Z", "" })
            Refused(() => FalcoAdapter.Time(bad));

        long tick = 0;
        var adapter = new FalcoAdapter(binding, () => tick);
        string time = DateTimeOffset.FromUnixTimeMilliseconds(now).UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff", CultureInfo.InvariantCulture) + "456789Z";
        byte[] Event(string rule, string source = "syscall", string node = "guest", Dictionary<string, object?>? fields = null, string? uuid = null)
        {
            var root = new Dictionary<string, object?> { ["hostname"] = node, ["output"] = "synthetic", ["priority"] = "Warning",
                ["rule"] = rule, ["source"] = source, ["tags"] = new[] { "splat" }, ["time"] = time,
                ["output_fields"] = fields ?? new Dictionary<string, object?>() };
            if (uuid != null) root["uuid"] = uuid;
            return JsonSerializer.SerializeToUtf8Bytes(root);
        }
        Dictionary<string, object?> Fields(string? cgroups) => new() { ["proc.pid"] = 4242, ["thread.cgroups"] = cgroups };
        (string? Id, long Observed) Classify(byte[] data, long at, FalcoAdapter? other = null)
        {
            using var document = StrictJson.Parse(data);
            return (other ?? adapter).Classify(document.RootElement, at);
        }

        var hit = Classify(Event(binding.Rule, fields: Fields(Cgroups(lease))), now);
        check(hit.Id is { } first && first.StartsWith("falco:", StringComparison.Ordinal) && hit.Observed == now);
        check(Classify(Event(binding.Rule, fields: Fields(Cgroups(lease))), now).Id == hit.Id); // a resend is the same alert
        check(Classify(Event(binding.Rule, fields: Fields(Cgroups(lease + "/worker")), uuid: "f2c1"), now).Id == "falco:f2c1");
        check(Classify(Event(binding.Rule, fields: Fields(Cgroups(FalcoScope.Prefix + Guid.NewGuid().ToString("D")))), now).Id == null);
        check(Classify(Event(binding.Rule, fields: Fields("cpu=/user.slice memory=/user.slice")), now).Id == null);
        check(Classify(Event(binding.Rule, fields: Fields(null)), now).Id == null);
        check(Classify(Event(binding.Rule, node: "other", fields: Fields(Cgroups(lease))), now).Id == null);
        check(Classify(Event("Some other rule", fields: Fields(Cgroups(lease))), now).Id == null);
        Refused(() => Classify(Event(binding.Rule, fields: new() { ["proc.pid"] = 4242 }), now)); // output lacks %thread.cgroups
        Refused(() => Classify(Event(binding.Rule, source: "k8s_audit", fields: Fields(Cgroups(lease))), now));
        Refused(() => Classify(Event(binding.Rule, fields: Fields(Cgroups(lease))), binding.ExpiresUnixMs));
        Refused(() => Classify(Event(binding.Rule, fields: Fields(Cgroups(lease)), uuid: "bad\nid"), now));
        Refused(() => Classify(Encoding.UTF8.GetBytes("{\"rule\":\"r\",\"source\":\"syscall\",\"hostname\":\"guest\"}"), now));

        // Blindness: Falco's drop alert, then its loss counters and its own identity across snapshots.
        check(Classify(Event(FalcoAdapter.DropRule, "internal", fields: new() { ["n_drops"] = "1", ["n_evts"] = "900" }), now)
            .Id?.StartsWith("falco-drop:", StringComparison.Ordinal) == true);
        check(Classify(Event(FalcoAdapter.DropRule), now).Id == null);                     // a user rule borrowing the name
        check(Classify(Event(FalcoAdapter.DropRule, "internal", node: "other"), now).Id == null);
        Dictionary<string, object?> Snapshot(object start, object drops, object queued) =>
            new() { ["falco.start_ts"] = start, ["scap.n_drops"] = drops, ["falco.outputs_queue_num_drops"] = queued };
        string? Metrics(object start, object drops, object queued) =>
            Classify(Event(FalcoAdapter.MetricsRule, "internal", fields: Snapshot(start, drops, queued)), now).Id;
        check(Metrics(1730000000000000000UL, 5UL, 0UL) == null);                         // baseline only
        check(Metrics("1730000000000000000", "5", "0") == null);                         // re-encoded, unchanged
        check(Metrics(1730000000000000000UL, 6UL, 0UL)?.StartsWith("falco-drop:", StringComparison.Ordinal) == true);
        check(Metrics(1730000000000000000UL, 6UL, 1UL)?.StartsWith("falco-drop:", StringComparison.Ordinal) == true);
        check(Metrics(1730000099000000000UL, 0UL, 0UL)?.StartsWith("falco-restart:", StringComparison.Ordinal) == true);
        Refused(() => Metrics(1.5, 6UL, 0UL));
        var tolerant = new FalcoAdapter(With(s => s with { OnDrop = "tolerate" }));
        check(Classify(Event(FalcoAdapter.DropRule, "internal"), now, tolerant).Id == null);
        check(Classify(Event(binding.Rule, fields: Fields(Cgroups(lease))), now, tolerant).Id != null); // tolerance is about blindness only

        // Silence, measured from the node's last word on the injected monotonic clock.
        tick = 30_000; check(adapter.Silent() == null); // at the limit is not past it
        tick = 30_001; check(adapter.Silent() == "falco-silence");
        Classify(Event("Some other rule"), now);        // any authentic word from the node counts
        check(adapter.Silent() == null);
        Classify(Event("Some other rule", node: "other"), now);
        tick = 60_002; check(adapter.Silent() == "falco-silence"); // another node's traffic does not
        long open = 0;
        var forgiving = new FalcoAdapter(With(s => s with { MaxSilenceMs = null }), () => open);
        open = 86_400_000; check(forgiving.Silent() == null);

        // The real handler over ASP.NET request/response streams and real SQLite, as FalconChecks does.
        using var services = new ServiceCollection().AddOptions().BuildServiceProvider();
        string auth = "Bearer " + Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var mailbox = new Latch(Path.Combine(directory, "falco.sqlite"), binding.Fingerprint);
        Refused(() => new AlertIngress(binding, mailbox, Credentials.Digest(auth))); // no fallback to the tuple route
        using var ingress = new AlertIngress(binding, mailbox, Credentials.Digest(auth), falco: new FalcoAdapter(binding));
        check(ingress.Path == "/v1/falco/alerts");
        async Task<int> Send(byte[] body, string? path = null)
        {
            var http = new DefaultHttpContext { RequestServices = services };
            http.Request.Scheme = "https"; http.Request.Method = "POST"; http.Request.Path = path ?? ingress.Path;
            http.Request.Host = new HostString("127.0.0.1", binding.ListenPort);
            http.Request.ContentType = "application/json"; http.Request.Headers.Authorization = auth;
            using var input = new MemoryStream(body); using var output = new MemoryStream();
            http.Request.Body = input; http.Response.Body = output;
            await ingress.HandleAsync(http);
            return http.Response.StatusCode;
        }
        check(await Send(Event(binding.Rule, fields: Fields(Cgroups(FalcoScope.Prefix + Guid.NewGuid().ToString("D"))))) == 204);
        check(await Send(Event(binding.Rule, fields: new() { ["proc.pid"] = 1 })) == 409);
        check(await Send(Encoding.UTF8.GetBytes("{\"rule\":1}")) == 400);
        check(await Send(Event(binding.Rule, fields: Fields(Cgroups(lease))), "/v1/alerts") == 404);
        check(mailbox.Read().State == "idle");
        check(await Send(Event(binding.Rule, fields: Fields(Cgroups(lease)))) == 202);
        var row = mailbox.Read();
        check(row.State == "pending" && row.Alert!.StartsWith("falco:", StringComparison.Ordinal));

        // The watchdog admits silence through the same latch, once.
        long quiet = 0;
        var watched = new FalcoAdapter(binding, () => quiet);
        var silence = new Latch(Path.Combine(directory, "silence.sqlite"), binding.Fingerprint);
        quiet = 30_001;
        using (var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            var watching = watched.WatchAsync(silence, stop.Token);
            while (silence.Read().State == "idle" && !stop.IsCancellationRequested) await Task.Delay(50);
            stop.Cancel(); await watching;
        }
        var silent = silence.Read();
        check(silent.State == "pending" && silent.Alert == "falco-silence");
        Console.WriteLine("PASS Falco lease-cgroup attribution, drop/restart/silence policy and HTTP admission checks.");
    }
}
