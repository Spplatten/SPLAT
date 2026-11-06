using System.Text.Json;
namespace Splat.AlertSidecar;

internal static class SelfTest
{
    internal static int Run()
    {
        Console.WriteLine($"PASS {Checks()} checks: binding compatibility, Falcon schema/identity, Falco lease attribution, HTTP admission, freshness, durable recovery and evidence semantics.");
        return 0;
    }

    // Real parser, SQL transactions and restart recovery. No fabricated vendor/network success.
    // Returns how many checks ran, so the suite can tell a dropped check group from a passing one.
    internal static int Checks()
    {
        int assertions = 0;
        void Check(bool value) { assertions++; if (!value) throw new InvalidOperationException("Assertion " + assertions); }
        string directory = Path.Combine(Path.GetTempPath(), "splat-sidecar-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var b = new Binding(Guid.NewGuid().ToString("N"), "test-node", Guid.NewGuid(), 123, 77, 9000,
                "falco", "test-rule", now + 60000, 19443, 19444);
            b.Check(now);
            var a = new Alert(1,b.Source,"event-1",b.Rule,b.Node,b.Boot,b.Cgroup,b.Pid,b.StartTicks,now);
            Check(b.Matches(a, now));
            Check(!b.Matches(a with { StartTicks = 9001 }, now));
            Check(!b.Matches(a with { Boot = Guid.NewGuid() }, now));
            Check(!b.Matches(a with { Cgroup = 124 }, now));
            Check(!b.Matches(a with { Rule = "other" }, now));
            Check(!b.Matches(a with { ObservedUnixMs = now-30001 }, now));
            Check(!b.Matches(a with { ObservedUnixMs = now+2001 }, now));
            Check(!b.Matches(a, now+60000));
            Check(!b.Matches(a with { Pid = 78 }, now));
            Check(!b.Matches(a with { Source = "falcon" }, now));
            string path = Path.Combine(directory,"mailbox.sqlite");
            var latch = new Latch(path,b.Fingerprint);
            Check(latch.Read().State == "idle");
            Check(latch.Admit(a.AlertId, now, now));
            int admitted = 0;
            Parallel.For(0,128, new ParallelOptions { MaxDegreeOfParallelism = 4 },
                i => { if (latch.Admit("duplicate-"+i,now,now)) Interlocked.Increment(ref admitted); });
            Check(admitted == 0);
            Check(new Latch(path,b.Fingerprint).Read().State == "pending");
            Check(latch.Read().Alert == a.AlertId);
            bool refused = false;
            try { _ = new Latch(path,(b with { TaskId=Guid.NewGuid().ToString("N") }).Fingerprint); }
            catch (InvalidDataException) { refused=true; }
            Check(refused);
            latch.Finish("terminal-without-drain-proof");
            latch.Finish("host-reports-drain"); // Terminal evidence is immutable, never upgraded by a late retry.
            Check(latch.Read().State == "terminal-without-drain-proof");
            Check(!latch.Read().Reported);
            latch.MarkReported();
            Check(new Latch(path,b.Fingerprint).Read().Reported);
            Check(!latch.Admit("late",now,now));
            using var noProof = JsonDocument.Parse("""{"status":{"state":"TASK_STATE_CANCELED"},"metadata":{"urn:splat:a2a:template-lease:v1":{"workloadTerminationConfirmed":false}}}""");
            Check(Control.Outcome(noProof.RootElement) == "terminal-without-drain-proof");
            using var confirmed = JsonDocument.Parse("""{"status":{"state":"TASK_STATE_CANCELED"},"metadata":{"urn:splat:a2a:template-lease:v1":{"workloadTerminationConfirmed":true}}}""");
            Check(Control.Outcome(confirmed.RootElement) == "host-reports-drain");
            using var working = JsonDocument.Parse("""{"status":{"state":"TASK_STATE_WORKING"}}""");
            Check(Control.Outcome(working.RootElement) == null);
            var race = new Latch(Path.Combine(directory,"race.sqlite"), b.Fingerprint);
            int winners = 0;
            Parallel.For(0,128,new ParallelOptions { MaxDegreeOfParallelism=4 },i => {
                if (race.Admit("racer-"+i,now,now)) Interlocked.Increment(ref winners);
            });
            Check(winners == 1);
            Check(new Latch(Path.Combine(directory,"race.sqlite"), b.Fingerprint).Read().State == "pending");
            Check(!b.Matches(a with { Version=2 },now));
            Check(!b.Matches(a with { Node="other-node" },now));
            Check(!b.Matches(a with { AlertId="event\ninjected" },now));
            FalconChecks.RunAsync(directory,Check).GetAwaiter().GetResult();
            FalcoChecks.RunAsync(directory,Check).GetAwaiter().GetResult();
            return assertions;
        }
        finally { Directory.Delete(directory, recursive:true); }
    }
}
