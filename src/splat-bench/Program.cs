using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;

namespace SplatBench;

/// <summary>
/// Measures the wall-clock latency the governed Windows launch path ADDS, by running the same
/// trivial tool twice on the same machine: once through the full containment path, once bare.
///
/// It deliberately does not benchmark anyone else's product. The 200-800ms attributed to cloud
/// sandboxes in the enterprise brief is a third-party claim this harness cannot verify, and
/// publishing unverifiable numbers about named competitors is exactly what made the latency claim
/// unsendable. What can be owned is the delta measured here.
///
/// The tool under test is `cmd.exe /c exit 0` on purpose: the goal is to measure the overhead, so
/// the payload must be as close to zero as a real process launch allows. Anything heavier would
/// dilute the very number being reported.
///
/// Not an xUnit test, and not run by `dotnet test`. Timing assertions inside the suite would be
/// flaky on a loaded machine and would eventually be muted, which is worse than having no gate.
/// The suite instead binds the DOCUMENTED figure to whatever this harness last committed.
/// </summary>
internal static class Program
{
    private const string ToolPath = @"C:\Windows\System32\cmd.exe";
    private const string ToolArgs = "/c exit 0";
    private const int LaunchTimeoutSeconds = 30;

    private static async Task<int> Main(string[] args)
    {
        int iterations = IntArg(args, "--iterations", 50);
        int warmup = IntArg(args, "--warmup", 5);
        string outPath = StringArg(args, "--out", DefaultEvidencePath());

        if (iterations < 20)
        {
            Console.Error.WriteLine($"[bench] refusing to record fewer than 20 iterations (asked for {iterations}); a percentile over a smaller sample is noise wearing a number's clothes.");
            return 2;
        }

        if (!File.Exists(ToolPath))
        {
            Console.Error.WriteLine($"[bench] tool under test not found: {ToolPath}");
            return 2;
        }

        Console.WriteLine($"[bench] tool           {ToolPath} {ToolArgs}");
        Console.WriteLine($"[bench] iterations     {iterations} (plus {warmup} discarded warmup)");
        Console.WriteLine($"[bench] elevated       {IsElevated()}");
        Console.WriteLine();

        var failures = new List<string>();

        // Warmup is discarded rather than averaged in: the first governed launch pays for JIT of the
        // whole Win32 interop path and a cold filesystem, which is a real cost but not a per-call one.
        for (int i = 0; i < warmup; i++)
        {
            try
            {
                await ContainedIterationAsync();
                await BareIterationAsync();
            }
            catch (Exception ex)
            {
                failures.Add($"warmup {i}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        var contained = new Phases(iterations);
        var bare = new List<double>(iterations);

        // Arms alternate rather than running in blocks, so that a machine that gets busier partway
        // through the run degrades both arms together instead of biasing the delta.
        for (int i = 0; i < iterations; i++)
        {
            try
            {
                contained.Add(await ContainedIterationAsync());
            }
            catch (Exception ex)
            {
                failures.Add($"contained {i}: {ex.GetType().Name}: {ex.Message}");
            }

            try
            {
                bare.Add(await BareIterationAsync());
            }
            catch (Exception ex)
            {
                failures.Add($"bare {i}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // A verdict about MEASUREMENT VALIDITY, not about speed. A performance budget belongs to
        // whoever is gating on it, and baking an arbitrary threshold in here would invent a claim
        // rather than record one.
        bool complete = contained.Total.Count == iterations && bare.Count == iterations;
        if (!complete)
        {
            failures.Add($"incomplete sample: contained={contained.Total.Count}, bare={bare.Count}, wanted {iterations} of each");
        }

        string verdict = failures.Count == 0 ? "PASS" : "FAIL";

        var containedStats = Stats.From(contained.Total);
        var bareStats = Stats.From(bare);

        Console.WriteLine($"  bare       p50 {bareStats.P50:F2} ms   p95 {bareStats.P95:F2} ms");
        Console.WriteLine($"  contained  p50 {containedStats.P50:F2} ms   p95 {containedStats.P95:F2} ms");
        Console.WriteLine($"  overhead   p50 {containedStats.P50 - bareStats.P50:F2} ms   p95 {containedStats.P95 - bareStats.P95:F2} ms");
        Console.WriteLine();
        Console.WriteLine($"  jail provision  p50 {Stats.From(contained.Jail).P50:F2} ms");
        Console.WriteLine($"  sandbox setup   p50 {Stats.From(contained.Sandbox).P50:F2} ms");
        Console.WriteLine($"  launch + wait   p50 {Stats.From(contained.Launch).P50:F2} ms");
        Console.WriteLine($"  jail drain      p50 {Stats.From(contained.Drain).P50:F2} ms");
        Console.WriteLine();

        WriteEvidence(outPath, verdict, iterations, containedStats, bareStats, contained, failures);

        Console.WriteLine($"[bench] verdict {verdict}");
        foreach (var f in failures)
        {
            Console.Error.WriteLine($"[bench] {f}");
        }

        return verdict == "PASS" ? 0 : 1;
    }

    /// <summary>
    /// One full governed launch, phase by phase: ACL jail, job object with its clamps, suspended
    /// start under a restricted token, then the jail drain. Phases are timed separately because a
    /// single blended number hides which ring costs what, and that is the first question a reader
    /// with a latency budget asks.
    /// </summary>
    private static async Task<(double Jail, double Sandbox, double Launch, double Drain)> ContainedIterationAsync()
    {
        var jailManager = new NtAclJailManager();
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        var missionId = Guid.NewGuid();

        var sw = Stopwatch.StartNew();
        string jailPath = await jailManager.ProvisionJailAsync(missionId);
        double jail = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        using var sandbox = new Win32JobSandbox($"BenchJob_{missionId:N}");
        sandbox.ConfigureExtendedLimits(256L * 1024 * 1024, 50);
        double sandboxSetup = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        await launcher.LaunchSuspendedInJobAsync(
            ToolPath, ToolArgs, jailPath, sandbox,
            dropAdminPrivileges: true,
            timeoutSeconds: LaunchTimeoutSeconds);
        double launch = sw.Elapsed.TotalMilliseconds;

        sw.Restart();
        await jailManager.DrainAndCleanupJailAsync(jailPath);
        double drain = sw.Elapsed.TotalMilliseconds;

        return (jail, sandboxSetup, launch, drain);
    }

    /// <summary>
    /// The same tool with no containment at all. The working directory is still created and removed
    /// so the delta reflects the locks rather than directory I/O both arms would pay anyway.
    /// </summary>
    private static async Task<double> BareIterationAsync()
    {
        string dir = Path.Combine(Path.GetTempPath(), "splat_bench_bare_" + Guid.NewGuid().ToString("N"));

        var sw = Stopwatch.StartNew();
        Directory.CreateDirectory(dir);

        using (var p = new Process())
        {
            p.StartInfo = new ProcessStartInfo(ToolPath, ToolArgs)
            {
                WorkingDirectory = dir,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            p.Start();
            await p.WaitForExitAsync();
        }

        Directory.Delete(dir, recursive: true);
        return sw.Elapsed.TotalMilliseconds;
    }

    private static void WriteEvidence(
        string path, string verdict, int iterations,
        Stats contained, Stats bare, Phases phases, List<string> failures)
    {
        var root = new JsonObject
        {
            ["schema"] = 1,
            ["verdict"] = verdict,
            ["recorded_utc"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            ["subject"] = "governed Windows launch overhead vs the same tool run bare",
            ["tool"] = $"{ToolPath} {ToolArgs}",
            ["os_version"] = Environment.OSVersion.Version.ToString(),
            ["processor_count"] = Environment.ProcessorCount,
            ["elevated"] = IsElevated(),
            ["iterations"] = iterations,
            ["bare_ms"] = bare.ToJson(),
            ["contained_ms"] = contained.ToJson(),
            ["overhead_ms"] = new JsonObject
            {
                ["p50"] = Round(contained.P50 - bare.P50),
                ["p95"] = Round(contained.P95 - bare.P95)
            },
            ["contained_phase_p50_ms"] = new JsonObject
            {
                ["jail_provision"] = Round(Stats.From(phases.Jail).P50),
                ["sandbox_setup"] = Round(Stats.From(phases.Sandbox).P50),
                ["launch_and_wait"] = Round(Stats.From(phases.Launch).P50),
                ["jail_drain"] = Round(Stats.From(phases.Drain).P50)
            },
            ["failures"] = new JsonArray(failures.Select(f => (JsonNode)JsonValue.Create(f)!).ToArray())
        };

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + Environment.NewLine);
        Console.WriteLine($"[evidence] wrote {path}");
    }

    private static string DefaultEvidencePath()
    {
        string dir = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "evidence");
        return Path.GetFullPath(Path.Combine(dir, $"bench-windows-{Environment.OSVersion.Version}.json"));
    }

    private static bool IsElevated()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static double Round(double v) => Math.Round(v, 2);

    private static int IntArg(string[] args, string name, int fallback)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length && int.TryParse(args[i + 1], out int v) ? v : fallback;
    }

    private static string StringArg(string[] args, string name, string fallback)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : fallback;
    }

    private sealed class Phases(int capacity)
    {
        public List<double> Jail { get; } = new(capacity);
        public List<double> Sandbox { get; } = new(capacity);
        public List<double> Launch { get; } = new(capacity);
        public List<double> Drain { get; } = new(capacity);
        public List<double> Total { get; } = new(capacity);

        public void Add((double Jail, double Sandbox, double Launch, double Drain) p)
        {
            Jail.Add(p.Jail);
            Sandbox.Add(p.Sandbox);
            Launch.Add(p.Launch);
            Drain.Add(p.Drain);
            Total.Add(p.Jail + p.Sandbox + p.Launch + p.Drain);
        }
    }

    private readonly record struct Stats(int N, double Min, double P50, double P95, double Max, double Mean)
    {
        public static Stats From(List<double> raw)
        {
            if (raw.Count == 0)
            {
                return new Stats(0, 0, 0, 0, 0, 0);
            }

            var s = raw.ToList();
            s.Sort();
            return new Stats(s.Count, s[0], Percentile(s, 0.50), Percentile(s, 0.95), s[^1], s.Average());
        }

        /// <summary>
        /// Nearest-rank on the sorted sample. Interpolating between neighbours would invent a
        /// latency that was never observed, which is the wrong trade for a number meant as evidence.
        /// </summary>
        private static double Percentile(List<double> sorted, double q)
        {
            int rank = (int)Math.Ceiling(q * sorted.Count);
            return sorted[Math.Clamp(rank - 1, 0, sorted.Count - 1)];
        }

        public JsonObject ToJson() => new()
        {
            ["n"] = N,
            ["min"] = Math.Round(Min, 2),
            ["p50"] = Math.Round(P50, 2),
            ["p95"] = Math.Round(P95, 2),
            ["max"] = Math.Round(Max, 2),
            ["mean"] = Math.Round(Mean, 2)
        };
    }
}
