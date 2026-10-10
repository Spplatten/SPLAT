using MissionController.Host;
using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The console's plan-then-apply machine over the shared substrate code. What is held here is consent:
/// an apply makes only the change the last plan on screen showed, once, and anything else that runs in
/// between spends the plan. The guest is a recording stand-in, so "changed nothing" is asserted on the
/// commands it was handed, not inferred from a report.
/// </summary>
public sealed class SubstrateLifecycleTests
{
    private static WslAgentToken HermeticToken => new(authToken: "0123456789abcdef");

    /// <summary>Port 1: nothing answers, and no real daemon on this machine is ever asked.</summary>
    private static readonly WslSubstrateHealthChecker NoDaemon = new("127.0.0.1", 1, HermeticToken);

    private sealed class RecordingGuest
    {
        public int Calls;

        public Func<IReadOnlyList<string>, Task<(int, string)>> Answer { get; init; } =
            _ => Task.FromResult((-1, "wsl.exe did not start"));

        public Task<(int ExitCode, string Output)> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return Answer(args);
        }
    }

    private static string Scratch(string name) =>
        Path.Combine(Path.GetTempPath(), "splat-lifecycle-tests", Guid.NewGuid().ToString("N"), name);

    private static SubstrateLifecycle Lifecycle(RecordingGuest guest, string? manifestPath = null) =>
        new(guest.RunAsync, NoDaemon,
            ledgerPath: Scratch("ledger.db"),
            // Never the operator's own manifest: a scripted mount must not leave one an unmount would act on.
            manifestPath: manifestPath ?? Scratch("mount-manifest.json"),
            environment: _ => null);

    [Fact]
    public async Task AMountPlanWithStepsLeft_AuthorizesExactlyOneApply()
    {
        var guest = new RecordingGuest();
        var lifecycle = Lifecycle(guest);

        SubstrateReport plan = await lifecycle.PlanMountAsync();
        Assert.Equal(1, plan.ExitCode);
        Assert.Contains("nothing is changed", plan.Text);
        Assert.Equal(SubstrateChange.Mount, lifecycle.Planned);

        SubstrateReport applied = await lifecycle.ApplyAsync();
        Assert.Contains("SPLAT provision - making this host enforce", applied.Text);
        Assert.Equal(SubstrateChange.None, lifecycle.Planned);

        int callsAfterApply = guest.Calls;
        SubstrateReport again = await lifecycle.ApplyAsync();
        Assert.Contains("Nothing is planned", again.Text);
        Assert.Equal(callsAfterApply, guest.Calls);
    }

    [Fact]
    public async Task AnApplyWithNoPlan_TouchesNothing()
    {
        var guest = new RecordingGuest();

        SubstrateReport report = await Lifecycle(guest).ApplyAsync();

        Assert.False(report.Succeeded);
        Assert.Contains("Nothing is planned, so nothing was changed", report.Text);
        Assert.Equal(0, guest.Calls);
    }

    [Fact]
    public async Task ACheckBetweenPlanAndApply_SpendsThePlan()
    {
        var guest = new RecordingGuest();
        var lifecycle = Lifecycle(guest);
        await lifecycle.PlanMountAsync();

        await lifecycle.CheckAsync();
        int callsAfterCheck = guest.Calls;
        SubstrateReport report = await lifecycle.ApplyAsync();

        Assert.Equal(SubstrateChange.None, lifecycle.Planned);
        Assert.Contains("Nothing is planned", report.Text);
        Assert.Equal(callsAfterCheck, guest.Calls);
    }

    [Fact]
    public async Task AnUnmountPlanWithNoManifest_AuthorizesNothing()
    {
        var lifecycle = Lifecycle(new RecordingGuest());

        SubstrateReport plan = await lifecycle.PlanUnmountAsync();

        Assert.Equal(1, plan.ExitCode);
        Assert.Contains("No mount manifest", plan.Text);
        Assert.Equal(SubstrateChange.None, lifecycle.Planned);
    }

    [Fact]
    public async Task AnUnmountPlanThatFoundAManifest_AuthorizesThatUnmount()
    {
        string manifestPath = Scratch("mount-manifest.json");
        Directory.CreateDirectory(Path.GetDirectoryName(manifestPath)!);
        MountManifest.Create("Ubuntu (test)", Array.Empty<MountChange>()).Write(manifestPath);
        var lifecycle = Lifecycle(new RecordingGuest(), manifestPath);

        SubstrateReport plan = await lifecycle.PlanUnmountAsync();
        Assert.True(plan.Succeeded, plan.Text);
        Assert.True(File.Exists(manifestPath), "a plan must not take anything out");
        Assert.Equal(SubstrateChange.Unmount, lifecycle.Planned);

        SubstrateReport applied = await lifecycle.ApplyAsync();
        Assert.True(applied.Succeeded, applied.Text);
        Assert.Contains("Unmounted.", applied.Text);
        Assert.False(File.Exists(manifestPath));
    }

    [Fact]
    public async Task ARunThatThrows_SaysSo_AndAuthorizesNothing()
    {
        var guest = new RecordingGuest { Answer = _ => throw new InvalidOperationException("the guest went away") };
        var lifecycle = Lifecycle(guest);

        SubstrateReport plan = await lifecycle.PlanMountAsync();

        Assert.Equal(SubstrateLifecycle.CrashedExitCode, plan.ExitCode);
        Assert.Contains("Stopped: the guest went away", plan.Text);
        Assert.Equal(SubstrateChange.None, lifecycle.Planned);
    }

    [Fact]
    public async Task ASecondOperationWhileOneRuns_IsRefused_AndStartsNothing()
    {
        var release = new TaskCompletionSource<(int, string)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var guest = new RecordingGuest { Answer = _ => release.Task };
        var lifecycle = Lifecycle(guest);

        Task<SubstrateReport> first = lifecycle.PlanMountAsync();
        while (Volatile.Read(ref guest.Calls) == 0)
        {
            await Task.Yield();
        }

        SubstrateReport second = await lifecycle.CheckAsync();
        Assert.Contains("Another substrate operation is still running", second.Text);
        Assert.Equal(1, guest.Calls);

        release.SetResult((-1, "wsl.exe did not start"));
        Assert.Equal(1, (await first).ExitCode);
        Assert.Equal(SubstrateChange.Mount, lifecycle.Planned);
    }

    [Fact]
    public async Task TheConsolesDoctor_SpeaksToTheConsolesOperator()
    {
        SubstrateReport report = await Lifecycle(new RecordingGuest()).CheckAsync();

        Assert.Contains($"Linux lease substrate - {SubstrateLifecycle.LeasedWork}", report.Text);
        Assert.Contains("each lease is compiled from its template", report.Text);
        Assert.DoesNotContain("run_command and run_code", report.Text);
        Assert.DoesNotContain("--egress", report.Text);
    }

    [Fact]
    public void TheDaemonBesideAnInstalledConsole_IsTheOneItMounts()
    {
        string install = Path.GetDirectoryName(Scratch("x"))!;
        string app = Path.Combine(install, "App");
        Directory.CreateDirectory(app);
        Assert.Null(SubstrateLifecycle.DaemonBesideApp(app));

        Directory.CreateDirectory(Path.Combine(install, "Linux"));
        string daemon = Path.Combine(install, "Linux", "splat-agent");
        File.WriteAllBytes(daemon, new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F' });

        Assert.Equal(daemon, SubstrateLifecycle.DaemonBesideApp(app + Path.DirectorySeparatorChar));
    }

    [Fact]
    public async Task AManagedGuest_IsCheckedThroughItsService_AndNeverMutatesTheOperatorsGuest()
    {
        var guest = new RecordingGuest();
        var measured = new SubstrateReport(0, "Managed guest enforcing\n");
        var lifecycle = new SubstrateLifecycle(guest.RunAsync, NoDaemon, managedCheck: _ => Task.FromResult(measured));

        Assert.Equal(measured, await lifecycle.CheckAsync());
        Assert.Equal(SubstrateLifecycle.CrashedExitCode, (await lifecycle.PlanMountAsync()).ExitCode);
        Assert.Equal(SubstrateChange.None, lifecycle.Planned);
        Assert.Equal(SubstrateLifecycle.CrashedExitCode, (await lifecycle.PlanUnmountAsync()).ExitCode);
        Assert.False((await lifecycle.ApplyAsync()).Succeeded);
        Assert.Equal(0, guest.Calls);
    }

    [Fact]
    public async Task AnUnavailableManagedGuest_DoesNotFallBackToTheOperatorsDaemon()
    {
        var guest = new RecordingGuest();
        var lifecycle = new SubstrateLifecycle(guest.RunAsync, NoDaemon,
            managedCheck: _ => throw new IOException("service unavailable"));

        SubstrateReport report = await lifecycle.CheckAsync();

        Assert.False(report.Succeeded);
        Assert.Contains("service unavailable", report.Text);
        Assert.Equal(SubstrateChange.None, lifecycle.Planned);
        Assert.Equal(0, guest.Calls);
    }
}
