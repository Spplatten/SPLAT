using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Linux;

namespace MissionController.Host;

/// <summary>What a substrate run said, whole: the report an operator reads and the status it ended on.</summary>
public sealed record SubstrateReport(int ExitCode, string Text)
{
    public bool Succeeded => ExitCode == 0;
}

/// <summary>The one change a plan on screen authorizes.</summary>
public enum SubstrateChange
{
    None,
    Mount,
    Unmount,
}

/// <summary>
/// The substrate's lifecycle as the desktop app drives it: the same doctor, mount and unmount that
/// splat-mcp runs from its command line, each report captured whole so the console can show it.
///
/// A deterministic plan-then-apply machine. A plan is the consent: <see cref="ApplyAsync"/> makes only the
/// change the last plan showed, and every run replaces the plan, so a button can never apply a plan
/// other than the report on screen. One operation runs at a time; a second is refused rather than
/// queued, because two mounts racing over /etc in the guest would leave a manifest that matches neither.
/// </summary>
public sealed class SubstrateLifecycle
{
    /// <summary>
    /// What the console runs under the lease, and how its operator acts on the report. Its operator
    /// presses buttons rather than typing flags, so the remedies name the page rather than the command.
    /// </summary>
    public const string LeasedWork = "Linux-lease templates";

    private readonly SubstrateDoctor.WslRunner _wsl;
    private readonly WslSubstrateHealthChecker _health;
    private readonly string? _daemonBinary;
    private readonly string _ledgerPath;
    private readonly string? _manifestPath;
    private readonly Func<string, string?> _environment;
    private readonly Func<CancellationToken, Task<SubstrateReport>>? _managedCheck;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public SubstrateLifecycle(
        SubstrateDoctor.WslRunner? wsl = null,
        WslSubstrateHealthChecker? health = null,
        string? daemonBinary = null,
        string? ledgerPath = null,
        string? manifestPath = null,
        Func<string, string?>? environment = null,
        Func<CancellationToken, Task<SubstrateReport>>? managedCheck = null)
    {
        _wsl = wsl ?? SubstrateDoctor.RunWslAsync;
        _health = health ?? new WslSubstrateHealthChecker();
        _daemonBinary = daemonBinary;
        // The console's own chain, which is not splat-mcp's: the two hosts keep separate ledgers unless
        // SPLAT_DB_PATH points both at one, and a doctor that inspected the other file would vouch for
        // a ledger this host never writes.
        _ledgerPath = ledgerPath ?? SqliteStorageContext.GetDefaultDatabasePath();
        _manifestPath = manifestPath;
        _environment = environment ?? Environment.GetEnvironmentVariable;
        _managedCheck = managedCheck;
    }

    /// <summary>The change the last plan showed, or <see cref="SubstrateChange.None"/>.</summary>
    public SubstrateChange Planned { get; private set; }

    public bool IsManaged => _managedCheck is not null;

    /// <summary>
    /// The daemon an installed console ships beside it. The community installer lays out
    /// <c>&lt;install&gt;\App</c> and <c>&lt;install&gt;\Linux\splat-agent</c>; a build with neither, such
    /// as a developer's, gets null and mounting builds the daemon from the repository with cargo.
    /// </summary>
    public static string? DaemonBesideApp(string appDirectory)
    {
        string candidate = Path.GetFullPath(Path.Combine(appDirectory, "..", "Linux", "splat-agent"));
        return File.Exists(candidate) ? candidate : null;
    }

    public Task<SubstrateReport> CheckAsync(CancellationToken ct = default) =>
        RunAsync(SubstrateChange.None, async output =>
        {
            if (_managedCheck is null)
                return await SubstrateDoctor.RunAsync(Doctor(), output, _wsl, _health, ledgerPath: _ledgerPath, ct: ct);
            SubstrateReport report = await _managedCheck(ct);
            await output.WriteAsync(report.Text);
            return report.ExitCode;
        });

    /// <summary>Shows what mounting would change; a plan with steps left authorizes <see cref="ApplyAsync"/>.</summary>
    public Task<SubstrateReport> PlanMountAsync(CancellationToken ct = default) =>
        RunAsync(SubstrateChange.Mount, output => Provision(apply: false, output, ct));

    /// <summary>Shows what unmounting would take out; a plan that found a manifest authorizes <see cref="ApplyAsync"/>.</summary>
    public Task<SubstrateReport> PlanUnmountAsync(CancellationToken ct = default) =>
        RunAsync(SubstrateChange.Unmount, output => Unmount(apply: false, output, ct));

    /// <summary>Makes the change the last plan showed, and nothing else.</summary>
    public async Task<SubstrateReport> ApplyAsync(CancellationToken ct = default)
    {
        if (!await _gate.WaitAsync(0, ct))
        {
            return Busy;
        }

        try
        {
            SubstrateChange change = Planned;
            // Spent before it runs: a failed apply must be planned again, against the state it left.
            Planned = SubstrateChange.None;
            return change switch
            {
                SubstrateChange.Mount => await CaptureAsync(output => Provision(apply: true, output, ct)),
                SubstrateChange.Unmount => await CaptureAsync(output => Unmount(apply: true, output, ct)),
                _ => new SubstrateReport(1, "Nothing is planned, so nothing was changed. Plan a mount or an unmount first, read it, then apply it."),
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private static SubstrateReport Busy { get; } =
        new(1, "Another substrate operation is still running. Nothing was started; wait for it to finish.");

    private DoctorOptions Doctor() =>
        new(null, null, _environment(LedgerKeyFile.EnvironmentVariable), _environment(RunRecordKeyFile.EnvironmentVariable))
        {
            LeasedWork = LeasedWork,
            DaemonRemedy = "Mount, on the Kernel Lease page, installs the daemon this build carries",
            CeilingRemedy = "Mount, on the Kernel Lease page, writes one",
        };

    private Task<int> Provision(bool apply, TextWriter output, CancellationToken ct) =>
        IsManaged ? RefuseManagedChange(output) : SubstrateProvisioner.RunAsync(new ProvisionOptions(apply), output, _wsl, _health,
            agentBinaryPath: _daemonBinary, manifestPath: _manifestPath, ct: ct);

    private Task<int> Unmount(bool apply, TextWriter output, CancellationToken ct) =>
        IsManaged ? RefuseManagedChange(output) : SubstrateUnmounter.RunAsync(new UnmountOptions(apply, _manifestPath), output, _wsl, ct);

    private static Task<int> RefuseManagedChange(TextWriter output)
    {
        // Never mutate the operator's default distro when missions target a different account's
        // guest. Installing or removing that service remains the administrator's deployment action.
        output.WriteLine("This guest belongs to the managed service. Its administrator installs or removes it; nothing was changed.");
        return Task.FromResult(CrashedExitCode);
    }

    /// <summary>
    /// Runs one report under the gate and records what it authorizes: a mount plan with steps left
    /// (exit 1), an unmount plan that found a manifest (exit 0). A check authorizes nothing.
    /// </summary>
    private async Task<SubstrateReport> RunAsync(SubstrateChange plans, Func<TextWriter, Task<int>> run)
    {
        if (!await _gate.WaitAsync(0))
        {
            return Busy;
        }

        try
        {
            Planned = SubstrateChange.None;
            SubstrateReport report = await CaptureAsync(run);
            Planned = plans switch
            {
                SubstrateChange.Mount when !report.Succeeded && report.ExitCode != CrashedExitCode => SubstrateChange.Mount,
                SubstrateChange.Unmount when report.Succeeded => SubstrateChange.Unmount,
                _ => SubstrateChange.None,
            };
            return report;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>The status of a run that threw instead of reporting; it authorizes nothing.</summary>
    public const int CrashedExitCode = -1;

    private static async Task<SubstrateReport> CaptureAsync(Func<TextWriter, Task<int>> run)
    {
        using var text = new StringWriter();
        try
        {
            return new SubstrateReport(await run(text), text.ToString());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The command line lets these reach the terminal; a window has no terminal, and a report
            // that ends mid-line with nothing after it reads as one that is still running.
            text.WriteLine();
            text.WriteLine($"Stopped: {ex.Message}");
            return new SubstrateReport(CrashedExitCode, text.ToString());
        }
    }
}
