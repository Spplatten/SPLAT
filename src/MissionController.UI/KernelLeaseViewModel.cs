using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Host;

namespace MissionController.UI.ViewModels;

/// <summary>
/// The Kernel Lease page: the console's own door onto the daemon under its Linux-lease templates.
/// Every rule about what may be applied lives in <see cref="SubstrateLifecycle"/>, which splat-mcp's
/// doctor, provision and unmount share; this only shows the reports and keeps the buttons honest about
/// what the last plan allows.
/// </summary>
public partial class KernelLeaseViewModel : ObservableObject
{
    private readonly SubstrateLifecycle _substrate;

    [ObservableProperty]
    private string _verdict = "Not checked yet. Check this host to read whether a lease here reaches the kernel.";

    [ObservableProperty]
    private string _report = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsIdle))]
    [NotifyPropertyChangedFor(nameof(CanManage))]
    [NotifyPropertyChangedFor(nameof(CanApply))]
    private bool _isBusy;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(CanApply))]
    [NotifyPropertyChangedFor(nameof(ApplyLabel))]
    private SubstrateChange _planned;

    public KernelLeaseViewModel(SubstrateLifecycle substrate)
    {
        _substrate = substrate;
    }

    public bool IsIdle => !IsBusy;

    public bool CanManage => IsIdle && !_substrate.IsManaged;

    public bool CanApply => !IsBusy && Planned != SubstrateChange.None;

    public string ApplyLabel => Planned switch
    {
        SubstrateChange.Mount => "Mount: apply the plan below",
        SubstrateChange.Unmount => "Unmount: apply the plan below",
        _ => "Apply (plan first)",
    };

    [RelayCommand]
    public Task CheckAsync() => RunAsync(_substrate.CheckAsync, "Checking this host...");

    [RelayCommand]
    public Task PlanMountAsync() => RunAsync(_substrate.PlanMountAsync, "Planning a mount. Nothing is changed by a plan...");

    [RelayCommand]
    public Task PlanUnmountAsync() => RunAsync(_substrate.PlanUnmountAsync, "Planning an unmount. Nothing is changed by a plan...");

    [RelayCommand]
    public Task ApplyAsync() =>
        RunAsync(_substrate.ApplyAsync, Planned == SubstrateChange.Unmount ? "Unmounting..." : "Mounting...");

    private async Task RunAsync(Func<CancellationToken, Task<SubstrateReport>> run, string working)
    {
        IsBusy = true;
        Verdict = working;
        try
        {
            SubstrateReport result = await run(CancellationToken.None);
            Report = result.Text;
            Verdict = LastLine(result.Text);
        }
        catch (Exception ex)
        {
            // SubstrateLifecycle reports its own failures; this is for one it could not, so the page
            // says what happened instead of the command swallowing it or the window closing on it.
            Report = ex.ToString();
            Verdict = $"Stopped: {ex.Message}";
        }
        finally
        {
            // Read back, never assumed: the lifecycle decides what a report authorizes.
            Planned = _substrate.Planned;
            IsBusy = false;
        }
    }

    /// <summary>
    /// The banner is the report's own last line - every report ends on its verdict - so the page never
    /// says more than the report beneath it.
    /// </summary>
    private static string LastLine(string text) =>
        text.Split('\n').Select(line => line.Trim()).LastOrDefault(line => line.Length > 0) ?? "The report was empty.";
}
