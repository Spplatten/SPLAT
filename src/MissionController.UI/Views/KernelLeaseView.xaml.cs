using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class KernelLeaseView : Page
{
    public KernelLeaseViewModel ViewModel { get; }

    public KernelLeaseView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<KernelLeaseViewModel>();
        DataContext = ViewModel;
        // Nothing runs on open: a check probes wsl.exe and the daemon, and opening a page - including
        // the self-test opening every page - must not start the guest behind the operator's back.
    }
}
