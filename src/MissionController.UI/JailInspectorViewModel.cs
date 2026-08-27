using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;

namespace MissionController.UI.ViewModels;

public partial class JailInspectorViewModel : ObservableObject
{
    private readonly IJailManager _jailManager;

    [ObservableProperty]
    private string _jailStatusMessage = "Jail Subsystem Active";

    [ObservableProperty]
    private int _sweptJailsCount = 0;

    public JailInspectorViewModel(IJailManager jailManager)
    {
        _jailManager = jailManager;
    }

    [RelayCommand]
    public async System.Threading.Tasks.Task SweepOrphanJailsAsync()
    {
        int swept = await _jailManager.SweepOrphanJailsAsync();
        SweptJailsCount = swept;
        JailStatusMessage = $"Cleaned {swept} orphaned/stale jail directories.";
    }
}
