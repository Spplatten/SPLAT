using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class ProjectStudioView : Page
{
    public ProjectStudioViewModel ViewModel { get; }
    private readonly LiveMissionMonitorViewModel _monitorViewModel;

    public ProjectStudioView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<ProjectStudioViewModel>();
        _monitorViewModel = App.Services.GetRequiredService<LiveMissionMonitorViewModel>();
        DataContext = ViewModel;

        Loaded += async (s, e) =>
        {
            if (ViewModel.AgentTemplates.Count == 0)
            {
                await ViewModel.LoadAsync();
            }
        };
    }

    private void NewProject_Click(object sender, RoutedEventArgs e) => ViewModel.BeginNewProject();

    private void AddStage_Click(object sender, RoutedEventArgs e) => ViewModel.AddStage();

    private void RemoveStage_Click(object sender, RoutedEventArgs e) => ViewModel.RemoveSelectedStage();

    private async void SaveProject_Click(object sender, RoutedEventArgs e) => await ViewModel.SaveProjectAsync();

    private async void LaunchProject_Click(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.TryBuildDraft(out var project, out var errorMessage) || project == null)
        {
            ViewModel.StatusMessage = errorMessage;
            return;
        }

        if (App.MainWindowInstance is MainWindow mainWindow)
        {
            mainWindow.NavigateTo(typeof(LiveMissionMonitorView));
            await _monitorViewModel.StartProjectAsync(project, ViewModel.GetLaunchParameters(), "Operator_ProjectLead");
        }
    }
}
