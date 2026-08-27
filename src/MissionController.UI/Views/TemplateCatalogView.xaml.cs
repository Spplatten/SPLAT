using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class TemplateCatalogView : Page
{
    public TemplateCatalogViewModel ViewModel { get; }
    private readonly LiveMissionMonitorViewModel _monitorViewModel;

    public TemplateCatalogView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<TemplateCatalogViewModel>();
        _monitorViewModel = App.Services.GetRequiredService<LiveMissionMonitorViewModel>();
        DataContext = ViewModel;

        Loaded += async (s, e) =>
        {
            if (ViewModel.Templates.Count == 0)
            {
                await ViewModel.LoadTemplatesAsync();
            }
        };
    }

    private void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Data binding handles selection
    }

    private async void LaunchTemplate_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.SelectedTemplate != null)
        {
            var parameters = ViewModel.GetCurrentParameters();

            // Navigate to monitor and start mission with user parameters
            if (App.MainWindowInstance is MainWindow mainWin)
            {
                mainWin.NavigateTo(typeof(LiveMissionMonitorView));
                await _monitorViewModel.StartMissionAsync(
                    ViewModel.SelectedTemplate,
                    parameters,
                    "Operator_SecOpsTier1");
            }
        }
    }
}
