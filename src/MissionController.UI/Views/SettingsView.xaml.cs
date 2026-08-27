using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class SettingsView : Page
{
    public SettingsViewModel ViewModel { get; }

    public SettingsView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SettingsViewModel>();
        DataContext = ViewModel;

        Loaded += async (s, e) =>
        {
            await ViewModel.CheckVaultStatusAsync();
        };
    }

    private async void RefreshVault_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.CheckVaultStatusAsync();
    }
}
