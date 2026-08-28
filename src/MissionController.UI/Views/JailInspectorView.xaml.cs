using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class JailInspectorView : Page
{
    public JailInspectorViewModel ViewModel { get; }

    public JailInspectorView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<JailInspectorViewModel>();
        DataContext = ViewModel;
        this.Loaded += async (s, e) => await ViewModel.RefreshJailsAsync();
    }

    private async void SweepButton_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SweepOrphanJailsAsync();
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.RefreshJailsAsync();
    }
}
