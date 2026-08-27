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
    }

    private async void SweepButton_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SweepOrphanJailsAsync();
    }
}
