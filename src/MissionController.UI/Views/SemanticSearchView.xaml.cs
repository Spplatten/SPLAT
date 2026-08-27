using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class SemanticSearchView : Page
{
    public SemanticSearchViewModel ViewModel { get; }

    public SemanticSearchView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<SemanticSearchViewModel>();
        DataContext = ViewModel;
    }

    private async void SearchTextBox_KeyDown(object sender, KeyRoutedEventArgs e)
    {
        if (e.Key == Windows.System.VirtualKey.Enter)
        {
            await ViewModel.PerformSearchAsync();
        }
    }
}
