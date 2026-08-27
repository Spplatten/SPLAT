using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml.Controls;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class QuickDiagnosticianView : Page
{
    public QuickDiagnosticianViewModel ViewModel { get; }

    public QuickDiagnosticianView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<QuickDiagnosticianViewModel>();
        DataContext = ViewModel;
    }

    private async void Tile_ItemClick(object sender, ItemClickEventArgs e)
    {
        if (e.ClickedItem is FriendlyDiagnosticTile tile)
        {
            await ViewModel.RunTileDiagnosticAsync(tile);
        }
    }
}
