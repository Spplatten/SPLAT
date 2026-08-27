using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.Core.Interfaces;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class LiveMissionMonitorView : Page
{
    public LiveMissionMonitorViewModel ViewModel { get; }
    private readonly ITemplateRegistry _templateRegistry;

    public LiveMissionMonitorView()
    {
        InitializeComponent();
        ViewModel = App.Services.GetRequiredService<LiveMissionMonitorViewModel>();
        _templateRegistry = App.Services.GetRequiredService<ITemplateRegistry>();
        DataContext = ViewModel;
    }

    private async void QuickRunButton_Click(object sender, RoutedEventArgs e)
    {
        var template = await _templateRegistry.GetTemplateByIdAsync("net-dns-audit");
        if (template != null)
        {
            await ViewModel.StartMissionAsync(template, new Dictionary<string, string>(), "Operator_SecOpsTier1");
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        ViewModel.CancelMission();
    }
}
