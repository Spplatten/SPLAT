using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.Core.Enums;
using MissionController.Core.Models;
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
                await _monitorViewModel.StartMissionAsync(ViewModel.SelectedTemplate, parameters);
            }
        }
    }

    private async void CreateTemplate_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.Templates.Count == 0)
        {
            await ViewModel.LoadTemplatesAsync();
        }

        var basePicker = new ComboBox
        {
            ItemsSource = ViewModel.Templates,
            DisplayMemberPath = nameof(SingleToolTemplate.Name),
            SelectedItem = ViewModel.SelectedTemplate ?? ViewModel.Templates[0],
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        var kindPicker = new ComboBox
        {
            ItemsSource = new[] { TemplateKind.TaskAgent, TemplateKind.ProjectAgent },
            SelectedItem = TemplateKind.TaskAgent,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        var idBox = new TextBox { Header = "Template ID", PlaceholderText = "custom-capacity-review" };
        var nameBox = new TextBox { Header = "Agent name", PlaceholderText = "Capacity Review Agent" };
        var descriptionBox = new TextBox { Header = "Description", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true };
        var categoryBox = new TextBox { Header = "Category", PlaceholderText = "Custom Operations" };
        var directiveBox = new TextBox { Header = "Agent directive", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, MinHeight = 90 };
        var objectiveBox = new TextBox { Header = "Objective", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true };
        var deliverablesBox = new TextBox { Header = "Deliverables (one per line)", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, MinHeight = 70 };
        var successCriteriaBox = new TextBox { Header = "Success criteria (one per line)", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, MinHeight = 70 };

        var content = new ScrollViewer
        {
            MaxHeight = 620,
            Content = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new TextBlock { Text = "New templates inherit the selected sensor, sandbox limits, and approved egress. Only the agent role and output contract are authored here.", TextWrapping = TextWrapping.Wrap },
                    new TextBlock { Text = "Governed base agent" },
                    basePicker,
                    new TextBlock { Text = "Agent level" },
                    kindPicker,
                    idBox,
                    nameBox,
                    descriptionBox,
                    categoryBox,
                    directiveBox,
                    objectiveBox,
                    deliverablesBox,
                    successCriteriaBox
                }
            }
        };

        var dialog = new ContentDialog
        {
            Title = "Build a Governed Agent Template",
            Content = content,
            PrimaryButtonText = "Save Template",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            XamlRoot = XamlRoot
        };

        if (await dialog.ShowAsync() != ContentDialogResult.Primary)
        {
            return;
        }

        var saveResult = await ViewModel.CreateCustomTemplateAsync(
            idBox.Text,
            nameBox.Text,
            descriptionBox.Text,
            categoryBox.Text,
            directiveBox.Text,
            (TemplateKind)kindPicker.SelectedItem,
            objectiveBox.Text,
            new[] { deliverablesBox.Text },
            new[] { successCriteriaBox.Text },
            (SingleToolTemplate)basePicker.SelectedItem);

        var resultDialog = new ContentDialog
        {
            Title = saveResult.Success ? "Template Saved" : "Template Not Saved",
            Content = new TextBlock { Text = saveResult.Message, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = "Close",
            XamlRoot = XamlRoot
        };
        await resultDialog.ShowAsync();
    }
}
