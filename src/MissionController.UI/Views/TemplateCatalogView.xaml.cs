using System;
using System.Linq;
using System.Threading.Tasks;
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
        => await ShowTemplateEditorAsync(null);

    /// <summary>
    /// Opens the same editor over an existing checkup the operator authored. Only their own: a
    /// catalog checkup is re-seeded from source at every launch, so an edit to one would be silently
    /// undone at the next restart, and the view model refuses it for that reason.
    /// </summary>
    private async void EditTemplate_Click(object sender, RoutedEventArgs e)
    {
        var selected = ViewModel.SelectedTemplate;
        if (selected is null)
        {
            return;
        }

        if (!selected.IsUserCreated)
        {
            var refusal = new ContentDialog
            {
                Title = "This checkup cannot be edited",
                Content = new TextBlock
                {
                    Text = $"'{selected.Name}' ships with SPLAT and is restored from source every time the app "
                         + "starts, so an edit here would disappear at the next launch. Use \"Create a checkup\" "
                         + "and pick it as the base: the copy runs the same command and destination, and its "
                         + "wording is yours to change.",
                    TextWrapping = TextWrapping.Wrap
                },
                CloseButtonText = "Close",
                XamlRoot = XamlRoot
            };
            await refusal.ShowAsync();
            return;
        }

        await ShowTemplateEditorAsync(selected);
    }

    private async Task ShowTemplateEditorAsync(SingleToolTemplate? existing)
    {
        if (ViewModel.Templates.Count == 0)
        {
            await ViewModel.LoadTemplatesAsync();
        }

        // Editing keeps the base it was derived from, and the picker is locked: changing the base of
        // an existing checkup would change the command it runs, which is the one thing this editor
        // does not do. DerivedTemplateGuard would refuse the result anyway.
        var baseForEdit = existing is null
            ? null
            : ViewModel.Templates.FirstOrDefault(t => t.TemplateId == existing.SourceTemplateId);

        var basePicker = new ComboBox
        {
            ItemsSource = baseForEdit is null ? ViewModel.Templates : new[] { baseForEdit },
            DisplayMemberPath = nameof(SingleToolTemplate.Name),
            SelectedItem = baseForEdit ?? ViewModel.SelectedTemplate ?? ViewModel.Templates[0],
            IsEnabled = existing is null,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        var kindPicker = new ComboBox
        {
            ItemsSource = new[] { TemplateKind.TaskAgent, TemplateKind.ProjectAgent },
            SelectedItem = existing?.Kind is TemplateKind.ProjectAgent
                ? TemplateKind.ProjectAgent
                : TemplateKind.TaskAgent,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };
        var idBox = new TextBox
        {
            Header = "Short ID (used in logs)",
            PlaceholderText = "custom-capacity-review",
            Text = existing?.TemplateId ?? string.Empty,
            // The id is the row's key. Editing it under an existing checkup would write a second
            // copy rather than change this one, so it is fixed once the checkup exists.
            IsEnabled = existing is null
        };
        var nameBox = new TextBox
        {
            Header = "Name shown in the list",
            PlaceholderText = "Capacity Review",
            Text = existing?.Name ?? string.Empty
        };
        var descriptionBox = new TextBox { Header = "One line describing what it checks", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, Text = existing?.Description ?? string.Empty };
        var categoryBox = new TextBox { Header = "Group it appears under", PlaceholderText = "Custom Operations", Text = existing?.Category ?? string.Empty };
        var directiveBox = new TextBox { Header = "What to tell the AI (its role and what to look for)", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, MinHeight = 90, Text = existing is null ? string.Empty : StripOutputContract(existing.SystemPrompt) };
        var objectiveBox = new TextBox { Header = "The question this checkup answers", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, Text = existing?.OutputContract?.Objective ?? string.Empty };
        var deliverablesBox = new TextBox { Header = "What the report must contain (one per line)", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, MinHeight = 70, Text = string.Join(Environment.NewLine, existing?.OutputContract?.Deliverables ?? Array.Empty<string>()) };
        var successCriteriaBox = new TextBox { Header = "How to tell the report is good (one per line)", TextWrapping = TextWrapping.Wrap, AcceptsReturn = true, MinHeight = 70, Text = string.Join(Environment.NewLine, existing?.OutputContract?.SuccessCriteria ?? Array.Empty<string>()) };

        var content = new ScrollViewer
        {
            MaxHeight = 620,
            Content = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new TextBlock
                    {
                        Text = existing is null
                            ? "A new checkup runs the base checkup's command, sandbox limits and destination, "
                              + "unchanged. What you write here is the wording: what the AI is told to look for, "
                              + "and what its report must contain."
                            : "You are editing the wording of a checkup you created. The command it runs, its "
                              + "sandbox limits and its destination stay exactly as they are and cannot be "
                              + "changed here.",
                        TextWrapping = TextWrapping.Wrap
                    },
                    new TextBlock { Text = "Based on this checkup" },
                    basePicker,
                    new TextBlock { Text = "Runs as" },
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
            Title = existing is null ? "Create a checkup" : $"Edit {existing.Name}",
            Content = content,
            PrimaryButtonText = existing is null ? "Create" : "Save changes",
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
            (SingleToolTemplate)basePicker.SelectedItem,
            replaceExisting: existing is not null);

        var resultDialog = new ContentDialog
        {
            Title = saveResult.Success ? "Saved" : "Not saved",
            Content = new TextBlock { Text = saveResult.Message, TextWrapping = TextWrapping.Wrap },
            CloseButtonText = "Close",
            XamlRoot = XamlRoot
        };
        await resultDialog.ShowAsync();
    }

    /// <summary>
    /// The operator's own directive, without the output contract the save appends to it.
    ///
    /// A saved prompt is "&lt;what the operator wrote&gt;\n\n[OUTPUT CONTRACT]\n...", assembled by
    /// <c>TemplateCatalogViewModel.BuildGovernedPrompt</c> from the objective, deliverables and
    /// success criteria - which have their own boxes in this editor. Prefilling the directive box
    /// with the whole prompt would put the contract back through the box that gets a fresh contract
    /// appended, so every edit would stack another copy of it.
    /// </summary>
    private static string StripOutputContract(string systemPrompt)
    {
        const string marker = "\n\n[OUTPUT CONTRACT]";
        int cut = systemPrompt.IndexOf(marker, StringComparison.Ordinal);
        return cut < 0 ? systemPrompt : systemPrompt[..cut];
    }
}
