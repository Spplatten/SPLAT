using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.UI.ViewModels;

namespace MissionController.UI.Views;

public sealed partial class TemplateCatalogView
{
    private async void BuildAgent_Click(object sender, RoutedEventArgs e)
    {
        var jsonBox = new TextBox
        {
            Text = AgentManifestCompiler.ExampleJson,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            MinHeight = 260,
            MaxLength = 131072,
            Header = "SPLAT agent manifest (JSON)"
        };
        var errorText = new TextBlock { TextWrapping = TextWrapping.Wrap };
        var content = new StackPanel { Spacing = 12 };
        content.Children.Add(new TextBlock
        {
            Text = "Define your agent's instructions and choose 1–6 approved tools. Each tool becomes a checkup; "
                 + "the agent runs them in order from Project Studio. Network access requires allowNetwork: true on the tool.",
            TextWrapping = TextWrapping.Wrap
        });
        content.Children.Add(jsonBox);
        content.Children.Add(errorText);
        content.Children.Add(new TextBlock
        {
            Text = "Available templateId values:\n" + string.Join("\n", GovernedTemplateCatalog.All
                .Where(t => t.Tool.Substrate == ToolSubstrate.LinuxLease)
                .Select(t => $"{t.TemplateId} — {t.Name}" + (t.EgressRule.ToolProcessNeedsNetwork ? " (network required)" : ""))),
            IsTextSelectionEnabled = true,
            TextWrapping = TextWrapping.Wrap
        });
        var editor = new ContentDialog
        {
            Title = "Build an agent from its tools",
            Content = new ScrollViewer { Content = content, MaxHeight = 580 },
            PrimaryButtonText = "Review agent",
            CloseButtonText = "Cancel",
            XamlRoot = XamlRoot
        };
        CompiledAgentManifest? compiled = null;
        editor.PrimaryButtonClick += (_, args) =>
        {
            try
            {
                compiled = AgentManifestCompiler.Compile(jsonBox.Text);
            }
            catch (InvalidOperationException ex)
            {
                // Keep the authored text in place when a capability cannot be honored.
                args.Cancel = true;
                errorText.Text = ex.Message;
            }
        };
        if (await editor.ShowAsync() != ContentDialogResult.Primary || compiled is null)
            return;

        var preview = new ContentDialog
        {
            Title = $"Review {compiled.Project.Name}",
            Content = new ScrollViewer
            {
                MaxHeight = 580,
                Content = new TextBlock
                {
                    Text = string.Join("\n\n", compiled.Templates.Select((t, i) =>
                        $"{i + 1}. {t.Name}\nBased on: {t.SourceTemplateId}\nModel: {t.TargetModel}\n"
                        + $"Runs: {t.Tool.ExecutablePath} {t.Tool.ArgumentsTemplate}\n"
                        + (t.EgressRule.ToolProcessNeedsNetwork
                            ? $"Tool network: {t.EgressRule.AllowedFqdn}:{t.EgressRule.AllowedPort}\n"
                            : "Tool network: no IPv4/IPv6 egress\n")
                        + $"Limits: {t.Tool.TimeoutSeconds}s, {t.Tool.MaxMemoryBytes / (1024 * 1024)} MiB, {t.Tool.MaxCpuPercent}% CPU"
                        + (t.Tool.ExecutionPolicy is { } policy
                            ? "\nAdditional file grants:\n" + string.Join("\n", policy.FileGrants.Select(g =>
                                $"  {g.Path}: {string.Join(", ", g.Access)} ({g.Scope})"))
                                + "\nAllowed syscalls: " + string.Join(", ", policy.Syscalls)
                            : "\nFiles: existing jail and protected-file deny-list")))
                        + "\n\nEach step requests its own Linux lease at launch; the daemon must be enforcing. "
                        + "An explicit execution policy additionally requires a supporting guest; unavailable grants refuse launch. "
                        + "Model requests use SPLAT's separate connection. Saving does not run the agent.",
                    IsTextSelectionEnabled = true,
                    TextWrapping = TextWrapping.Wrap
                }
            },
            PrimaryButtonText = "Save agent",
            CloseButtonText = "Cancel",
            XamlRoot = XamlRoot
        };
        if (await preview.ShowAsync() != ContentDialogResult.Primary)
            return;

        string message;
        bool saved = false;
        try
        {
            var imported = await App.Services.GetRequiredService<AgentManifestImporter>().ImportAsync(jsonBox.Text);
            saved = true;
            await ViewModel.LoadTemplatesAsync();
            ViewModel.SelectedTemplate = ViewModel.Templates.First(t => t.TemplateId == imported.Templates[0].TemplateId);
            // Project Studio is a singleton and may already have loaded its catalog before import.
            var studio = App.Services.GetRequiredService<ProjectStudioViewModel>();
            await studio.LoadAsync();
            studio.SelectedProject = studio.Projects.First(p => p.ProjectId == imported.Project.ProjectId);
            message = $"Saved '{imported.Project.Name}' with {imported.Templates.Count} checkups. Open Project Studio to review parameters and run it."
                + $"\n\nConnect an external agent using:\nsplat-mcp --agent {AgentManifestApproval.AgentIdOf(imported)} --agent-version {AgentManifestApproval.Hash(imported)}";
        }
        catch (Exception ex)
        {
            message = saved ? $"The agent was saved, but the view could not refresh: {ex.Message}" : ex.Message;
        }

        await new ContentDialog
        {
            Title = saved ? "Agent saved" : "Agent not saved",
            Content = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true },
            CloseButtonText = "Close",
            XamlRoot = XamlRoot
        }.ShowAsync();
    }
}
