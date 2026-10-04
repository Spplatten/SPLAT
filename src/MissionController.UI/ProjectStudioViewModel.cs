using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.UI.ViewModels;

public partial class ProjectStageDraftItem : ObservableObject
{
    public string StageId { get; }
    public string StageLabel { get; }
    public SingleToolTemplate AgentTemplate { get; }

    [ObservableProperty]
    private string _directive;

    [ObservableProperty]
    private bool _continueOnFailure;

    public ProjectStageDraftItem(string stageId, string stageLabel, SingleToolTemplate agentTemplate, string directive)
    {
        StageId = stageId;
        StageLabel = stageLabel;
        AgentTemplate = agentTemplate;
        _directive = directive;
    }

    public ProjectStage ToStage() => new(StageId, StageLabel, AgentTemplate.TemplateId, Directive, ContinueOnFailure);
}

public partial class ProjectStudioViewModel : ObservableObject
{
    private readonly ITemplateRegistry _templateRegistry;
    private readonly IProjectTemplateRegistry _projectRegistry;
    private readonly IModelStreamClient? _modelClient;

    [ObservableProperty]
    private ObservableCollection<SingleToolTemplate> _agentTemplates = new();

    [ObservableProperty]
    private ObservableCollection<ProjectTemplate> _projects = new();

    [ObservableProperty]
    private ObservableCollection<ProjectStageDraftItem> _draftStages = new();

    [ObservableProperty]
    private SingleToolTemplate? _selectedAgentTemplate;

    [ObservableProperty]
    private ProjectStageDraftItem? _selectedStage;

    [ObservableProperty]
    private ProjectTemplate? _selectedProject;

    [ObservableProperty]
    private string _projectId = "project-custom-new";

    [ObservableProperty]
    private string _projectName = "New Governed Project";

    [ObservableProperty]
    private string _projectDescription = string.Empty;

    [ObservableProperty]
    private string _projectCategory = "Custom Projects";

    [ObservableProperty]
    private string _projectGoal = string.Empty;

    [ObservableProperty]
    private string _deliverablesText = string.Empty;

    [ObservableProperty]
    private string _stageDirective = string.Empty;

    [ObservableProperty]
    private bool _continueOnFailure;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _naturalLanguagePrompt = string.Empty;

    [ObservableProperty]
    private string _synthesizedWorkflowSummary = string.Empty;

    [ObservableProperty]
    private bool _isSynthesizing;

    [ObservableProperty]
    private string _webhookUrl = "http://127.0.0.1:5678/webhook/custom-flow";

    [ObservableProperty]
    private string _oauthCallbackUrl = "http://127.0.0.1:5678/oauth/callback/tiktok";

    public ProjectStudioViewModel(
        ITemplateRegistry templateRegistry,
        IProjectTemplateRegistry projectRegistry,
        IModelStreamClient? modelClient = null)
    {
        _templateRegistry = templateRegistry;
        _projectRegistry = projectRegistry;
        _modelClient = modelClient;
    }

    partial void OnSelectedProjectChanged(ProjectTemplate? value)
    {
        if (value != null)
        {
            LoadProjectIntoDraft(value);
        }
    }

    public Dictionary<string, string> GetLaunchParameters() =>
        string.IsNullOrWhiteSpace(ProjectGoal)
            ? new Dictionary<string, string>()
            : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["ProjectGoal"] = ProjectGoal.Trim()
            };

    public void BeginNewProject()
    {
        SelectedProject = null;
        ProjectId = "project-custom-new";
        ProjectName = "New Governed Project";
        ProjectDescription = string.Empty;
        ProjectCategory = "Custom Projects";
        ProjectGoal = string.Empty;
        DeliverablesText = string.Empty;
        StageDirective = string.Empty;
        ContinueOnFailure = false;
        DraftStages.Clear();
        SelectedStage = null;
        StatusMessage = "Draft cleared. Add ordered agent stages to define the project.";
    }

    [RelayCommand]
    public async Task SynthesizeWorkflowAsync()
    {
        if (string.IsNullOrWhiteSpace(NaturalLanguagePrompt))
        {
            StatusMessage = "Enter a description of what you want your agent or workflow to do.";
            return;
        }

        IsSynthesizing = true;
        StatusMessage = "Compiling your request into governed stages...";
        try
        {
            // The catalogue this page already loaded is the grounding context: the compiler may only
            // name templates the operator can actually see in the picker beside it. It is handed the
            // model client too - until 2026-09-25 the synthesiser took one and never called it, and
            // matched keywords instead, so a request it did not recognise produced a plan about
            // something else entirely and said "Successfully synthesized".
            var synthesizer = new MissionController.Core.Workflow.WorkflowSynthesizerEngine(
                _modelClient, AgentTemplates.ToList());
            var project = await synthesizer.SynthesizeProjectAsync(NaturalLanguagePrompt);

            ProjectId = project.ProjectId;
            ProjectName = project.Name;
            ProjectDescription = project.Description;
            ProjectCategory = project.Category;
            WebhookUrl = $"http://127.0.0.1:5678/webhook/{project.ProjectId}";

            DraftStages.Clear();
            foreach (var stage in project.Stages)
            {
                // The compiler refuses a plan naming a template the catalogue lacks, so this lookup
                // succeeds - but the draft is what the operator then runs, and a null here would put
                // a stage on screen with no agent behind it.
                var template = AgentTemplates.FirstOrDefault(t =>
                    string.Equals(t.TemplateId, stage.TemplateId, StringComparison.OrdinalIgnoreCase));
                if (template is null)
                {
                    throw new InvalidOperationException(
                        $"Stage '{stage.StageId}' names template '{stage.TemplateId}', which this page has not loaded.");
                }

                DraftStages.Add(new ProjectStageDraftItem(stage.StageId, stage.Name, template, stage.Directive)
                {
                    ContinueOnFailure = stage.ContinueOnFailure,
                });
            }

            SelectedStage = DraftStages.LastOrDefault();
            DeliverablesText = string.Join(Environment.NewLine, project.Deliverables);
            int carryOn = project.Stages.Count(stage => stage.ContinueOnFailure);
            SynthesizedWorkflowSummary = carryOn == 0
                ? $"{project.Name} ({project.Stages.Count} stages)"
                : $"{project.Name} ({project.Stages.Count} stages, {carryOn} set to continue on failure)";
            StatusMessage = $"Compiled '{project.Name}' into {project.Stages.Count} governed stages. Review each directive before saving.";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Synthesis error: {ex.Message}";
        }
        finally
        {
            IsSynthesizing = false;
        }
    }

    public void AddStage()
    {
        if (SelectedAgentTemplate == null)
        {
            StatusMessage = "Choose a governed agent template before adding a stage.";
            return;
        }

        var directive = string.IsNullOrWhiteSpace(StageDirective)
            ? $"Collect the evidence relevant to this project and report only observed facts from the {SelectedAgentTemplate.Name} sensor."
            : StageDirective.Trim();
        var stageNumber = DraftStages.Count + 1;
        var stageId = $"stage-{stageNumber}";
        while (DraftStages.Any(stage => string.Equals(stage.StageId, stageId, StringComparison.OrdinalIgnoreCase)))
        {
            stageNumber++;
            stageId = $"stage-{stageNumber}";
        }

        var stage = new ProjectStageDraftItem(
            stageId,
            $"Stage {stageNumber}: {SelectedAgentTemplate.Name}",
            SelectedAgentTemplate,
            directive)
        {
            ContinueOnFailure = ContinueOnFailure
        };

        DraftStages.Add(stage);
        SelectedStage = stage;
        StageDirective = string.Empty;
        ContinueOnFailure = false;
        StatusMessage = $"Added {stage.StageLabel}. The project remains a finite ordered playbook.";
    }

    public void RemoveSelectedStage()
    {
        if (SelectedStage == null)
        {
            return;
        }

        DraftStages.Remove(SelectedStage);
        SelectedStage = DraftStages.LastOrDefault();
        StatusMessage = "Stage removed from the project draft.";
    }

    public bool TryBuildDraft(out ProjectTemplate? project, out string errorMessage)
    {
        project = null;
        errorMessage = string.Empty;

        var normalizedId = NormalizeProjectId(ProjectId);
        var stages = DraftStages.Select(stage => stage.ToStage()).ToArray();
        var deliverables = CleanLines(DeliverablesText);

        var candidate = new ProjectTemplate(
            normalizedId,
            ProjectName.Trim(),
            ProjectDescription.Trim(),
            ProjectCategory.Trim(),
            stages,
            deliverables,
            false);

        try
        {
            candidate.Validate();
            project = candidate;
            return true;
        }
        catch (Exception ex)
        {
            errorMessage = ex.Message;
            return false;
        }
    }

    public async Task<bool> SaveProjectAsync()
    {
        if (!TryBuildDraft(out var project, out var errorMessage) || project == null)
        {
            StatusMessage = errorMessage;
            return false;
        }

        if (!project.ProjectId.StartsWith("project-custom-", StringComparison.Ordinal))
        {
            StatusMessage = "Custom projects must use the project-custom- ID prefix.";
            return false;
        }

        if (Projects.Any(existing => string.Equals(existing.ProjectId, project.ProjectId, StringComparison.OrdinalIgnoreCase) && existing.IsBuiltIn))
        {
            StatusMessage = "Built-in projects are immutable. Save this playbook under a new project-custom- ID.";
            return false;
        }

        try
        {
            await _projectRegistry.RegisterProjectTemplateAsync(project);
            await LoadAsync();
            SelectedProject = Projects.FirstOrDefault(item => string.Equals(item.ProjectId, project.ProjectId, StringComparison.OrdinalIgnoreCase));
            StatusMessage = $"Saved project '{project.Name}' with {project.Stages.Count} ordered stages.";
            return true;
        }
        catch (Exception ex)
        {
            StatusMessage = ex.Message;
            return false;
        }
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        IsLoading = true;
        try
        {
            var templates = await _templateRegistry.GetAllTemplatesAsync();
            AgentTemplates.Clear();
            foreach (var template in templates)
            {
                AgentTemplates.Add(template);
            }

            var projects = await _projectRegistry.GetAllProjectTemplatesAsync();
            Projects.Clear();
            foreach (var project in projects)
            {
                Projects.Add(project);
            }

            if (SelectedAgentTemplate == null && AgentTemplates.Count > 0)
            {
                SelectedAgentTemplate = AgentTemplates[0];
            }

            // No project is selected for the operator. Selecting one calls LoadProjectIntoDraft,
            // so auto-selecting the first saved playbook opened the page with the definition
            // fields already full of a read-only built-in's text - which reads as a draft the
            // operator started and did not. The stage picker above is different: it is a choice
            // within a draft, not the draft itself, so it keeps its default.
        }
        finally
        {
            IsLoading = false;
        }
    }

    private void LoadProjectIntoDraft(ProjectTemplate project)
    {
        ProjectId = project.ProjectId;
        ProjectName = project.Name;
        ProjectDescription = project.Description;
        ProjectCategory = project.Category;
        DeliverablesText = string.Join(Environment.NewLine, project.Deliverables);
        DraftStages.Clear();

        foreach (var stage in project.Stages)
        {
            var template = AgentTemplates.FirstOrDefault(item =>
                string.Equals(item.TemplateId, stage.TemplateId, StringComparison.OrdinalIgnoreCase));
            if (template != null)
            {
                DraftStages.Add(new ProjectStageDraftItem(stage.StageId, stage.Name, template, stage.Directive)
                {
                    ContinueOnFailure = stage.ContinueOnFailure
                });
            }
        }

        SelectedStage = DraftStages.LastOrDefault();
        StatusMessage = project.IsBuiltIn
            ? "Built-in project loaded. Save a copy with a project-custom- ID to edit it."
            : "Project loaded for editing.";
    }

    private static string NormalizeProjectId(string value)
    {
        var builder = new StringBuilder();
        var separatorPending = false;

        foreach (var character in value.Trim().ToLowerInvariant())
        {
            if (character is >= 'a' and <= 'z' or >= '0' and <= '9')
            {
                if (separatorPending && builder.Length > 0)
                    builder.Append('-');
                builder.Append(character);
                separatorPending = false;
            }
            else
            {
                separatorPending = true;
            }
        }

        var normalized = builder.ToString().Trim('-');
        return normalized.StartsWith("project-", StringComparison.Ordinal)
            ? normalized
            : $"project-{normalized}";
    }

    private static IReadOnlyList<string> CleanLines(string value) => value
        .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
        .Select(item => item.Trim())
        .Where(item => item.Length > 0)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
}
