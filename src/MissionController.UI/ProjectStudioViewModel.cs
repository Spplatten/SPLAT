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
        IProjectTemplateRegistry projectRegistry)
    {
        _templateRegistry = templateRegistry;
        _projectRegistry = projectRegistry;
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
        StatusMessage = "Synthesizing governed workflow with AI & vetted primitives...";
        try
        {
            var synthesizer = new MissionController.Core.Workflow.WorkflowSynthesizerEngine();
            var graph = await synthesizer.SynthesizeFromNaturalLanguageAsync(NaturalLanguagePrompt);

            ProjectId = $"project-custom-{graph.WorkflowId.Replace("flow-", "")}";
            ProjectName = graph.Name;
            ProjectDescription = graph.Description;
            ProjectCategory = "Synthesized Workflows";
            WebhookUrl = $"http://127.0.0.1:5678/webhook/{graph.WorkflowId}";

            DraftStages.Clear();
            int stageNum = 1;
            foreach (var node in graph.Nodes.Where(n => n.NodeType != MissionController.Core.Workflow.WorkflowNodeType.Trigger))
            {
                var matchingTemplate = AgentTemplates.FirstOrDefault(t =>
                    t.TargetModel.Contains("claude", StringComparison.OrdinalIgnoreCase)) ?? AgentTemplates.FirstOrDefault();

                if (matchingTemplate != null)
                {
                    string directive = node.NodeType switch
                    {
                        MissionController.Core.Workflow.WorkflowNodeType.OAuthExchange => $"[OAuth Exchange] Intercept and securely deposit token for {node.Configuration.GetValueOrDefault("Provider", "Provider")} into Windows DPAPI vault.",
                        MissionController.Core.Workflow.WorkflowNodeType.SandboxedScript => $"[Sandboxed Script ({node.Configuration.GetValueOrDefault("Runtime", "PowerShell")})] {node.ScriptCommand}",
                        MissionController.Core.Workflow.WorkflowNodeType.Condition => $"[Condition Gate] Evaluate trigger data for: {node.Configuration.GetValueOrDefault("Matches", "Pattern")}",
                        MissionController.Core.Workflow.WorkflowNodeType.ReActAgent => $"[Governed ReAct Agent] Goal: {node.Configuration.GetValueOrDefault("Goal", "Investigate")} | Tools: {node.Configuration.GetValueOrDefault("AllowedTools", "DiagnosticSuite")} | MaxSteps: {node.Configuration.GetValueOrDefault("MaxSteps", "4")}",
                        MissionController.Core.Workflow.WorkflowNodeType.MemoryRecall => $"[Semantic Memory Recall] Query: {node.Configuration.GetValueOrDefault("Query", "HistoricalIncidents")} | TopK: {node.Configuration.GetValueOrDefault("TopK", "3")}",
                        MissionController.Core.Workflow.WorkflowNodeType.MemoryStore => $"[Semantic Memory Store] Key: {node.Configuration.GetValueOrDefault("Key", "KnowledgeEntry")}",
                        MissionController.Core.Workflow.WorkflowNodeType.TransactionalScope => $"[Transactional Scope] Assertion: '{node.Configuration.GetValueOrDefault("Assertion", "SUCCESS")}' with automated rollback fallback.",
                        _ => node.Configuration.GetValueOrDefault("Prompt", $"Execute governed {node.Name} task.")
                    };

                    DraftStages.Add(new ProjectStageDraftItem(
                        $"stage-{stageNum}",
                        $"Stage {stageNum}: {node.Name}",
                        matchingTemplate,
                        directive));
                    stageNum++;
                }
            }

            SelectedStage = DraftStages.LastOrDefault();
            DeliverablesText = $"1. Complete sandboxed execution of {graph.Name}\n2. Notarize execution in SHA-256 chained audit ledger";
            SynthesizedWorkflowSummary = $"{graph.Name} ({graph.Nodes.Count} nodes, trigger: {graph.Trigger.Type})";
            StatusMessage = $"Successfully synthesized governed workflow '{graph.Name}' ({graph.Nodes.Count} nodes).";
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

            if (SelectedProject == null && Projects.Count > 0)
            {
                SelectedProject = Projects[0];
            }
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
