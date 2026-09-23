using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.UI.ViewModels;

public partial class ParameterInputItem : ObservableObject
{
    public string Key { get; }
    public string Label { get; }
    public string Description { get; }
    public bool IsRequired { get; }
    public bool IsMultiLine { get; }

    [ObservableProperty]
    private string _value = string.Empty;

    public ParameterInputItem(TemplateParameterField field)
    {
        Key = field.Key;
        Label = field.Label;
        Description = field.Description;
        IsRequired = field.IsRequired;
        IsMultiLine = field.IsMultiLine;
        Value = field.DefaultValue;
    }
}

public partial class TemplateCatalogViewModel : ObservableObject
{
    private readonly ITemplateRegistry _registry;

    [ObservableProperty]
    private ObservableCollection<SingleToolTemplate> _templates = new();

    [ObservableProperty]
    private SingleToolTemplate? _selectedTemplate;

    [ObservableProperty]
    private ObservableCollection<ParameterInputItem> _activeParameters = new();

    [ObservableProperty]
    private bool _isLoading;

    /// <summary>
    /// What the list shows: <see cref="Templates"/> narrowed by <see cref="SearchText"/>. Kept as a
    /// separate collection rather than filtering Templates in place, because Templates is also the
    /// source the custom-template builder picks its base from, and that list must never be narrowed
    /// by whatever the operator last typed into the search box.
    /// </summary>
    public ObservableCollection<SingleToolTemplate> FilteredTemplates { get; } = new();

    [ObservableProperty]
    private string _searchText = string.Empty;

    /// <summary>"12 of 51 templates" - raised by <see cref="ApplyFilter"/>, since neither Count notifies through x:Bind on its own.</summary>
    public string CountSummary => $"{FilteredTemplates.Count} of {Templates.Count} templates";

    public TemplateCatalogViewModel(ITemplateRegistry registry)
    {
        _registry = registry;
    }

    partial void OnSearchTextChanged(string value) => ApplyFilter();

    /// <summary>
    /// Case-insensitive match over the fields an operator actually thinks in: the name, the
    /// category, the description, the tool's name and the template id. Every word typed must match
    /// somewhere, so "defender endpoint" finds the Defender audit and "identity kerberos" narrows
    /// to one template instead of unioning two categories.
    /// </summary>
    public static bool Matches(SingleToolTemplate template, string searchText)
    {
        if (string.IsNullOrWhiteSpace(searchText))
            return true;

        string haystack = string.Join('\n',
            template.Name, template.Category, template.Description, template.Tool.Name, template.TemplateId);
        foreach (string word in searchText.Split(' ', System.StringSplitOptions.RemoveEmptyEntries))
        {
            if (!haystack.Contains(word, System.StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private void ApplyFilter()
    {
        FilteredTemplates.Clear();
        foreach (var template in Templates)
        {
            if (Matches(template, SearchText))
                FilteredTemplates.Add(template);
        }

        // A selection the filter just hid would leave the inspector showing a template that is not
        // in the list; move it to the first match so what is shown is always something clickable.
        if (SelectedTemplate is null || !FilteredTemplates.Contains(SelectedTemplate))
            SelectedTemplate = FilteredTemplates.FirstOrDefault();

        OnPropertyChanged(nameof(CountSummary));
    }

    partial void OnSelectedTemplateChanged(SingleToolTemplate? value)
    {
        ActiveParameters.Clear();
        if (value != null)
        {
            foreach (var field in value.ParameterFields)
            {
                ActiveParameters.Add(new ParameterInputItem(field));
            }
        }
    }

    public Dictionary<string, string> GetCurrentParameters()
    {
        var dict = new Dictionary<string, string>();
        foreach (var param in ActiveParameters)
        {
            dict[param.Key] = param.Value;
        }
        return dict;
    }

    public async Task<(bool Success, string Message)> CreateCustomTemplateAsync(
        string templateId,
        string name,
        string description,
        string category,
        string systemPrompt,
        TemplateKind kind,
        string objective,
        IEnumerable<string> deliverables,
        IEnumerable<string> successCriteria,
        SingleToolTemplate baseTemplate)
    {
        if (baseTemplate == null)
            return (false, "Choose a governed base agent first.");

        var normalizedId = NormalizeTemplateId(templateId);
        if (!normalizedId.StartsWith("custom-", System.StringComparison.Ordinal))
            normalizedId = $"custom-{normalizedId}";

        if (normalizedId == "custom-")
            return (false, "The template ID must contain letters or numbers.");

        if (await _registry.GetTemplateByIdAsync(normalizedId) != null)
            return (false, $"Template ID '{normalizedId}' already exists.");

        var outputContract = new TemplateOutputContract(
            objective.Trim(),
            CleanLines(deliverables),
            CleanLines(successCriteria));

        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(description) ||
            string.IsNullOrWhiteSpace(category) || string.IsNullOrWhiteSpace(systemPrompt) ||
            string.IsNullOrWhiteSpace(outputContract.Objective) ||
            outputContract.Deliverables.Count == 0 || outputContract.SuccessCriteria.Count == 0)
        {
            return (false, "Name, description, category, directive, objective, deliverables, and success criteria are required.");
        }

        var governedPrompt = BuildGovernedPrompt(systemPrompt, outputContract);
        var template = new SingleToolTemplate(
            normalizedId,
            name.Trim(),
            description.Trim(),
            category.Trim(),
            baseTemplate.TargetModel,
            baseTemplate.Tool,
            baseTemplate.EgressRule,
            governedPrompt,
            baseTemplate.ParameterFields,
            baseTemplate.GetEffectiveDefaults(),
            System.Array.Empty<RemediationAction>(),
            kind,
            outputContract,
            baseTemplate.TemplateId,
            true);

        try
        {
            template.ValidateStrictRules();
            await _registry.RegisterTemplateAsync(template);
            await LoadTemplatesAsync();
            SelectedTemplate = Templates.FirstOrDefault(item => item.TemplateId == normalizedId) ?? template;
            return (true, $"Saved governed agent template '{template.Name}'.");
        }
        catch (System.Exception ex)
        {
            return (false, ex.Message);
        }
    }

    [RelayCommand]
    public async System.Threading.Tasks.Task LoadTemplatesAsync()
    {
        IsLoading = true;
        try
        {
            var list = await _registry.GetAllTemplatesAsync();
            Templates.Clear();
            foreach (var t in list)
            {
                Templates.Add(t);
            }
            ApplyFilter();
        }
        finally
        {
            IsLoading = false;
        }
    }

    private static string NormalizeTemplateId(string value)
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

        return builder.ToString().Trim('-');
    }

    private static IReadOnlyList<string> CleanLines(IEnumerable<string> values) => values
        .SelectMany(value => value.Split(new[] { '\r', '\n' }, System.StringSplitOptions.RemoveEmptyEntries))
        .Select(value => value.Trim())
        .Where(value => value.Length > 0)
        .Distinct(System.StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static string BuildGovernedPrompt(string systemPrompt, TemplateOutputContract outputContract) =>
        $"{systemPrompt.Trim()}\n\n[OUTPUT CONTRACT]\nObjective: {outputContract.Objective}\n" +
        $"Deliverables: {string.Join("; ", outputContract.Deliverables)}\n" +
        $"Success criteria: {string.Join("; ", outputContract.SuccessCriteria)}\n" +
        "Use observed evidence, mark unknowns as unknown, and do not invent telemetry.";
}
