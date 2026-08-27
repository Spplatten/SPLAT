using System.Collections.Generic;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
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

    public TemplateCatalogViewModel(ITemplateRegistry registry)
    {
        _registry = registry;
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
            if (Templates.Count > 0 && SelectedTemplate == null)
            {
                SelectedTemplate = Templates[0];
            }
        }
        finally
        {
            IsLoading = false;
        }
    }
}
