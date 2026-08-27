using System.Collections.ObjectModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;

namespace MissionController.UI.ViewModels;

public partial class SemanticSearchViewModel : ObservableObject
{
    private readonly ISemanticMemoryIndex _memoryIndex;

    [ObservableProperty]
    private string _searchQuery = string.Empty;

    [ObservableProperty]
    private ObservableCollection<SemanticSearchResult> _searchResults = new();

    [ObservableProperty]
    private bool _isSearching;

    [ObservableProperty]
    private string _searchSummary = "Enter keywords or natural language questions to search past mission diagnostic logs.";

    public SemanticSearchViewModel(ISemanticMemoryIndex memoryIndex)
    {
        _memoryIndex = memoryIndex;
    }

    [RelayCommand]
    public async Task PerformSearchAsync()
    {
        if (string.IsNullOrWhiteSpace(SearchQuery))
            return;

        IsSearching = true;
        try
        {
            var results = await _memoryIndex.SearchSimilarMissionsAsync(SearchQuery, topK: 10, minScore: 0.05);
            SearchResults.Clear();
            foreach (var r in results)
            {
                SearchResults.Add(r);
            }
            SearchSummary = $"Found {results.Count} matching past mission artifacts (Ranked by Cosine Similarity).";
        }
        finally
        {
            IsSearching = false;
        }
    }
}
