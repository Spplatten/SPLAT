using System.Text.RegularExpressions;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Every StaticResource / ThemeResource key a view names must exist somewhere the runtime will
/// look, or the page dies in InitializeComponent with "Cannot find a Resource with the Name/Key"
/// the first time someone clicks its navigation item. The XAML compiler does not check this,
/// and the build was green on 2026-09-23 while two of the nine views (Sandbox Inspector,
/// Cryptographic Audit) could not open at all: one named a button style that had been renamed,
/// one a brush that was never defined. A resource key is a contract between a view and the
/// design tokens, and this is the test that holds it.
/// </summary>
public sealed class XamlResourceKeyTests
{
    /// <summary>
    /// Keys WinUI itself defines (generic.xaml and the theme resources). Listed rather than
    /// discovered, because the platform dictionary is not on disk in this repository. A new
    /// platform key a view legitimately uses is added here, with the view that needs it.
    /// </summary>
    private static readonly HashSet<string> PlatformKeys = new(StringComparer.Ordinal)
    {
        "AccentButtonStyle",
        "ApplicationPageBackgroundThemeBrush",
        "CardBackgroundFillColorDefaultBrush",
        "LayerFillColorDefaultBrush",
        "TextFillColorSecondaryBrush",
        "TextFillColorTertiaryBrush",
    };

    private static readonly Regex Reference = new(
        @"\{(?:StaticResource|ThemeResource)\s+(?<key>[A-Za-z0-9_]+)\s*\}", RegexOptions.Compiled);

    private static readonly Regex Definition = new(
        @"x:(?:Key|Name)=""(?<key>[A-Za-z0-9_]+)""", RegexOptions.Compiled);

    [Fact]
    public void Every_resource_key_a_view_references_is_defined()
    {
        string ui = Path.Combine(RepositoryRoot(), "src", "MissionController.UI");
        var xaml = Directory.EnumerateFiles(ui, "*.xaml", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                     && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"))
            .ToList();
        Assert.NotEmpty(xaml);

        // Defined anywhere in the project: App.xaml, the token dictionary, or a page's own
        // resources. Page-local scope is deliberately ignored - a key defined in one page and
        // used in another would still fail at runtime, but that pattern does not occur here and
        // the check that matters is "defined nowhere", which is the one that shipped.
        var defined = new HashSet<string>(StringComparer.Ordinal);
        foreach (string file in xaml)
        {
            foreach (Match m in Definition.Matches(File.ReadAllText(file)))
            {
                defined.Add(m.Groups["key"].Value);
            }
        }

        var missing = new List<string>();
        foreach (string file in xaml)
        {
            string text = File.ReadAllText(file);
            foreach (Match m in Reference.Matches(text))
            {
                string key = m.Groups["key"].Value;
                if (!defined.Contains(key) && !PlatformKeys.Contains(key))
                {
                    int line = text[..m.Index].Count(c => c == '\n') + 1;
                    missing.Add($"{Path.GetRelativePath(ui, file)}:{line} references '{key}'");
                }
            }
        }

        Assert.True(missing.Count == 0,
            "These resource keys are referenced but defined nowhere in MissionController.UI, so the page "
            + "that uses them throws XamlParseException the moment it is navigated to:\n  "
            + string.Join("\n  ", missing));
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
