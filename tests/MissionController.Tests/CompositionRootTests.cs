using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The orchestration engine spent its whole life unregistered: constructed by its own tests, by
/// nothing else. Every containment guarantee it grew was therefore a guarantee no shipped code
/// path could reach, and the suite stayed green the entire time because a test composes the engine
/// itself.
///
/// These read the composition root as SOURCE because the test project cannot reference the WinUI
/// app - the same technique DocumentationDriftTests uses to bind prose to code. A source assertion
/// is weaker than resolving the container, and it is the strongest thing available from here; what
/// it does catch is the regression that actually happened, which is a registration silently absent.
/// </summary>
public class CompositionRootTests
{
    private static string UiProjectDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return Path.Combine(dir!.FullName, "src", "MissionController.UI");
    }

    private static string CompositionRootText()
    {
        string path = Path.Combine(UiProjectDirectory(), "App.xaml.cs");
        Assert.True(File.Exists(path), $"composition root not found at {path}");
        return File.ReadAllText(path);
    }

    private static readonly TimeSpan RegexBudget = TimeSpan.FromSeconds(1);

    /// <summary>
    /// The self-test opens the pages named in <c>MainWindow.EveryPage</c>, and only those, so a page
    /// the navigation offers that the list forgot is the one failure the self-test cannot see - the
    /// comment on the list says as much. This holds the three places a page is named to each other:
    /// every view under <c>Views/</c> is in the list, every menu tag in <c>MainWindow.xaml</c> maps to
    /// a view that is in the list, and the list names nothing that is not a view. Source-level, for
    /// the reason the class summary gives.
    /// </summary>
    [Fact]
    public void TheSelfTest_OpensEveryPageTheConsoleHas()
    {
        string ui = UiProjectDirectory();
        string window = File.ReadAllText(Path.Combine(ui, "MainWindow.xaml.cs"));
        string menu = File.ReadAllText(Path.Combine(ui, "MainWindow.xaml"));

        var views = Directory.EnumerateFiles(Path.Combine(ui, "Views"), "*.xaml.cs")
            .Select(File.ReadAllText)
            .Select(text => Regex.Match(text, @"partial class (?<name>\w+)\s*:\s*Page\b", RegexOptions.None, RegexBudget))
            .Where(match => match.Success)
            .Select(match => match.Groups["name"].Value)
            .ToHashSet(StringComparer.Ordinal);
        Assert.NotEmpty(views);

        var listBlock = Regex.Match(window, @"EveryPage\s*=\s*\{(?<body>[^}]*)\}", RegexOptions.None, RegexBudget);
        Assert.True(listBlock.Success, "MainWindow.EveryPage is gone, so the self-test has nothing to open");
        var listed = Regex.Matches(listBlock.Groups["body"].Value, @"typeof\((?<name>\w+)\)", RegexOptions.None, RegexBudget)
            .Select(match => match.Groups["name"].Value)
            .ToList();

        var menuTags = Regex.Matches(menu, @"<NavigationViewItem\b[^>]*\bTag=""(?<tag>[^""]+)""", RegexOptions.None, RegexBudget)
            .Select(match => match.Groups["tag"].Value)
            .ToList();
        Assert.NotEmpty(menuTags);

        var tagToView = Regex.Matches(window, @"typeof\((?<view>\w+)\)\)\s*return\s*""(?<tag>[^""]+)"";", RegexOptions.None, RegexBudget)
            .ToDictionary(match => match.Groups["tag"].Value, match => match.Groups["view"].Value, StringComparer.Ordinal);

        var unmappedTags = menuTags.Where(tag => !tagToView.ContainsKey(tag)).ToList();
        Assert.True(unmappedTags.Count == 0,
            $"menu items whose tag no page is mapped to in GetTagForPage: {string.Join(", ", unmappedTags)}");

        var missing = views.Where(view => !listed.Contains(view, StringComparer.Ordinal)).OrderBy(v => v, StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0,
            $"pages under Views/ that the self-test never opens: {string.Join(", ", missing)}; add them to MainWindow.EveryPage");

        var unknown = listed.Where(name => !views.Contains(name)).ToList();
        Assert.True(unknown.Count == 0,
            $"MainWindow.EveryPage names something that is not a page under Views/: {string.Join(", ", unknown)}");

        Assert.Equal(listed.Count, listed.Distinct(StringComparer.Ordinal).Count());
        Assert.Contains("SettingsView", listed);
        Assert.Contains("IsSettingsVisible=\"True\"", menu);
    }

    [Fact]
    public void TheWorkflowEngine_IsRegisteredInTheContainer()
    {
        Assert.Matches(
            new Regex(@"AddSingleton<IWorkflowExecutionEngine>", RegexOptions.None, TimeSpan.FromSeconds(1)),
            CompositionRootText());
    }

    [Fact]
    public void TheWorkflowEngine_IsGivenTheRealMissionEngineAndCatalogue()
    {
        // Without both of these a GovernedMission node refuses at run time - the engine resolves,
        // the app starts, and every workflow fails on its first step. Registering it half-wired
        // would look exactly like working software until someone ran something.
        string source = CompositionRootText();

        Assert.Contains("missionEngine: sp.GetRequiredService<IMissionExecutionEngine>()", source);
        Assert.Contains("templateRegistry: sp.GetRequiredService<ITemplateRegistry>()", source);
    }
}
