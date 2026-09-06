using System;
using System.IO;
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
    private static string CompositionRootText()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        string path = Path.Combine(dir!.FullName, "src", "MissionController.UI", "App.xaml.cs");
        Assert.True(File.Exists(path), $"composition root not found at {path}");
        return File.ReadAllText(path);
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
