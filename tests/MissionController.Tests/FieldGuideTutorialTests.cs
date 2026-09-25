using System;
using System.IO;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Holds <c>docs/TUTORIAL.md</c> to <c>docs/SPLAT-Field-Guide.html</c>, so the plain-English guide has
/// one author and two renderings rather than two documents that agree by hand.
/// </summary>
public class FieldGuideTutorialTests
{
    private const string SyncEnvironmentVariable = "SPLAT_SYNC_TUTORIAL";

    /// <summary>
    /// The markdown copy is generated. Set <c>SPLAT_SYNC_TUTORIAL=1</c> to rewrite it instead of
    /// asserting it - the same bargain the test count strikes, for the same reason: a derived file a
    /// human has to reproduce by hand is a derived file that will eventually disagree.
    ///
    /// Before this, the census had to be bound in both copies, pattern by pattern, because a
    /// correction had landed in one and not the other; the live page told readers for weeks that
    /// Windows did "not filter network sockets" while both repository copies said otherwise. The
    /// census is now bound in the HTML alone, and this test is what makes that enough.
    /// </summary>
    [Fact]
    public void TheTutorial_IsTheFieldGuideAsMarkdown()
    {
        string root = RepositoryRoot();
        string tutorial = Path.Combine(root, "docs", "TUTORIAL.md");
        string expected = FieldGuideMarkdown.Convert(
            File.ReadAllText(Path.Combine(root, "docs", "SPLAT-Field-Guide.html")));

        if (Environment.GetEnvironmentVariable(SyncEnvironmentVariable) == "1")
        {
            File.WriteAllText(tutorial, expected);
            return;
        }

        // Compared with line endings normalised: this repository is checked out with core.autocrlf on,
        // so the same commit is CRLF in the shared tree and LF in a worktree.
        string actual = File.ReadAllText(tutorial).Replace("\r\n", "\n", StringComparison.Ordinal);

        Assert.True(
            actual == expected,
            "docs/TUTORIAL.md is not what docs/SPLAT-Field-Guide.html generates. Do not edit it by " +
            "hand - it is derived. Change the HTML, then re-derive it with:" + Environment.NewLine +
            $"    {SyncEnvironmentVariable}=1 dotnet test --filter TheTutorial_IsTheFieldGuideAsMarkdown");
    }

    /// <summary>
    /// The converter refuses what it does not understand. Without this, a new kind of block added to
    /// the page would be dropped from the markdown copy and nothing would say so - which is precisely
    /// the failure the derivation exists to prevent, arriving in a new shape.
    /// </summary>
    [Fact]
    public void AnElementTheConverterDoesNotKnow_FailsRatherThanDisappearing()
    {
        const string page = "<div class=\"wrap\"><section><p class=\"part\">Part 1 — x</p><h2>y</h2>" +
                            "<aside class=\"new\">something new</aside></section></div>";

        var ex = Assert.Throws<InvalidOperationException>(() => FieldGuideMarkdown.Convert(page));

        Assert.Contains("aside", ex.Message, StringComparison.Ordinal);
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
