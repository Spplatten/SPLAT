using System;
using System.IO;
using System.Linq;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// MVVMTK0045 is suppressed in the UI project because it warns about WinRT AOT compatibility, and
/// this application is never published AOT or trimmed. That is a conditional justification, and a
/// conditional justification with nothing watching it is how a reasonable suppression becomes a
/// silent one - the same failure mode the documentation drift tests exist to prevent.
///
/// So the precondition is asserted rather than trusted: enable AOT or trimming and this fails,
/// forcing whoever does it to migrate the ViewModels to partial properties instead of inheriting a
/// suppression whose reason has expired.
/// </summary>
public class UiWarningSuppressionTests
{
    private const string SuppressedCode = "MVVMTK0045";

    private static string UiProjectText()
    {
        string path = Path.Combine(RepositoryRoot(), "src", "MissionController.UI", "MissionController.UI.csproj");
        Assert.True(File.Exists(path), $"UI project not found at {path}");
        return File.ReadAllText(path);
    }

    [Fact]
    public void TheAotWarningSuppression_IsOnlyValidWhileNothingIsPublishedAot()
    {
        string project = UiProjectText();
        if (!project.Contains(SuppressedCode, StringComparison.OrdinalIgnoreCase))
        {
            // Migrated or otherwise fixed. Nothing left to guard.
            return;
        }

        // Matches the enabling form only. <PublishAot>false</PublishAot> is an explicit opt-out and
        // must not trip a guard whose whole point is that AOT is off.
        var enabled = new[] { "PublishAot", "PublishTrimmed", "IsAotCompatible" }
            .Where(property => project.Contains($"<{property}>true</{property}>", StringComparison.OrdinalIgnoreCase))
            .ToList();

        Assert.True(
            enabled.Count == 0,
            $"{SuppressedCode} is suppressed in MissionController.UI.csproj on the grounds that this app is never "
            + $"published AOT, but {string.Join(" and ", enabled)} is now enabled. The suppression's justification has "
            + "expired: migrate the ViewModels to partial properties (needs LangVersion preview for the MVVM Toolkit "
            + "generator) or drop the AOT setting.");
    }

    /// <summary>
    /// A bare code in NoWarn tells the next reader nothing about whether it may be removed. This
    /// keeps the reasoning attached to the switch, where it survives being copied into another
    /// project or skimmed during a review.
    /// </summary>
    [Fact]
    public void TheSuppression_CarriesItsJustificationInline()
    {
        string project = UiProjectText();
        if (!project.Contains(SuppressedCode, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        Assert.True(
            project.Contains("PublishAot", StringComparison.OrdinalIgnoreCase)
            && project.Contains("partial properties", StringComparison.OrdinalIgnoreCase),
            $"{SuppressedCode} is suppressed without the comment explaining the AOT precondition and the "
            + "partial-property migration that would replace it. Restore the justification next to the NoWarn.");
    }

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, ".git")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }
}
