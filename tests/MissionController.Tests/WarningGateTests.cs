using System.Text.RegularExpressions;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The warning gate guarding itself. A build setting is the easiest control in this repository to
/// switch off quietly - one property, in a file nobody reads twice - and the reason it exists is not
/// tidiness: NU1903, a high-severity advisory in the native SQLite the ledger loads, sat in build
/// output as a warning long enough to ship inside dist\App.
///
/// So the exemption list is asserted rather than trusted, and it is empty. The last project that
/// opted out, the console, was frozen on Windows App SDK 1.6; it moved to 2.5.1 on .NET 10 on
/// 2026-09-18 and built with no warnings, so an exemption now has to appear in a diff and fail here.
/// </summary>
public sealed class WarningGateTests
{
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

    [Theory]
    [InlineData("src")]
    [InlineData("tests")]
    public void EveryShippingTree_TurnsWarningsIntoErrors(string tree)
    {
        string props = Path.Combine(RepositoryRoot(), tree, "Directory.Build.props");

        Assert.True(File.Exists(props), $"{tree}/Directory.Build.props is gone, so nothing holds {tree} to a clean build");
        Assert.Contains("<TreatWarningsAsErrors>true</TreatWarningsAsErrors>", File.ReadAllText(props));
    }

    [Fact]
    public void NoProjectOptsOut()
    {
        var optedOut = Directory
            .EnumerateFiles(RepositoryRoot(), "*.csproj", SearchOption.AllDirectories)
            .Where(p => p.Contains($"{Path.DirectorySeparatorChar}src{Path.DirectorySeparatorChar}", StringComparison.Ordinal)
                     || p.Contains($"{Path.DirectorySeparatorChar}tests{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(p => Regex.IsMatch(File.ReadAllText(p), @"<TreatWarningsAsErrors>\s*false\s*</TreatWarningsAsErrors>",
                                      RegexOptions.IgnoreCase))
            .Select(Path.GetFileName)
            .ToList();

        Assert.Empty(optedOut);
    }
}
