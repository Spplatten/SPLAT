using System;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using MissionController.Core;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The one root every SPLAT file hangs off, and the guard that keeps it the only one.
///
/// Before <see cref="SplatDataRoot"/> the two hosts each computed their own paths - eleven
/// expressions of the same idea, over two differently named roots - and the console's jail page
/// computed the jail directory a second time, beside the manager that makes them. The tests here are
/// mostly about the things a second expression of a path gets wrong: which of the three ways of
/// naming a root wins, what an existing installation's data does when the root moves, and whether
/// anything in the tree still computes a data path on its own.
/// </summary>
public class SplatDataRootTests
{
    private static string NewTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "splat-data-root-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    [Fact]
    public void TheEnvironmentVariable_WinsOverAMarkerBesideTheExecutable()
    {
        string executable = NewTempDirectory();
        File.WriteAllText(Path.Combine(executable, SplatDataRoot.PortableMarkerFileName), string.Empty);
        string named = Path.Combine(NewTempDirectory(), "elsewhere");

        var location = SplatDataRoot.Resolve(executable, named);

        Assert.Equal(SplatDataRootKind.Environment, location.Kind);
        Assert.Equal(named, location.Root);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void AnEmptyEnvironmentValue_IsTreatedAsUnset(string configured)
    {
        // An empty variable that meant "the empty path" would open a database beside whatever the
        // working directory happened to be, which is the same rule SqliteStorageContext already used.
        var location = SplatDataRoot.Resolve(NewTempDirectory(), configured);

        Assert.NotEqual(SplatDataRootKind.Environment, location.Kind);
    }

    [Fact]
    public void ARelativeEnvironmentValue_IsRefused()
    {
        // Not resolved against the working directory: the console starts in its own folder and an MCP
        // host starts splat-mcp wherever it pleases, so one relative value would name two roots and
        // the hosts would keep separate ledgers without either of them saying anything.
        var ex = Assert.Throws<InvalidOperationException>(
            () => SplatDataRoot.Resolve(NewTempDirectory(), @"data\splat"));

        Assert.Contains(SplatDataRoot.EnvironmentVariable, ex.Message, StringComparison.Ordinal);
        Assert.Contains("absolute", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AMarkerBesideTheExecutable_PutsTheDataBesideIt()
    {
        string executable = NewTempDirectory();
        File.WriteAllText(Path.Combine(executable, SplatDataRoot.PortableMarkerFileName), string.Empty);

        var location = SplatDataRoot.Resolve(executable, null);

        Assert.Equal(SplatDataRootKind.Portable, location.Kind);
        Assert.Equal(Path.Combine(executable, SplatDataRoot.PortableDefaultDirectoryName), location.Root);
    }

    [Fact]
    public void AMarkerOneDirectoryAbove_IsFound()
    {
        // The kit's own layout: splat-mcp.exe sits in splat\ and the console in splat\app\, and both
        // have to find the one data directory rather than making two.
        string kit = NewTempDirectory();
        string console = Path.Combine(kit, "app");
        Directory.CreateDirectory(console);
        File.WriteAllText(Path.Combine(kit, SplatDataRoot.PortableMarkerFileName), string.Empty);

        var fromConsole = SplatDataRoot.Resolve(console, null);
        var fromServer = SplatDataRoot.Resolve(kit, null);

        Assert.Equal(fromServer.Root, fromConsole.Root);
        Assert.Equal(Path.Combine(kit, SplatDataRoot.PortableDefaultDirectoryName), fromConsole.Root);
    }

    [Fact]
    public void AMarkerTwoDirectoriesAbove_IsNotFound()
    {
        // Bounded on purpose. An unbounded walk would let a marker left in C:\ decide where every copy
        // on the machine keeps its data.
        string top = NewTempDirectory();
        string deep = Path.Combine(top, "one", "two");
        Directory.CreateDirectory(deep);
        File.WriteAllText(Path.Combine(top, SplatDataRoot.PortableMarkerFileName), string.Empty);

        Assert.NotEqual(SplatDataRootKind.Portable, SplatDataRoot.Resolve(deep, null).Kind);
    }

    [Fact]
    public void TheMarkerCanNameItsOwnDirectory_AndCommentsAreIgnored()
    {
        string kit = NewTempDirectory();
        File.WriteAllLines(
            Path.Combine(kit, SplatDataRoot.PortableMarkerFileName),
            new[] { "# written by Mount SPLAT", "evidence" });

        var location = SplatDataRoot.Resolve(kit, null);

        Assert.Equal(Path.Combine(kit, "evidence"), location.Root);
    }

    [Fact]
    public void WithNoMarkerAndNoVariable_TheRootIsUnderLocalApplicationData()
    {
        var location = SplatDataRoot.Resolve(NewTempDirectory(), null);

        Assert.Equal(SplatDataRootKind.Host, location.Kind);
        Assert.Equal(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SPLAT"),
            location.Root);
    }

    [Fact]
    public void EveryPathInTheLayout_IsUnderTheRoot()
    {
        string root = NewTempDirectory();
        var layout = new SplatDataLayout(root);

        var paths = new[]
        {
            layout.Database, layout.LedgerDatabase, layout.Vault, layout.Jails, layout.CrashLog,
            layout.SelfTestReport, layout.McpWorkspace, layout.CopilotWorkspace,
            layout.ComplianceExports, layout.MissionRunRecords, layout.MountManifest,
        };

        Assert.All(paths, path => Assert.StartsWith(root + Path.DirectorySeparatorChar, path, StringComparison.Ordinal));

        // Distinct, because a layout that returned the same path twice would have two subsystems
        // writing over each other and nothing would fail until a mission did.
        Assert.Equal(paths.Length, paths.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void Adoption_MovesAnOlderInstallationsDatabaseAndVault()
    {
        string legacy = NewTempDirectory();
        string root = Path.Combine(NewTempDirectory(), "SPLAT");
        Directory.CreateDirectory(Path.Combine(legacy, "Data"));
        File.WriteAllText(Path.Combine(legacy, "Data", "missioncontroller.db"), "chain");
        Directory.CreateDirectory(Path.Combine(legacy, "Vault"));
        File.WriteAllText(Path.Combine(legacy, "Vault", "anthropic.key"), "protected");

        var host = new SplatDataLocation(root, SplatDataRootKind.Host, "test");
        var moved = SplatDataRoot.AdoptLegacyHostLayout(host, legacy);

        Assert.Equal(2, moved.Count);
        Assert.Equal("chain", File.ReadAllText(Path.Combine(root, "Data", "missioncontroller.db")));
        Assert.Equal("protected", File.ReadAllText(Path.Combine(root, "Vault", "anthropic.key")));
        Assert.False(Directory.Exists(Path.Combine(legacy, "Data")));

        // Idempotent: the second host to start finds nothing left to do and says nothing.
        Assert.Empty(SplatDataRoot.AdoptLegacyHostLayout(host, legacy));
    }

    [Fact]
    public void Adoption_LeavesAnExistingDestinationAlone()
    {
        // The operator may already have run a newer build. Overwriting the live chain with the
        // abandoned one would destroy exactly the evidence this product exists to keep.
        string legacy = NewTempDirectory();
        string root = NewTempDirectory();
        Directory.CreateDirectory(Path.Combine(legacy, "Data"));
        File.WriteAllText(Path.Combine(legacy, "Data", "missioncontroller.db"), "abandoned");
        Directory.CreateDirectory(Path.Combine(root, "Data"));
        File.WriteAllText(Path.Combine(root, "Data", "missioncontroller.db"), "live");

        var moved = SplatDataRoot.AdoptLegacyHostLayout(
            new SplatDataLocation(root, SplatDataRootKind.Host, "test"), legacy);

        Assert.Empty(moved);
        Assert.Equal("live", File.ReadAllText(Path.Combine(root, "Data", "missioncontroller.db")));
        Assert.True(Directory.Exists(Path.Combine(legacy, "Data")));
    }

    [Theory]
    [InlineData(SplatDataRootKind.Portable)]
    [InlineData(SplatDataRootKind.Environment)]
    public void Adoption_DoesNothingForACopyThatWasToldWhereToLive(SplatDataRootKind kind)
    {
        // A drive that silently swallowed the host's ledger the first time it was plugged in would be
        // an exfiltration tool with a friendly icon.
        string legacy = NewTempDirectory();
        Directory.CreateDirectory(Path.Combine(legacy, "Data"));
        File.WriteAllText(Path.Combine(legacy, "Data", "missioncontroller.db"), "host history");
        string root = NewTempDirectory();

        var moved = SplatDataRoot.AdoptLegacyHostLayout(new SplatDataLocation(root, kind, "test"), legacy);

        Assert.Empty(moved);
        Assert.True(File.Exists(Path.Combine(legacy, "Data", "missioncontroller.db")));
        Assert.False(Directory.Exists(Path.Combine(root, "Data")));
    }

    /// <summary>
    /// The guard that keeps this type the only answer. Eleven independent expressions of
    /// <c>LocalApplicationData</c> are how the product ended up with its data under two roots and its
    /// jail directory computed twice; nothing stopped a twelfth being written, and a data root that
    /// most of the product ignores is worse than none, because the parts that obey it look portable.
    ///
    /// Only paths SPLAT owns are in scope. Windows' own directories - System, Windows, the user
    /// profile for <c>.wslconfig</c> - are not data and are not matched here.
    /// </summary>
    [Fact]
    public void NoOtherSourceFile_ComputesADataPathOfItsOwn()
    {
        string root = RepositoryRoot();
        var offenders = Directory
            .EnumerateFiles(Path.Combine(root, "src"), "*.cs", SearchOption.AllDirectories)
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(file => !file.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(file => !string.Equals(Path.GetFileName(file), "SplatDataRoot.cs", StringComparison.Ordinal))
            .Where(file => Regex.IsMatch(File.ReadAllText(file), @"SpecialFolder\.LocalApplicationData"))
            .Select(file => Path.GetRelativePath(root, file))
            .ToList();

        Assert.True(
            offenders.Count == 0,
            "These files compute a data path instead of asking SplatDataRoot for one, so a portable " +
            "copy would leave their files on the host: " + string.Join(", ", offenders));
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
