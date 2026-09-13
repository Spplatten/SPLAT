using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The two properties of the shipped artifact that cannot be asserted from inside the process that
/// produces it, so they are asserted against the files that produce it: the single file must carry
/// its native SQLite, and the script must refuse to announce success it did not earn.
///
/// Both have failed before in this repository - a "single file" that needed a DLL beside it, and F22,
/// a packaging path that reported success without a verified package.
/// </summary>
public sealed class SplatMcpDistributionTests
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

    [Fact]
    public void TheSingleFile_CarriesItsNativeSqlite()
    {
        string project = File.ReadAllText(
            Path.Combine(RepositoryRoot(), "src", "splat-mcp", "splat-mcp.csproj"));

        // Without this, a single-file publish drops e_sqlite3.dll beside the executable, and the
        // ledger fails to open on the first machine that downloads only the exe.
        Assert.Contains("<IncludeNativeLibrariesForSelfExtract>true</IncludeNativeLibrariesForSelfExtract>", project);
    }

    [Fact]
    public void ThePublishScript_ChecksEveryStepItClaims()
    {
        string script = File.ReadAllText(
            Path.Combine(RepositoryRoot(), "packaging", "publish-splat-mcp.ps1"));

        // A publish that returns non-zero, an output that is not there, an executable that cannot
        // start, and a stray file beside a "self-contained" one: each must stop the script.
        Assert.Contains("$LASTEXITCODE -ne 0", script);
        Assert.Contains("produced no", script);
        Assert.Contains("failed to print its usage", script);
        Assert.Contains("it is not self-contained", script);

        // And since 1.9, the daemon it carries: one that links libelf or zlib dynamically cannot start in a
        // guest without them, and an executable that quietly shipped without it would send a stranger back
        // to a repository and a Rust toolchain they do not have.
        Assert.Contains("links libelf, zlib or zstd dynamically", script);
        Assert.Contains("does not carry the daemon it was built with", script);
    }
}
