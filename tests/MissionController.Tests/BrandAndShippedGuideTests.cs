using System.Text.RegularExpressions;
using MissionController.Core;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The console's brand assets and the copy of the Field Guide it ships.
///
/// Both exist because of the same defect: the onboarding wizard's "Read the SPLAT Field Guide"
/// link pointed at a file in a GitHub repository that is private, so the one person the link was
/// written for - somebody who has just installed the console and wants the plain-English
/// explanation - was sent to a 404 behind a sign-in wall. The fix is to ship the guide inside the
/// build and open that. These tests hold the parts of the fix a compiler cannot: that no view
/// links out to the private repository, that the guide is actually copied beside the executable,
/// that the search finds it in both layouts it ships in, and that every asset the XAML names was
/// generated - a missing PNG renders as nothing at all and throws no error anywhere.
/// </summary>
public sealed class BrandAndShippedGuideTests
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

    private static string UiProject() => Path.Combine(RepositoryRoot(), "src", "MissionController.UI");

    private static IEnumerable<string> ViewMarkup() =>
        Directory.EnumerateFiles(UiProject(), "*.xaml", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}")
                     && !p.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}"));

    /// <summary>
    /// No view sends the operator to the source repository. It is private: every such link is a
    /// sign-in wall for everyone who is not its author, and the console is expected to run on
    /// machines with no egress at all, where even a public link would be a dead end.
    /// </summary>
    [Fact]
    public void NoView_LinksToTheSourceRepository()
    {
        var offenders = new List<string>();

        foreach (string file in ViewMarkup())
        {
            string text = File.ReadAllText(file);
            foreach (Match match in Regex.Matches(text, @"https?://[^""'\s<>]*github\.com[^""'\s<>]*"))
            {
                int line = text[..match.Index].Count(c => c == '\n') + 1;
                offenders.Add($"{Path.GetRelativePath(UiProject(), file)}:{line} -> {match.Value}");
            }
        }

        Assert.True(offenders.Count == 0,
            "These views link out to the source repository, which is private - the reader gets a "
            + "404 behind a sign-in wall, and an offline machine gets nothing at all. Ship the "
            + "document with the build and open the shipped copy instead:\n  "
            + string.Join("\n  ", offenders));
    }

    /// <summary>
    /// The guide is copied beside the executable by the UI project. Asserted against the project
    /// file rather than a build output so the check holds on a clean clone, and because the failure
    /// it guards - somebody dropping the Content item - is a source edit.
    /// </summary>
    [Fact]
    public void TheFieldGuide_IsCopiedBesideTheExecutable()
    {
        Assert.True(File.Exists(Path.Combine(RepositoryRoot(), "docs", ShippedFieldGuide.FileName)),
            "The Field Guide is missing from docs/, so no build can ship it.");

        string project = File.ReadAllText(Path.Combine(UiProject(), "MissionController.UI.csproj"));

        Assert.Contains($@"Include=""..\..\docs\{ShippedFieldGuide.FileName}""", project, StringComparison.Ordinal);
        Assert.Contains($@"Link=""docs\{ShippedFieldGuide.FileName}""", project, StringComparison.Ordinal);
        Assert.Contains(@"CopyToOutputDirectory=""PreserveNewest""", project, StringComparison.Ordinal);
    }

    /// <summary>
    /// The two layouts the guide ships in: beside the executable in any build, and one level up
    /// beside App\ in a client package. A miss returns null rather than throwing, because the
    /// caller is a button click.
    /// </summary>
    [Fact]
    public void TheGuideSearch_FindsBothShippedLayouts()
    {
        string root = Path.Combine(Path.GetTempPath(), $"splat-guide-{Guid.NewGuid():N}");
        string app = Path.Combine(root, "App");

        try
        {
            Directory.CreateDirectory(app);
            Assert.Null(ShippedFieldGuide.Locate(app));
            Assert.Null(ShippedFieldGuide.Locate(""));

            // Client package: App\ beside docs\.
            Directory.CreateDirectory(Path.Combine(root, "docs"));
            string staged = Path.Combine(root, "docs", ShippedFieldGuide.FileName);
            File.WriteAllText(staged, "<html></html>");
            Assert.Equal(staged, ShippedFieldGuide.Locate(app));

            // Beside the executable, which wins: it is the copy this build produced.
            Directory.CreateDirectory(Path.Combine(app, "docs"));
            string beside = Path.Combine(app, "docs", ShippedFieldGuide.FileName);
            File.WriteAllText(beside, "<html></html>");
            Assert.Equal(beside, ShippedFieldGuide.Locate(app));
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
                // A temp directory that outlives the test is not a test failure.
            }
        }
    }

    /// <summary>
    /// Every asset named by the XAML, the project file and the package manifest exists. WinUI
    /// renders a missing <c>ms-appx:///</c> image as empty space and raises nothing, so a typo here
    /// is invisible until somebody notices the logo is gone - and MakeAppx packed tiles that were
    /// never generated at all for as long as the manifest has named them.
    /// </summary>
    [Fact]
    public void EveryNamedBrandAsset_HasBeenGenerated()
    {
        string assets = Path.Combine(UiProject(), "Assets");
        var named = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (string file in ViewMarkup())
        {
            foreach (Match m in Regex.Matches(File.ReadAllText(file), @"ms-appx:///Assets/([^""']+)"))
            {
                named.Add(m.Groups[1].Value);
            }
        }

        foreach (string file in new[] { "MissionController.UI.csproj", "Package.appxmanifest" })
        {
            foreach (Match m in Regex.Matches(File.ReadAllText(Path.Combine(UiProject(), file)),
                                              @"Assets[\\/]([A-Za-z0-9._-]+\.(?:png|ico))"))
            {
                named.Add(m.Groups[1].Value);
            }
        }

        // Guards the guard: an empty match set would pass every assertion below it.
        Assert.True(named.Count >= 6, $"Only {named.Count} brand assets were found to be named.");

        var missing = named.Where(n => !File.Exists(Path.Combine(assets, n))).ToList();
        Assert.True(missing.Count == 0,
            "Named but not present in src/MissionController.UI/Assets - regenerate them with "
            + "`py -3 brand/build-brand-assets.py`: " + string.Join(", ", missing));
    }

    /// <summary>
    /// The window icon carries every size Windows asks for. One 256px image in a .ico is legal and
    /// looks it: Windows downscales it itself for the 16px taskbar button, with no sharpening and
    /// no regard for what the artwork does at that size.
    /// </summary>
    [Fact]
    public void TheWindowIcon_CarriesEverySizeWindowsAsksFor()
    {
        byte[] ico = File.ReadAllBytes(Path.Combine(UiProject(), "Assets", "splat.ico"));

        Assert.True(ico.Length > 512, "splat.ico is too small to hold any real artwork.");
        Assert.Equal(0, BitConverter.ToUInt16(ico, 0));         // reserved
        Assert.Equal(1, BitConverter.ToUInt16(ico, 2));         // type: icon, not cursor

        int count = BitConverter.ToUInt16(ico, 4);
        var sizes = new HashSet<int>();
        for (int i = 0; i < count; i++)
        {
            int entry = 6 + (i * 16);
            int width = ico[entry] == 0 ? 256 : ico[entry];     // 0 is how 256 is spelled
            int bytes = BitConverter.ToInt32(ico, entry + 8);
            int offset = BitConverter.ToInt32(ico, entry + 12);

            Assert.True(bytes > 0 && offset + bytes <= ico.Length,
                $"Icon entry {i} ({width}px) points outside the file.");
            sizes.Add(width);
        }

        foreach (int required in new[] { 16, 20, 24, 32, 40, 48, 64, 128, 256 })
        {
            Assert.Contains(required, sizes);
        }
    }

    /// <summary>
    /// The marks keep the alpha channel they were keyed for. A PNG saved as truecolour without
    /// alpha would carry the studio backdrop back into the app as an opaque dark rectangle around
    /// every logo - which is the entire thing the keying pass exists to remove.
    /// </summary>
    [Fact]
    public void TheKeyedMarks_AreTruecolourWithAlpha()
    {
        string assets = Path.Combine(UiProject(), "Assets");
        var pngs = Directory.EnumerateFiles(assets, "*.png").ToList();

        Assert.True(pngs.Count >= 6, $"Only {pngs.Count} PNG assets - the pass did not run.");

        foreach (string png in pngs)
        {
            byte[] head = new byte[26];
            using (var stream = File.OpenRead(png))
            {
                Assert.Equal(head.Length, stream.ReadAtLeast(head, head.Length, throwOnEndOfStream: false));
            }

            Assert.Equal("IHDR", System.Text.Encoding.ASCII.GetString(head, 12, 4));
            Assert.True(head[25] == 6,
                $"{Path.GetFileName(png)} has PNG colour type {head[25]}; 6 (truecolour + alpha) is "
                + "what the keyed artwork needs.");
        }
    }
}
