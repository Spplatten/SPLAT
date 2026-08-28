using System;
using System.IO;
using MissionController.Core;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The crash sink is the only thing that speaks when the app dies before a window exists - it is
/// what turned "it just doesn't open" into a one-line XAML diagnosis. It has to append reliably and,
/// above all, never throw: an exception raised while handling a crash destroys the very report
/// somebody is trying to read.
/// </summary>
public class FatalErrorLogTests
{
    private static string NewTempPath() => Path.Combine(
        Path.GetTempPath(), "splat-fatal-log-tests", Guid.NewGuid().ToString("N"), "crash.log");

    [Fact]
    public void Write_CreatesMissingDirectories_AndRecordsSourceAndDetail()
    {
        string path = NewTempPath();
        Assert.False(Directory.Exists(Path.GetDirectoryName(path)));

        bool persisted = FatalErrorLog.Write("WinUI UnhandledException", new InvalidOperationException("boom"), path);

        Assert.True(persisted);
        string contents = File.ReadAllText(path);
        Assert.Contains("WinUI UnhandledException", contents);
        Assert.Contains("boom", contents);
        // A timestamp is what makes a crash log usable across repeated launch attempts.
        Assert.Contains(DateTime.UtcNow.Year.ToString(), contents);
    }

    [Fact]
    public void Write_Appends_SoRepeatedFailedLaunchesAllSurvive()
    {
        string path = NewTempPath();

        FatalErrorLog.Write("First", "first failure", path);
        FatalErrorLog.Write("Second", "second failure", path);

        string contents = File.ReadAllText(path);
        Assert.Contains("first failure", contents);
        Assert.Contains("second failure", contents);
    }

    [Fact]
    public void Write_ToAnUnusablePath_ReturnsFalseWithoutThrowing()
    {
        // Invalid characters and a non-existent device: writing must fail quietly, because this runs
        // inside a crash handler where a second exception would mask the first.
        string unusable = Path.Combine("Z:\\", "no-such-device", "\0invalid", "crash.log");

        bool persisted = FatalErrorLog.Write("Fatal", new Exception("original error"), unusable);

        Assert.False(persisted);
    }

    [Fact]
    public void Write_HandlesNullDetail_WithoutThrowing()
    {
        string path = NewTempPath();

        bool persisted = FatalErrorLog.Write("AppDomain UnhandledException", null, path);

        Assert.True(persisted);
        Assert.Contains("AppDomain UnhandledException", File.ReadAllText(path));
    }

    [Fact]
    public void DefaultPath_LandsUnderLocalAppData_WhereAnOperatorCanFindIt()
    {
        string expectedRoot = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

        Assert.StartsWith(expectedRoot, FatalErrorLog.DefaultPath, StringComparison.OrdinalIgnoreCase);
        Assert.EndsWith("crash.log", FatalErrorLog.DefaultPath, StringComparison.OrdinalIgnoreCase);
    }
}
