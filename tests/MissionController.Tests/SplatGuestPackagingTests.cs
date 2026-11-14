using System.Diagnostics;

namespace MissionController.Tests;

public sealed class SplatGuestPackagingTests
{
    [Theory]
    [InlineData("Valid")]
    [InlineData("ArchiveTamper")]
    [InlineData("MissingLicense")]
    [InlineData("SourceVersion")]
    [InlineData("PackageCount")]
    [InlineData("ChangedDuringCopy")]
    [InlineData("SourceFiles")]
    [InlineData("FalseSourceClaim")]
    public async Task GuestBuildAndInstalledPackage_KeepTheirMeasuredRecords(string testCase)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
        };
        // A pwsh 7 parent hands its module path down through dotnet and the test host. Windows
        // PowerShell then resolves PS7's Utility module and loses Get-FileHash, failing all eight
        // cases for a reason unrelated to packaging; without the variable it composes its own.
        start.Environment.Remove("PSModulePath");
        foreach (string argument in new[] { "-NoProfile", "-NonInteractive", "-File",
            Path.Combine(MissionReplayHarness.RepositoryRoot(), "packaging", "test-splat-guest-package.ps1"), "-Case", testCase })
            start.ArgumentList.Add(argument);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        using var process = Process.Start(start) ?? throw new IOException("Packaging test process did not start.");
        process.StandardInput.Close();
        try
        {
            var output = process.StandardOutput.ReadToEndAsync(deadline.Token);
            var error = process.StandardError.ReadToEndAsync(deadline.Token);
            await process.WaitForExitAsync(deadline.Token);
            string text = await output;
            Assert.True(process.ExitCode == 0, text + Environment.NewLine + await error);
            Assert.Contains("PASS " + testCase, text);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
    }
}
