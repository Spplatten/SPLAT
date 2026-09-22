using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A template fixes its executable and the shape of its command, but inside a <c>cmd /c</c> chain or
/// a PowerShell script the commands are named bare - <c>klist</c>, <c>netsh</c>, <c>w32tm</c> - and
/// something has to decide which file that name means. Until 2026-09-22 it was the operator's PATH.
/// On the machine this was found on, a JDK installer had put its bin directory ahead of System32,
/// so identity-kerberos-spn ran Java's klist and reported its usage text as the evidence.
///
/// Found by the operator's threat-model note of 2026-09-22 on the implicit execution environment:
/// the command line was locked, and what it resolved to was not.
/// </summary>
public class ToolCommandResolutionTests
{
    private static async Task<string> RunInJailAsync(string arguments, Action<string>? prepareJail = null)
    {
        var jails = new NtAclJailManager();
        string jail = await jails.ProvisionJailAsync(Guid.NewGuid());
        try
        {
            prepareJail?.Invoke(jail);
            using var job = new Win32JobSandbox($"Resolution_{Guid.NewGuid():N}");
            var run = await new SuspendedProcessLauncher(new RestrictedTokenProvider()).LaunchSuspendedInJobAsync(
                @"C:\Windows\System32\cmd.exe", arguments, jail, job,
                dropAdminPrivileges: true, timeoutSeconds: 30);
            return run.StandardOutput + run.StandardError;
        }
        finally
        {
            await jails.DrainAndCleanupJailAsync(jail);
        }
    }

    /// <summary>
    /// First, not only: web-autonomous-site-deploy asks for node, npm and git, which live wherever
    /// the operator installed them, and a PATH of the Windows directories alone cost it all three.
    /// </summary>
    [Fact]
    public async Task ATool_SearchesTheWindowsDirectoriesFirst_AndKeepsTheRestOfItsEnvironment()
    {
        string output = await RunInJailAsync("/c echo %PATH%& echo %COMPUTERNAME%");
        var lines = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        bool IsSystem32(string dir) => dir.TrimEnd('\\').Equals(Environment.SystemDirectory, StringComparison.OrdinalIgnoreCase);
        var searched = lines[0].Split(';', StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains(searched, IsSystem32);

        var ahead = searched.TakeWhile(dir => !IsSystem32(dir))
            .Where(dir => !dir.StartsWith(windows, StringComparison.OrdinalIgnoreCase))
            .ToList();
        Assert.True(ahead.Count == 0, "a tool's PATH searches these before System32: " + string.Join("; ", ahead));

        // setspn -L %COMPUTERNAME% is why the rest is inherited rather than rebuilt.
        Assert.Equal(Environment.MachineName, lines[1].Trim(), ignoreCase: true);
    }

    /// <summary>
    /// The regression itself. The Windows klist opens with its logon session; the JDK's answers with
    /// "Usage:". On a host with no JDK this passes either way, and on the host that had one it failed.
    /// </summary>
    [Fact]
    public async Task ABareKlist_IsTheWindowsKlist_WhateverTheHostInstalledAheadOfIt()
    {
        string output = await RunInJailAsync("/c klist");

        Assert.Contains("Current LogonId is", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Usage:", output, StringComparison.Ordinal);
    }

    /// <summary>
    /// cmd.exe tries the working directory before PATH, and the working directory is the jail - the
    /// one place a tool is allowed to write. A file left there must not become the next command.
    ///
    /// The variable that stops it is cleared here for the duration. The agent session this was
    /// written in already exported it, so the test would otherwise pass whether or not the launcher
    /// sets it - and the app, started from Explorer, does not inherit it from anywhere.
    /// </summary>
    [Fact]
    public async Task AFileInTheJail_IsNeverRunInPlaceOfTheCommandItShadows()
    {
        const string NoCurrentDirectory = "NoDefaultCurrentDirectoryInExePath";
        string? inherited = Environment.GetEnvironmentVariable(NoCurrentDirectory);
        Environment.SetEnvironmentVariable(NoCurrentDirectory, null);
        try
        {
            string output = await RunInJailAsync("/c klist",
                jail => File.WriteAllText(Path.Combine(jail, "klist.bat"), "@echo PLANTED IN THE JAIL"));

            Assert.DoesNotContain("PLANTED IN THE JAIL", output, StringComparison.Ordinal);
            Assert.Contains("Current LogonId is", output, StringComparison.Ordinal);
        }
        finally
        {
            Environment.SetEnvironmentVariable(NoCurrentDirectory, inherited);
        }
    }
}
