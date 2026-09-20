using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// What a run record reports as enforcement is read back from the kernel objects, never repeated from
/// the request. These run against the real job object, token and jail, because a fake would only
/// echo the request back.
/// </summary>
public class ContainmentReadbackTests
{
    [Fact]
    public void AJob_ReportsTheLimitsTheKernelHolds()
    {
        using var job = new Win32JobSandbox($"ReadbackJob_{Guid.NewGuid():N}");
        job.ConfigureExtendedLimits(256L * 1024 * 1024, 50);

        var limits = job.ReadBackLimits();

        Assert.Equal(256L * 1024 * 1024, limits.ProcessMemoryLimitBytes);
        Assert.Equal(256L * 1024 * 1024, limits.JobMemoryLimitBytes);
        Assert.Equal(50, limits.CpuRatePercent);
        Assert.Equal(32u, limits.ActiveProcessLimit);
        Assert.True(limits.KillOnJobClose);
    }

    [Fact]
    public void AJobWithNoCapsSet_ReportsNone_NotTheCapsSomeoneMightHaveWanted()
    {
        using var job = new Win32JobSandbox($"ReadbackBare_{Guid.NewGuid():N}");

        var limits = job.ReadBackLimits();

        Assert.Null(limits.ProcessMemoryLimitBytes);
        Assert.Null(limits.JobMemoryLimitBytes);
        Assert.Null(limits.CpuRatePercent);
        // The containment flags are armed at construction, caps or no caps.
        Assert.True(limits.KillOnJobClose);
        Assert.Equal(32u, limits.ActiveProcessLimit);
    }

    /// <summary>
    /// Measured on this host, 2026-09-19: wevtutil is refused inside the network-denied AppContainer
    /// exactly as Get-WinEvent is. The roadmap carried a report that the native tool could still read
    /// the event log in there, which would have let the SysOps triage template trade its network stack
    /// for containment; a parallel session made that trade, and this is the differential test that
    /// says it does not work. If a later Windows build opens the path, this test fails and the swap
    /// becomes available again - which is the only way anyone would find out.
    /// </summary>
    [Fact]
    public async Task Wevtutil_IsRefusedInsideTheNetworkDeniedContainer_JustAsTheCmdletIs()
    {
        const string query = "/c wevtutil.exe qe System \"/q:*[System[(Level=1 or Level=2)]]\" /c:1 /rd:true /f:text";
        var jails = new NtAclJailManager();
        var missionId = Guid.NewGuid();
        string jail = await jails.ProvisionJailAsync(missionId);
        try
        {
            var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());

            using var contained = new Win32JobSandbox($"Wevtutil_Denied_{missionId:N}");
            var denied = await launcher.LaunchSuspendedInJobAsync(
                "cmd.exe", query, jail, contained, dropAdminPrivileges: true, timeoutSeconds: 60,
                denyNetworkAccess: true);

            using var open = new Win32JobSandbox($"Wevtutil_Open_{missionId:N}");
            var uncontained = await launcher.LaunchSuspendedInJobAsync(
                "cmd.exe", query, jail, open, dropAdminPrivileges: true, timeoutSeconds: 60,
                denyNetworkAccess: false);

            string deniedOutput = denied.StandardOutput + denied.StandardError;
            string openOutput = uncontained.StandardOutput + uncontained.StandardError;

            // The same command, the same restricted token, one difference: the container.
            Assert.True(deniedOutput.Contains("Access is denied"), $"exit {denied.ExitCode}: {deniedOutput}");
            Assert.True(openOutput.Contains("Event["), $"exit {uncontained.ExitCode}: {openOutput}");
        }
        finally
        {
            await jails.DrainAndCleanupJailAsync(jail);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TheLauncher_ReportsTheJobAndTokenTheToolWasGiven(bool denyNetwork)
    {
        var jails = new NtAclJailManager();
        var missionId = Guid.NewGuid();
        string jail = await jails.ProvisionJailAsync(missionId);
        try
        {
            using var job = new Win32JobSandbox($"ReadbackLaunch_{missionId:N}");
            var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());

            var result = await launcher.LaunchSuspendedInJobAsync(
                "cmd.exe", "/c exit 0", jail, job, dropAdminPrivileges: true, timeoutSeconds: 30,
                denyNetworkAccess: denyNetwork);

            var controls = result.AppliedControls;
            Assert.NotNull(controls);
            string all = string.Join(" | ", controls!);
            Assert.True(result.ExitCode == 0, all);
            Assert.Contains($"job:{job.JobName}", controls);
            Assert.Contains(denyNetwork ? "token:appcontainer=0-capabilities" : "token:appcontainer=none", controls);
            // An AppContainer token runs at Low; the restricted token is lowered to Medium.
            Assert.Contains(denyNetwork ? "token:integrity=Low" : "token:integrity=Medium", controls);
            // Deny-only for an administrator, absent for a standard user, and never usable.
            Assert.DoesNotContain("token:administrators=enabled", controls);
            Assert.StartsWith("acl-jail:inheritance-stripped", jails.DescribeJail(jail));
        }
        finally
        {
            await jails.DrainAndCleanupJailAsync(jail);
        }
    }
}
