using System;
using System.Threading.Tasks;
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
