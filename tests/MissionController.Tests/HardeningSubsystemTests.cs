using System;
using System.IO;
using System.Security.AccessControl;
using System.Threading.Tasks;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using Xunit;

namespace MissionController.Tests;

public class HardeningSubsystemTests
{
    [Fact]
    public void Win32JobSandbox_CreationAndLimits_Succeeds()
    {
        using var sandbox = new Win32JobSandbox();
        Assert.NotNull(sandbox.JobName);

        // Apply 256MB RAM cap and 50% CPU limit
        sandbox.ConfigureExtendedLimits(256 * 1024 * 1024, 50);
        var metrics = sandbox.GetResourceMetrics();
        Assert.NotNull(metrics);
    }

    [Fact]
    public async Task NtAclJailManager_InheritanceStripped_Successfully()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "MissionTestJails_" + Guid.NewGuid().ToString("N"));
        var jailManager = new NtAclJailManager(tempDir);
        var missionId = Guid.NewGuid();

        try
        {
            string jailPath = await jailManager.ProvisionJailAsync(missionId);
            Assert.True(Directory.Exists(jailPath));

            var dirInfo = new DirectoryInfo(jailPath);
            var acl = dirInfo.GetAccessControl();

            // Verify inheritance is stripped (AreAccessRulesProtected == true)
            Assert.True(acl.AreAccessRulesProtected);

            // Verify clean drain and delete
            await jailManager.DrainAndCleanupJailAsync(jailPath);
            Assert.False(Directory.Exists(jailPath));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }
}
