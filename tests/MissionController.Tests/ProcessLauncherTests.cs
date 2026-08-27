using System;
using System.Threading.Tasks;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using Xunit;

namespace MissionController.Tests;

public class ProcessLauncherTests
{
    [Fact]
    public async Task SuspendedProcessLauncher_SpawnsAndCapturesOutput()
    {
        var tokenProvider = new RestrictedTokenProvider();
        var launcher = new SuspendedProcessLauncher(tokenProvider);
        using var job = new Win32JobSandbox();

        var result = await launcher.LaunchSuspendedInJobAsync(
            "C:\\Windows\\System32\\cmd.exe",
            "/c echo Hello from Hardened Sandbox",
            Environment.CurrentDirectory,
            job,
            dropAdminPrivileges: false,
            timeoutSeconds: 10);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("Hello from Hardened Sandbox", result.StandardOutput);
    }
}
