using SplatMcp;

namespace MissionController.Tests;

/// <summary>
/// The command line that reaches the elevated deployment script. An upgrade names only the instance it
/// replaces in place; anything an install takes would be ignored there, so it is refused instead.
/// </summary>
public sealed class ManagedDeploymentTests
{
    private const string Sha256 = "bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e";

    private static ManagedBridgeCommand.DeploymentRequest Parse(params string[] args) => ManagedBridgeCommand.ParseDeployment(args);

    [Fact]
    public void AnUpgradeNamesOnlyTheInstanceItReplaces()
    {
        var upgrade = Parse("provision", "--managed", "--upgrade", "--instance", "SplatLab", "--apply");

        Assert.Equal(("Upgrade", "SplatLab", true), (upgrade.Mode, upgrade.Instance, upgrade.Apply));
        Assert.Throws<ArgumentException>(() => Parse("provision", "--managed", "--upgrade", "--rootfs", @"C:\rootfs.wsl"));
        Assert.Throws<ArgumentException>(() => Parse("provision", "--managed", "--upgrade", "--operator-sid", "S-1-5-21-1-2-3-1001"));
        Assert.Throws<ArgumentException>(() => Parse("provision", "--managed", "--upgrade", "--upgrade"));
        Assert.Throws<ArgumentException>(() => Parse("unmount", "--managed", "--upgrade"));
    }

    [Fact]
    public void InstallAndRemoveKeepTheirOwnRequirements()
    {
        var install = Parse("provision", "--managed", "--rootfs", @"C:\rootfs.wsl", "--rootfs-sha256", Sha256, "--operator-sid", "S-1-5-21-1-2-3-1001");

        Assert.Equal(("Install", "SplatManaged", false), (install.Mode, install.Instance, install.Apply));
        Assert.Throws<ArgumentException>(() => Parse("provision", "--managed", "--rootfs", @"C:\rootfs.wsl", "--operator-sid", "S-1-5-21-1-2-3-1001"));
        Assert.Equal("Remove", Parse("unmount", "--managed", "--apply").Mode);
        Assert.Throws<ArgumentException>(() => Parse("unmount", "--managed", "--operator-sid", "S-1-5-21-1-2-3-1001"));
        Assert.Throws<ArgumentException>(() => Parse("provision", "--managed", "--instance", "NotSplat", "--upgrade"));
    }

    /// <summary>
    /// Pins the shipped script against the defect that failed the first live 2.4 install. Guest
    /// scripts went to sh through Process.StandardInput. On a UTF-8 system the writer prefixed a BOM,
    /// and WriteLine ended the text with CRLF, so /etc/wsl.conf was written as 'wsl.conf\r' and systemd
    /// never started. They now reach sh from a BOM-less UTF-8 file.
    /// </summary>
    [Fact]
    public void GuestScriptsReachShAsExactBytes()
    {
        using var resource = typeof(ManagedBridgeCommand).Assembly.GetManifestResourceStream("managed-deployment.ps1");
        Assert.NotNull(resource);
        string script = new StreamReader(resource).ReadToEnd();

        Assert.DoesNotContain("StandardInput.WriteLine", script);
        Assert.Contains("[Text.UTF8Encoding]::new($false).GetBytes($Script.Replace(\"`r\", '')", script);
        Assert.Contains("-RedirectStandardInput $scriptFile", script);
    }

    /// <summary>
    /// The daemon refuses a lease when one of the paths it always guards does not resolve. /etc/sudoers
    /// is one of them, and the minimal guest has no sudo, so every lease of the 2026-10-20 gate run was
    /// refused. The managed bootstrap gives the guest one: only when it is absent, and only root may
    /// read it.
    /// </summary>
    [Fact]
    public void TheManagedGuestHasEveryFileTheDaemonGuards()
    {
        using var resource = typeof(ManagedBridgeCommand).Assembly.GetManifestResourceStream("managed-deployment.ps1");
        Assert.NotNull(resource);
        string script = new StreamReader(resource).ReadToEnd();

        Assert.Contains("test -e /etc/sudoers || install -m 0440 -o root -g root /dev/null /etc/sudoers", script);
    }
}
