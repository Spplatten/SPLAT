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

    /// <summary>
    /// The archive itself carries what the daemon needs, so an import runs a lease without the managed
    /// installer: a fresh SPLAT Guest on 2026-10-23 had no systemd, no bpffs and no /etc/sudoers, and
    /// refused every lease until each was added by hand. The hook has to run too, not only exist.
    /// </summary>
    [Fact]
    public void TheGuestArchiveRunsALeaseWithoutAnInstaller()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }
        Assert.NotNull(dir);
        string script = File.ReadAllText(Path.Combine(dir!.FullName, "packaging", "build-splat-guest.sh"));

        Assert.Contains(@"printf '[boot]\nsystemd=true\n' > ""$1""/etc/wsl.conf", script);
        Assert.Contains(@"install -m 0440 -o root -g root /dev/null ""$1""/etc/sudoers", script);
        Assert.Contains("mount -t bpf -o mode=0700 bpffs /sys/fs/bpf", script);
        Assert.Contains("sysinit.target.wants/splat-bpffs.service", script);
        // systemd refuses a .mount unit for its own API filesystem: one was tried, and it never ran.
        Assert.DoesNotContain("sys-fs-bpf.mount", script);
        Assert.Contains(@"--customize-hook='sh ""$WORK/hooks/splat.sh"" ""$1""'", script);
    }

    /// <summary>
    /// A removal ends by moving the deployment root aside, which Windows refuses while a program inside it
    /// runs. Run from the installed copy, the gate's unmount removed everything else and left the root,
    /// which the reinstall then refused (2026-10-21). It is refused before anything is removed.
    /// </summary>
    [Fact]
    public void ARemovalRefusesToRunFromTheCopyItMovesAside()
    {
        using var resource = typeof(ManagedBridgeCommand).Assembly.GetManifestResourceStream("managed-deployment.ps1");
        Assert.NotNull(resource);
        string script = new StreamReader(resource).ReadToEnd();

        int remove = script.IndexOf("if ($Mode -eq 'Remove') {", StringComparison.Ordinal);
        int refusal = script.IndexOf("Run the unmount from a published splat-mcp.exe, not the installed copy", StringComparison.Ordinal);
        int firstEffect = script.IndexOf("Stop-Service -Name $Instance -ErrorAction Stop", remove, StringComparison.Ordinal);
        Assert.True(remove >= 0 && refusal > remove && refusal < firstEffect, "The refusal must come before the removal changes anything.");
    }

    /// <summary>
    /// The first gate unmount (2026-10-21) removed the service, the account and the distro, then stopped
    /// on the account's profile, which WSL still held. The removal now waits for it, bounded, and one
    /// that still cannot finish says it is to be re-run rather than leaving a half-removed instance silent.
    /// </summary>
    [Fact]
    public void ARemovalWaitsForTheRemovedAccountsProfile()
    {
        using var resource = typeof(ManagedBridgeCommand).Assembly.GetManifestResourceStream("managed-deployment.ps1");
        Assert.NotNull(resource);
        string script = new StreamReader(resource).ReadToEnd();

        Assert.DoesNotContain("if ($profile) { $profile | Remove-CimInstance }", script);
        Assert.Contains("for ($attempt = 1; $profile; $attempt++)", script);
        Assert.Contains("run this unmount again to finish", script);
    }
}
