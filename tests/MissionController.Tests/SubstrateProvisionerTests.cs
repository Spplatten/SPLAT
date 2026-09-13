using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// `splat-mcp provision` writes to /etc inside the guest and to the user's .wslconfig, so the property
/// held hardest here is the one a user cannot see from the output: without --apply, nothing is
/// changed. The guest is a scripted <see cref="SubstrateDoctor.WslRunner"/> that records every command
/// it is handed, so "changed nothing" is asserted on the commands, not inferred from the report.
/// </summary>
public sealed class SubstrateProvisionerTests
{
    private static readonly TimeSpan ReplyBudget = TimeSpan.FromSeconds(30);

    private static WslAgentToken HermeticToken => new(authToken: "0123456789abcdef");

    private const string EnforcingAnswer =
        "{\"type\":\"HEALTH_RESPONSE\",\"bpfLsmActive\":true,\"cgroupV2Active\":true," +
        "\"overlayFsSupported\":false,\"kernelVersion\":\"6.18.33.2\",\"enforcing\":true,\"activeLeaseCount\":0}";

    /// <summary>A guest with every step already done, except whatever the caller removes.</summary>
    private sealed class ScriptedGuest
    {
        public List<string> Commands { get; } = new();

        public bool HasAgent { get; init; } = true;

        public bool HasSystemd { get; init; } = true;

        public bool BpfOnBootLine { get; init; } = true;

        public Task<(int ExitCode, string Output)> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            string line = string.Join(' ', args);
            Commands.Add(line);

            (int, string) answer = line switch
            {
                _ when line.EndsWith("echo ok", StringComparison.Ordinal) => (0, "ok"),
                _ when line.Contains("os-release", StringComparison.Ordinal) => (0, "Ubuntu 26.04 LTS"),
                _ when line.Contains("ps -p 1", StringComparison.Ordinal) => (0, HasSystemd ? "systemd" : "init"),
                _ when line.Contains("/proc/cmdline", StringComparison.Ordinal) => (0, BpfOnBootLine ? "initrd=\\initrd.img lsm=landlock,yama,bpf" : "initrd=\\initrd.img lsm=landlock,yama"),
                _ when line.Contains("test -x /opt/splat/splat-agent", StringComparison.Ordinal) => (HasAgent ? 0 : 1, string.Empty),
                _ when line.Contains("test -f /etc/systemd/system/splat-agent.service", StringComparison.Ordinal) => (HasAgent ? 0 : 1, string.Empty),
                _ when line.Contains("systemctl is-active", StringComparison.Ordinal) => (0, "active\nenabled"),
                _ => (0, string.Empty),
            };
            return Task.FromResult(answer);
        }
    }

    /// <summary>Anything that writes, builds, installs or enables. A dry run must issue none of these.</summary>
    private static bool Mutates(string command) =>
        command.Contains("install ", StringComparison.Ordinal)
        || command.Contains("systemctl enable", StringComparison.Ordinal)
        || command.Contains("daemon-reload", StringComparison.Ordinal)
        || command.Contains(">> /etc/wsl.conf", StringComparison.Ordinal)
        || command.Contains("cargo", StringComparison.Ordinal);

    [Theory]
    [InlineData(new[] { "provision" }, false)]
    [InlineData(new[] { "provision", "--apply" }, true)]
    public void TheSubcommand_IsADryRunUnlessToldOtherwise(string[] args, bool apply)
    {
        var provision = Assert.IsType<McpServerCommand.Provision>(McpServerCommand.Parse(args));

        Assert.Equal(apply, provision.Apply);
    }

    [Theory]
    [InlineData(new[] { "--apply" }, "only for `splat-mcp provision`")]
    [InlineData(new[] { "doctor", "--apply" }, "only for `splat-mcp provision`")]
    [InlineData(new[] { "provision", "--apply=yes" }, "takes no value")]
    [InlineData(new[] { "provision", "--apply", "--apply" }, "more than once")]
    [InlineData(new[] { "provision", "--egress", "127.0.0.1:80" }, "takes only --apply")]
    public void AnOptionThatWouldDoNothing_IsRefused(string[] args, string reason)
    {
        var error = Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(args));

        Assert.Contains(reason, error.Message);
    }

    [Fact]
    public async Task ADryRun_ChangesNothing_EvenWhenThereIsEverythingLeftToDo()
    {
        var guest = new ScriptedGuest { HasAgent = false };
        var report = new StringWriter();

        int exit = await SubstrateProvisioner.RunAsync(
            new McpServerCommand.Provision(Apply: false), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken));

        Assert.Equal(1, exit);
        Assert.Contains("todo", report.ToString());
        Assert.Contains("--apply builds it", report.ToString());
        Assert.DoesNotContain(guest.Commands, Mutates);
    }

    [Fact]
    public async Task AHostWithoutWsl_IsToldTheStepIsItsOwn()
    {
        var report = new StringWriter();

        int exit = await SubstrateProvisioner.RunAsync(
            new McpServerCommand.Provision(Apply: true), report,
            (_, _) => Task.FromResult((-1, "wsl.exe not found")),
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken));

        Assert.Equal(1, exit);
        Assert.Contains("Run `wsl --install` yourself", report.ToString());
    }

    [Fact]
    public async Task AGuestWithoutSystemd_IsNotPretendedIntoEnforcing_EvenUnderApply()
    {
        var guest = new ScriptedGuest { HasSystemd = false };
        var report = new StringWriter();

        int exit = await SubstrateProvisioner.RunAsync(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken));

        // The fix is written, but it takes effect only after a restart that is the user's to take,
        // so the verdict stays NOT provisioned rather than reporting a boot that has not happened.
        Assert.Equal(1, exit);
        Assert.Contains("`wsl --shutdown` is yours", report.ToString());
        Assert.Contains(guest.Commands, command => command.Contains(">> /etc/wsl.conf", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AProvisionedHost_IsReportedAsSuch_FromTheAuthenticatedHealthCheck()
    {
        using var daemon = new SubstrateDoctorTests.StandInDaemon(EnforcingAnswer);
        var guest = new ScriptedGuest();
        var report = new StringWriter();

        int exit = await SubstrateProvisioner.RunAsync(
            new McpServerCommand.Provision(Apply: false), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget));

        Assert.Equal(0, exit);
        Assert.Contains("live: a lease reaches the kernel", report.ToString());
        Assert.Contains("comes back on its own after a restart", report.ToString());
        Assert.DoesNotContain(guest.Commands, Mutates);
    }

    /// <summary>
    /// Runs one provision against a .wslconfig in a directory of its own. Until this existed the path
    /// was the developer's real one, so no test could reach the code that appends to it - and any test
    /// that did would have appended to the file on the machine running the suite.
    /// </summary>
    private static async Task<(int Exit, string Report, string? After)> ProvisionWithConfig(string? config, bool apply)
    {
        string dir = Directory.CreateTempSubdirectory("splat-wslconfig-").FullName;
        try
        {
            string path = Path.Combine(dir, ".wslconfig");
            if (config is not null)
            {
                await File.WriteAllTextAsync(path, config);
            }

            var report = new StringWriter();
            int exit = await SubstrateProvisioner.RunAsync(
                new McpServerCommand.Provision(Apply: apply), report, new ScriptedGuest { BpfOnBootLine = false }.RunAsync,
                new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), path);

            return (exit, report.ToString(), File.Exists(path) ? await File.ReadAllTextAsync(path) : null);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task ADryRun_LeavesTheWindowsSideAlone_NotJustTheGuest()
    {
        // Mutates() reads the commands the guest was handed, and .wslconfig is not written through the
        // guest - so "changed nothing" was never asserted for the one file this command edits on Windows.
        var (exit, report, after) = await ProvisionWithConfig(config: null, apply: false);

        Assert.Equal(1, exit);
        Assert.Null(after);
        Assert.Contains("--apply appends a [wsl2] section", report);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("# kernelCommandLine = lsm=landlock,bpf\n")]
    [InlineData("[experimental]\nkernelCommandLine = lsm=landlock,bpf\n")]
    [InlineData("[boot]\nsystemd=true")]
    public async Task WithNoLiveKeyUnderWsl2_ApplyAppendsTheStanza(string? config)
    {
        // A commented-out key, or the same key under another section, is ignored by WSL. Reading either
        // as "already set" sent the user to edit a line that could never take effect.
        var (_, report, after) = await ProvisionWithConfig(config, apply: true);

        string written = Assert.IsType<string>(after);
        Assert.Contains("appended the lsm= stanza", report);
        Assert.StartsWith(config ?? string.Empty, written);
        Assert.EndsWith("[wsl2]\nkernelCommandLine = lsm=landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo,bpf\n", written);
    }

    [Theory]
    [InlineData("[wsl2]\nkernelCommandLine = lsm=landlock,yama\n", "already sets kernelCommandLine under [wsl2]")]
    [InlineData("[wsl2]\nmemory=8GB\n", "has a [wsl2] section without a kernelCommandLine")]
    public async Task AnExistingWsl2Section_IsNeverRewrittenOrDuplicated_OnlyNamed(string config, string named)
    {
        var (exit, report, after) = await ProvisionWithConfig(config, apply: true);

        Assert.Equal(1, exit);
        Assert.Contains(named, report);
        Assert.Equal(config, after);
    }
}
