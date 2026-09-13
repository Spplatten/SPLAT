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

        public Task<(int ExitCode, string Output)> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            string line = string.Join(' ', args);
            Commands.Add(line);

            (int, string) answer = line switch
            {
                _ when line.EndsWith("echo ok", StringComparison.Ordinal) => (0, "ok"),
                _ when line.Contains("os-release", StringComparison.Ordinal) => (0, "Ubuntu 26.04 LTS"),
                _ when line.Contains("ps -p 1", StringComparison.Ordinal) => (0, HasSystemd ? "systemd" : "init"),
                _ when line.Contains("/proc/cmdline", StringComparison.Ordinal) => (0, "initrd=\\initrd.img lsm=landlock,yama,bpf"),
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
}
