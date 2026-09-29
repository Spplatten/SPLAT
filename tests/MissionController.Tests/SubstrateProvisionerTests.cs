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

    /// <summary>
    /// Every run gets its own manifest path. Provisioning writes one under the data root when it
    /// changes anything, and the suite found that out the honest way: a run of these tests left a
    /// manifest in the operator's own %LOCALAPPDATA%\SPLAT describing a mount that had only ever
    /// happened to a scripted guest, which `splat-mcp unmount` would then have tried to undo.
    /// </summary>
    private static string LastManifestPath = string.Empty;

    private static Task<int> Provision(
        McpServerCommand.Provision provision,
        TextWriter output,
        SubstrateDoctor.WslRunner wsl,
        WslSubstrateHealthChecker health,
        string? wslConfigPath = null,
        string? agentBinaryPath = null)
    {
        LastManifestPath = Path.Combine(
            Path.GetTempPath(), "splat-provision-tests", Guid.NewGuid().ToString("N"), "mount-manifest.json");
        return SubstrateProvisioner.RunAsync(
            provision, output, wsl, health, wslConfigPath, agentBinaryPath, LastManifestPath);
    }

    private const string EnforcingAnswer =
        "{\"type\":\"HEALTH_RESPONSE\",\"bpfLsmActive\":true,\"cgroupV2Active\":true," +
        "\"overlayFsSupported\":false,\"kernelVersion\":\"6.18.33.2\",\"enforcing\":true,\"activeLeaseCount\":0}";

    /// <summary>A guest with every step already done, except whatever the caller removes.</summary>
    private sealed class ScriptedGuest
    {
        public List<string> Commands { get; } = new();

        public bool HasAgent { get; init; } = true;

        /// <summary>Whether the daemon has already written its token here.</summary>
        public bool HasAgentToken { get; init; }

        public bool HasSystemd { get; init; } = true;

        public bool BpfOnBootLine { get; init; } = true;

        public string? InstalledAgentSha256 { get; init; }

        public string? ShippedAgentFailsWith { get; init; }

        public bool HasCargo { get; init; }

        public bool ShippedAgentAlteredInTransit { get; init; }

        /// <summary>The mode of /mnt/c: 700 once umask=077 has taken effect, 777 as WSL mounts it by default.</summary>
        public string WindowsDriveMode { get; init; } = "700";

        public string WslConf { get; init; } = string.Empty;

        /// <summary>What /etc/splat/policy.json holds; null when the guest has none.</summary>
        public string? CeilingFile { get; init; }

        public Task<(int ExitCode, string Output)> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            string line = string.Join(' ', args);
            Commands.Add(line);

            (int, string) answer = line switch
            {
                _ when line.EndsWith("echo ok", StringComparison.Ordinal) => (0, "ok"),
                _ when line.Contains("stat -c %a /mnt/c", StringComparison.Ordinal) => (0, WindowsDriveMode),
                _ when line.Contains("cat /etc/wsl.conf", StringComparison.Ordinal) => (0, WslConf),
                _ when line.Contains("cat /etc/splat/policy.json", StringComparison.Ordinal) => CeilingFile is null ? (1, string.Empty) : (0, CeilingFile),
                _ when line.Contains("os-release", StringComparison.Ordinal) => (0, "Ubuntu 26.04 LTS"),
                _ when line.Contains("ps -p 1", StringComparison.Ordinal) => (0, HasSystemd ? "systemd" : "init"),
                _ when line.Contains("/proc/cmdline", StringComparison.Ordinal) => (0, BpfOnBootLine ? "initrd=\\initrd.img lsm=landlock,yama,bpf" : "initrd=\\initrd.img lsm=landlock,yama"),
                _ when line.Contains("test -x /opt/splat/splat-agent", StringComparison.Ordinal) => (HasAgent ? 0 : 1, string.Empty),
                _ when line.Contains("test -f /etc/systemd/system/splat-agent.service", StringComparison.Ordinal) => (HasAgent ? 0 : 1, string.Empty),
                // A guest the daemon has never run on has no token: it writes its own at first start.
                // The default matters - answering "it is already there" would hide the one change no
                // step here makes and no unmount would then know to take out.
                _ when line.Contains("test -f /etc/splat/agent.token", StringComparison.Ordinal) => (HasAgentToken ? 0 : 1, string.Empty),
                _ when line.Contains("systemctl is-active", StringComparison.Ordinal) => (0, "active\nenabled"),
                _ when line.EndsWith("sha256sum /opt/splat/splat-agent", StringComparison.Ordinal) => (0, $"{InstalledAgentSha256 ?? new string('0', 64)}  /opt/splat/splat-agent"),
                _ when line.Contains("wslpath -a", StringComparison.Ordinal) => (0, "/mnt/c/shipped/splat-agent"),
                _ when line.Contains("splat-agent.new --help", StringComparison.Ordinal) => ShippedAgentAlteredInTransit ? (4, string.Empty) : ShippedAgentFailsWith is null ? (0, string.Empty) : (3, ShippedAgentFailsWith),
                _ when line.Contains("command -v cargo", StringComparison.Ordinal) => HasCargo ? (0, "/home/dev/.cargo/bin/cargo") : (1, string.Empty),
                _ when line.Contains("printf %s \"$HOME\"", StringComparison.Ordinal) => (0, "/home/dev"),
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
        || command.Contains("> /etc/splat/policy.json", StringComparison.Ordinal)
        || command.Contains("systemctl restart", StringComparison.Ordinal)
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
    [InlineData(new[] { "provision", "--workspace", "C:\\" }, "takes only --apply and --egress")]
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

        int exit = await Provision(
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

        int exit = await Provision(
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

        int exit = await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken));

        // The fix is written, but it takes effect only after a restart that is the user's to take,
        // so the verdict stays NOT provisioned rather than reporting a boot that has not happened.
        Assert.Equal(1, exit);
        Assert.Contains("`wsl --shutdown` is yours", report.ToString());
        Assert.Contains(guest.Commands, command => command.Contains(">> /etc/wsl.conf", StringComparison.Ordinal));
    }

    /// <summary>
    /// WSL mounts the Windows drives with every mode bit open, so a leased command running as nobody
    /// read the operator's whole profile through /mnt/c. The fix was a runbook line; now --apply writes
    /// it, and the restart that makes it take effect stays the user's.
    /// </summary>
    [Fact]
    public async Task OpenWindowsDrives_AreClosedByApply_AndTheRestartIsTheUsers()
    {
        using var daemon = new SubstrateDoctorTests.StandInDaemon(EnforcingAnswer);
        var guest = new ScriptedGuest { WindowsDriveMode = "777" };
        var report = new StringWriter();

        await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget));

        Assert.Contains(guest.Commands, command => command.Contains("umask=077", StringComparison.Ordinal) && command.Contains(">> /etc/wsl.conf", StringComparison.Ordinal));
        Assert.Contains("Windows drives", report.ToString());
        Assert.Contains("`wsl --shutdown` is yours", report.ToString());
    }

    /// <summary>
    /// A mount is honest only if it can be undone, and undoing it means knowing what it did. Every
    /// change goes into a manifest as it is made - the appended stanza with its exact text, so
    /// unmount takes out those lines and not a stanza that looks like them; the daemon, the ceiling
    /// and the unit; and the token the daemon writes at first start, which no step here creates and
    /// which would otherwise be left behind as a root-owned secret nobody recorded.
    /// </summary>
    /// <summary>
    /// The unit must mount bpffs before it starts the daemon, or the daemon's hooks last exactly as
    /// long as its process and a `kill -9` frees whatever is leased at that moment.
    ///
    /// This is a content check on the unit rather than a behaviour check because the failure it
    /// guards is silent: `/sys/fs/bpf` exists as an ordinary read-only sysfs directory on a guest
    /// with no bpffs mounted - the state this project's own WSL2 guest was in on 2026-09-29 - so
    /// nothing downstream notices the mount is missing except the pins that then fail.
    /// </summary>
    [Fact]
    public async Task TheUnitMountsBpffs_BeforeItStartsTheDaemon()
    {
        using var daemon = new SubstrateDoctorTests.StandInDaemon(EnforcingAnswer);
        var guest = new ScriptedGuest();
        using var shipped = new ShippedAgent();

        await Provision(
            new McpServerCommand.Provision(Apply: true), new StringWriter(), guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget),
            agentBinaryPath: shipped.Path);

        string unit = Assert.Single(guest.Commands, c => c.Contains("[Unit]", StringComparison.Ordinal)
                                                      || c.Contains("SPLAT_UNIT", StringComparison.Ordinal));

        int mountAt = unit.IndexOf("mount -t bpf", StringComparison.Ordinal);
        int startAt = unit.IndexOf("ExecStart=/opt/splat/splat-agent", StringComparison.Ordinal);

        Assert.True(mountAt >= 0, $"The unit does not mount bpffs:\n{unit}");
        Assert.True(startAt >= 0, $"The unit does not start the daemon:\n{unit}");
        Assert.True(mountAt < startAt, "The mount must be an ExecStartPre, not something after the daemon is up.");

        // Conditional, so a guest whose distribution already mounted it is left alone - and
        // because mounting bpffs twice succeeds and stacks. Asserted by the guard's shape rather
        // than its spelling: `mountpoint -q` and a /proc/mounts grep are the same claim, and a
        // test that pins one of them fails on a correct change to the other.
        // The whole directive, taken from the newline before the mount rather than from the mount
        // itself: the guard sits to its LEFT, so a slice anchored on `mount` cuts the guard off and
        // the test fails against a unit that is correct. (char)10 because the tooling that writes
        // this file eats backslash escapes.
        int lineStart = unit.LastIndexOf((char)10, mountAt) + 1;
        string directive = unit[lineStart..unit.IndexOf((char)10, mountAt)];

        Assert.StartsWith("ExecStartPre=", directive, StringComparison.Ordinal);
        Assert.Contains("||", directive, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EveryChangeAnApplyMakes_IsRecordedInAMountManifest()
    {
        using var daemon = new SubstrateDoctorTests.StandInDaemon(EnforcingAnswer);
        var guest = new ScriptedGuest { WindowsDriveMode = "777", InstalledAgentSha256 = new string('b', 64) };
        using var shipped = new ShippedAgent();

        await Provision(
            new McpServerCommand.Provision(Apply: true), new StringWriter(), guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget),
            agentBinaryPath: shipped.Path);

        var manifest = MountManifest.Read(LastManifestPath);
        Assert.Equal(MountManifest.CurrentVersion, manifest.Version);

        var wslConf = Assert.Single(manifest.Changes, c => c.Kind == MountChange.Lines && c.Path == "/etc/wsl.conf");
        Assert.Equal("\n[automount]\noptions = \"umask=077\"\n", wslConf.Appended);

        Assert.Contains(manifest.Changes, c => c.Kind == MountChange.Unit && c.Path.EndsWith("splat-agent.service", StringComparison.Ordinal));
        Assert.Contains(manifest.Changes, c => c.Kind == MountChange.File && c.Path == "/opt/splat/splat-agent");
        Assert.Contains(manifest.Changes, c => c.Kind == MountChange.File && c.Path == "/etc/splat/agent.token");

        // The daemon it replaced is named, because nothing kept a copy of it.
        var binary = Assert.Single(manifest.Changes, c => c.Path == "/opt/splat/splat-agent");
        Assert.True(binary.Replaced);
        Assert.Equal(new string('b', 64), binary.PreviousSha256);
    }

    /// <summary>
    /// The ceiling is the one place a stolen token cannot reach around, so provision writes it into the
    /// guest from the operator's --egress, and restarts the daemon that reads it at startup. A guest that
    /// already holds the same document is left alone, and not restarted.
    /// </summary>
    [Fact]
    public async Task TheLeaseCeiling_IsWrittenFromTheOperatorsEgress_AndTheDaemonRestartedForIt()
    {
        using var daemon = new SubstrateDoctorTests.StandInDaemon(EnforcingAnswer);
        var egress = McpEgressPolicy.Parse("203.0.113.7:443,127.0.0.1:80");
        var guest = new ScriptedGuest();
        var report = new StringWriter();

        await Provision(
            new McpServerCommand.Provision(Apply: true, egress), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget));

        string write = Assert.Single(guest.Commands, command => command.Contains("> /etc/splat/policy.json", StringComparison.Ordinal));
        Assert.Contains("\"allowedEgress\"", write);
        Assert.Contains("203.0.113.7:443", write);
        Assert.Contains("\"allowedExecPrefixes\"", write);
        Assert.Contains(guest.Commands, command => command.Contains("systemctl restart splat-agent", StringComparison.Ordinal));
        Assert.Contains("egress bounded to 127.0.0.1:80, 203.0.113.7:443", report.ToString());

        // The same document already in place: nothing written, nothing restarted.
        var settled = new ScriptedGuest { CeilingFile = SubstrateProvisioner.CeilingDocument(egress) };
        await Provision(
            new McpServerCommand.Provision(Apply: true, egress), new StringWriter(), settled.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget));
        Assert.DoesNotContain(settled.Commands, command => command.Contains("> /etc/splat/policy.json", StringComparison.Ordinal));
        Assert.DoesNotContain(settled.Commands, command => command.Contains("systemctl restart", StringComparison.Ordinal));
    }

    /// <summary>An [automount] section the operator wrote is theirs; the tool names the edit rather than making it.</summary>
    [Fact]
    public async Task OpenWindowsDrives_WithAnExistingAutomountSection_AreNotEditedBlindly()
    {
        using var daemon = new SubstrateDoctorTests.StandInDaemon(EnforcingAnswer);
        var guest = new ScriptedGuest { WindowsDriveMode = "777", WslConf = "[automount]\noptions = \"metadata\"\n" };
        var report = new StringWriter();

        await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", daemon.Port, HermeticToken, ReplyBudget));

        Assert.DoesNotContain(guest.Commands, command => command.Contains(">> /etc/wsl.conf", StringComparison.Ordinal));
        Assert.Contains("add `options = \"umask=077\"` under it yourself", report.ToString());
    }

    [Fact]
    public async Task AProvisionedHost_IsReportedAsSuch_FromTheAuthenticatedHealthCheck()
    {
        using var daemon = new SubstrateDoctorTests.StandInDaemon(EnforcingAnswer);
        var guest = new ScriptedGuest();
        var report = new StringWriter();

        int exit = await Provision(
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
            int exit = await Provision(
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

    /// <summary>A stand-in for the daemon publish-splat-mcp.ps1 builds into the executable.</summary>
    private sealed class ShippedAgent : IDisposable
    {
        public ShippedAgent() => File.WriteAllBytes(Path, new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F', 2, 1, 1 });

        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "splat-agent-test-" + Guid.NewGuid().ToString("N"));

        public string Sha256 => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(Path))).ToLowerInvariant();

        public void Dispose() => File.Delete(Path);
    }

    [Fact]
    public async Task AGuestWithNoRustToolchain_GetsTheShippedDaemon_WithoutABuild()
    {
        using var shipped = new ShippedAgent();
        var guest = new ScriptedGuest { HasAgent = false };
        var report = new StringWriter();

        await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), agentBinaryPath: shipped.Path);

        // The whole of 1.9: nothing is built and no toolchain is looked for, so a guest without one gets
        // exactly as far as a guest with one.
        Assert.DoesNotContain(guest.Commands, command => command.Contains("cargo", StringComparison.Ordinal));
        Assert.Contains(guest.Commands, command => command.Contains("splat-agent.new --help", StringComparison.Ordinal));
        Assert.Contains("no Rust toolchain involved", report.ToString());
    }

    [Fact]
    public async Task AShippedDaemonThatWillNotStartHere_IsNamed_AndReplacesNothing()
    {
        using var shipped = new ShippedAgent();
        var guest = new ScriptedGuest
        {
            HasAgent = false,
            ShippedAgentFailsWith = "/lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found (required by /opt/splat/splat-agent.new)",
        };
        var report = new StringWriter();

        int exit = await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), agentBinaryPath: shipped.Path);

        // The loader's own words, whole: the version it names is the thing a stranger has to act on, and a
        // unit that starts a binary which cannot run would fail at boot where nobody is looking.
        Assert.Equal(1, exit);
        Assert.Contains("GLIBC_2.39' not found", report.ToString());
        Assert.DoesNotContain(guest.Commands, command => command.Contains("systemctl", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnInstalledDaemonThatIsNotTheShippedOne_IsReplaced_AndTheServiceRestarted()
    {
        using var shipped = new ShippedAgent();
        var guest = new ScriptedGuest { InstalledAgentSha256 = new string('a', 64) };
        var report = new StringWriter();

        await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), agentBinaryPath: shipped.Path);

        // Replacing the file is not enough on its own: the old process keeps running the old code until
        // the service restarts, which `enable --now` never does to a service that is already up.
        Assert.Contains(guest.Commands, command => command.Contains("splat-agent.new --help", StringComparison.Ordinal));
        Assert.Contains(guest.Commands, command => command.Contains("systemctl restart splat-agent", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnInstalledDaemonThatIsTheShippedOne_IsLeftAlone()
    {
        using var shipped = new ShippedAgent();
        // The daemon and the ceiling both already as this command would leave them.
        var guest = new ScriptedGuest
        {
            InstalledAgentSha256 = shipped.Sha256,
            CeilingFile = SubstrateProvisioner.CeilingDocument(McpEgressPolicy.None),
        };
        var report = new StringWriter();

        await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), agentBinaryPath: shipped.Path);

        // Restarting on every --apply would drop the leases a running daemon holds, to replace a file with
        // itself.
        Assert.DoesNotContain(guest.Commands, command => command.Contains("splat-agent.new", StringComparison.Ordinal));
        Assert.DoesNotContain(guest.Commands, command => command.Contains("systemctl restart", StringComparison.Ordinal));
        Assert.Contains("byte-for-byte the daemon built into this executable", report.ToString());
    }

    [Fact]
    public async Task ADryRun_WithAShippedDaemon_NamesIt_AndChangesNothing()
    {
        using var shipped = new ShippedAgent();
        var guest = new ScriptedGuest { HasAgent = false };
        var report = new StringWriter();

        int exit = await Provision(
            new McpServerCommand.Provision(Apply: false), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), agentBinaryPath: shipped.Path);

        Assert.Equal(1, exit);
        Assert.Contains("--apply installs the daemon built into this executable - no Rust toolchain needed", report.ToString());
        Assert.DoesNotContain(guest.Commands, Mutates);
    }

    /// <summary>
    /// Root installs what provision hands it, and the guest's /tmp is world-writable: any process in it -
    /// a leased workload included, which runs as nobody - can create a path there before provision does.
    /// The source build used /tmp/splat_agent_target, so whoever made that directory first owned what root
    /// installed out of it; the shipped install sent its startup check to a fixed /tmp file, which a file
    /// planted under that name made fail, with the planter's text given as the reason.
    /// </summary>
    [Fact]
    public async Task NeitherWayOfInstallingTheDaemon_GoesThroughTheGuestsTmp()
    {
        var building = new ScriptedGuest { HasAgent = false, HasCargo = true };
        await Provision(
            new McpServerCommand.Provision(Apply: true), new StringWriter(), building.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken));

        using var shipped = new ShippedAgent();
        var carrying = new ScriptedGuest { HasAgent = false };
        await Provision(
            new McpServerCommand.Provision(Apply: true), new StringWriter(), carrying.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), agentBinaryPath: shipped.Path);

        Assert.DoesNotContain(building.Commands.Concat(carrying.Commands), command => command.Contains("/tmp", StringComparison.Ordinal));
        // The build lands in the building user's own cache, and root installs it from there.
        Assert.Contains(building.Commands, command => command.Contains("install -D", StringComparison.Ordinal)
            && command.Contains("/home/dev/.cache/splat-agent-target/release/splat-agent", StringComparison.Ordinal));
    }

    /// <summary>
    /// The shipped daemon reaches the guest as a file in this user's Windows temp directory, which every
    /// process in the guest can write: DrvFs lists it rwxrwxrwx, and on 2026-09-13 `nobody` appended to
    /// one. So root hashes its own copy - made where only root can write - against the bytes this
    /// executable carries, before it runs that copy or moves it into place.
    /// </summary>
    [Fact]
    public async Task AShippedDaemonChangedOnItsWayIntoTheGuest_IsNotInstalled()
    {
        using var shipped = new ShippedAgent();
        var guest = new ScriptedGuest { HasAgent = false, ShippedAgentAlteredInTransit = true };
        var report = new StringWriter();

        int exit = await Provision(
            new McpServerCommand.Provision(Apply: true), report, guest.RunAsync,
            new WslSubstrateHealthChecker("127.0.0.1", 1, HermeticToken), agentBinaryPath: shipped.Path);

        Assert.Equal(1, exit);
        Assert.Contains(guest.Commands, command => command.Contains($"SPLAT_AGENT_SHA256={shipped.Sha256}", StringComparison.Ordinal));
        Assert.Contains("does not match the daemon built into this executable", report.ToString());
        Assert.DoesNotContain(guest.Commands, command => command.Contains("systemctl", StringComparison.Ordinal));
    }

    [Theory]
    // The warning this guest printed on every call on 2026-09-13, beside a clean stdout and exit 0.
    [InlineData(0, "systemd\n", "wsl: Failed to start the systemd user session for 'root'. See journalctl for more details.\n", "systemd")]
    [InlineData(0, "/mnt/c/Users/someone/AppData/Local/Temp/splat-agent-42\n", "wsl: Failed to start the systemd user session for 'someone'. See journalctl for more details.\n", "/mnt/c/Users/someone/AppData/Local/Temp/splat-agent-42")]
    // A command that failed keeps what wsl.exe said about it: there, stderr is the explanation.
    [InlineData(1, "", "wsl: There is no distribution with the supplied name.\n", "wsl: There is no distribution with the supplied name.")]
    public void WslDiagnostics_StayOutOfAnAnswer_ButNotOutOfAFailure(int exitCode, string stdout, string stderr, string expected) =>
        Assert.Equal(expected, SubstrateDoctor.OutputOf(exitCode, stdout, stderr));
}
