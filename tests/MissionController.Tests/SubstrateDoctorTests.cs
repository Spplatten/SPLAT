using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// `splat-mcp doctor` is what a stranger runs before trusting this host with an agent, so both of its
/// jobs are held here: it must report what THIS machine can do rather than what the product can do on
/// some other machine, and its summary of a lease must not drift from the substrate's own policy
/// tables. The probes are injected, so the report is tested without a WSL distro or a live daemon.
/// </summary>
public sealed class SubstrateDoctorTests
{
    private static readonly WslSubstrateHealthChecker NoDaemon = new("127.0.0.1", 1);

    private static string RepositoryRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "MissionController.sln")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        return dir!.FullName;
    }

    [Fact]
    public void TheSubcommand_IsOnlyEverTheFirstArgument()
    {
        Assert.IsType<McpServerCommand.Doctor>(McpServerCommand.Parse(new[] { "doctor" }));

        // Anywhere else it is an argument, not a subcommand - otherwise the value of an option could
        // quietly become one.
        Assert.IsType<McpServerCommand.UsageError>(
            McpServerCommand.Parse(new[] { "--egress=127.0.0.1:80", "doctor" }));
    }

    [Fact]
    public void TheSubcommand_KeepsTheOptionsItWasGiven()
    {
        string dir = Path.GetTempPath();

        var doctor = Assert.IsType<McpServerCommand.Doctor>(
            McpServerCommand.Parse(new[] { "doctor", "--workspace", dir, "--egress=127.0.0.1:80" }));

        Assert.Equal(Path.GetFullPath(dir), doctor.WorkspaceRoot);
        Assert.Equal("127.0.0.1:80", doctor.Egress.ToString());
    }

    [Fact]
    public async Task WithNoSubstrate_ItSaysSoAndExitsNonZero()
    {
        var report = new StringWriter();

        int exit = await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((-1, "wsl.exe not found")),
            health: NoDaemon);

        string text = report.ToString();
        Assert.Equal(1, exit);
        Assert.Contains("not reachable", text);
        Assert.Contains("NOT enforcing", text);
        Assert.Contains(McpServerHandler.DefaultWorkspaceRoot, text);
        // The file tools do not depend on the substrate, and the report must not read as if they do.
        Assert.Contains("fs_read and fs_write are confined", text);
        // An unkeyed chain is a property of this host, not a detail to discover later.
        Assert.Contains("UNKEYED", text);
    }

    [Fact]
    public async Task TheKernelAndItsBootLineAreReported_WhateverTheDaemonIsDoing()
    {
        var report = new StringWriter();

        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((0, "6.18.33.2-microsoft-standard-WSL2\n---\ninitrd=\\initrd.img lsm=landlock,yama,bpf\n")),
            health: NoDaemon);

        string text = report.ToString();
        Assert.Contains("6.18.33.2-microsoft-standard-WSL2", text);
        Assert.Contains("bpf is on the boot command line", text);
    }

    [Fact]
    public async Task AKernelWithoutBpfInItsBootLine_IsCalledOut()
    {
        var report = new StringWriter();

        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.None),
            report,
            wsl: (_, _) => Task.FromResult((0, "6.6.0-generic\n---\ninitrd=\\initrd.img lsm=landlock,yama\n")),
            health: NoDaemon);

        Assert.Contains("bpf is NOT on the boot command line", report.ToString());
    }

    [Fact]
    public async Task AnEgressPolicy_IsReportedAsTheOperatorWroteIt()
    {
        var report = new StringWriter();

        await SubstrateDoctor.RunAsync(
            new McpServerCommand.Doctor(null, McpEgressPolicy.Parse("203.0.113.7:443")),
            report,
            wsl: (_, _) => Task.FromResult((-1, "no wsl")),
            health: NoDaemon);

        Assert.Contains("may connect only to 203.0.113.7:443", report.ToString());
    }

    [Fact]
    public void EveryPolicyLineItPrints_IsStillInSupportedPolicy()
    {
        string policy = File.ReadAllText(
            Path.Combine(RepositoryRoot(), "native", "splat-agent", "SUPPORTED_POLICY.md"));

        var missing = SubstrateDoctor.LeasePolicy
            .Where(row => !policy.Contains(row.What, StringComparison.OrdinalIgnoreCase))
            .Select(row => row.What)
            .ToList();

        Assert.Empty(missing);
    }
}
