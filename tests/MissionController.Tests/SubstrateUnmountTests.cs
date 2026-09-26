using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// `splat-mcp unmount` plays a mount manifest backwards. The properties held here are the ones a
/// person cannot see from the output: that nothing is removed without a manifest, that nothing is
/// removed at all without --apply, that the config lines taken out are exactly the ones the mount
/// appended, and that anything it could not restore is named rather than passed over.
///
/// The guest is a scripted runner that records every command, so "changed nothing" is asserted on
/// the commands rather than inferred from the report.
/// </summary>
public sealed class SubstrateUnmountTests
{
    private sealed class ScriptedGuest
    {
        public List<string> Commands { get; } = new();

        public string WslConf { get; set; } = string.Empty;

        public bool RmdirSucceeds { get; init; } = true;

        public Task<(int ExitCode, string Output)> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
        {
            string line = string.Join(' ', args);
            Commands.Add(line);

            if (line.Contains("cat '/etc/wsl.conf'", StringComparison.Ordinal))
            {
                return Task.FromResult((0, WslConf));
            }

            if (line.Contains("rmdir", StringComparison.Ordinal))
            {
                return Task.FromResult(RmdirSucceeds ? (0, string.Empty) : (1, "not empty"));
            }

            // The rewrite carries the new content as an environment value, as the provisioner does.
            const string marker = "SPLAT_FILE=";
            int at = line.IndexOf(marker, StringComparison.Ordinal);
            if (at >= 0 && line.Contains("> '/etc/wsl.conf'", StringComparison.Ordinal))
            {
                WslConf = line[(at + marker.Length)..line.IndexOf(" sh -c ", StringComparison.Ordinal)];
            }

            return Task.FromResult((0, string.Empty));
        }
    }

    private static string NewManifestPath() =>
        Path.Combine(Path.GetTempPath(), "splat-unmount-tests", Guid.NewGuid().ToString("N"), "mount-manifest.json");

    private static string Write(string path, params MountChange[] changes)
    {
        MountManifest.Create("Ubuntu (test)", changes).Write(path);
        return path;
    }

    private static async Task<(int Exit, string Report, ScriptedGuest Guest)> UnmountAsync(
        string manifestPath, bool apply, ScriptedGuest? guest = null)
    {
        guest = guest ?? new ScriptedGuest();
        var output = new StringWriter();
        int exit = await SubstrateUnmounter.RunAsync(
            new McpServerCommand.Unmount(apply, manifestPath), output, guest.RunAsync, CancellationToken.None);
        return (exit, output.ToString(), guest);
    }

    [Fact]
    public async Task WithNoManifest_NothingIsRemovedAndNothingIsGuessed()
    {
        var (exit, report, guest) = await UnmountAsync(NewManifestPath(), apply: true);

        Assert.Equal(1, exit);
        Assert.Contains("No mount manifest", report, StringComparison.Ordinal);
        Assert.Empty(guest.Commands);
    }

    [Fact]
    public async Task WithoutApply_TheGuestIsNeverChanged()
    {
        string path = Write(
            NewManifestPath(),
            new MountChange(MountChange.File, MountChange.Guest, "/opt/splat/splat-agent"),
            new MountChange(MountChange.Unit, MountChange.Guest, "/etc/systemd/system/splat-agent.service"));

        var (exit, report, guest) = await UnmountAsync(path, apply: false);

        Assert.Equal(0, exit);
        Assert.Contains("Nothing was changed", report, StringComparison.Ordinal);
        Assert.DoesNotContain(guest.Commands, c => c.Contains("rm -f", StringComparison.Ordinal));
        Assert.DoesNotContain(guest.Commands, c => c.Contains("systemctl", StringComparison.Ordinal));
        Assert.True(File.Exists(path), "a dry run must not remove the manifest");
    }

    /// <summary>
    /// Backwards, because the order matters: the unit has to stop before the binary it runs is
    /// deleted, and a directory has to go after what was in it.
    /// </summary>
    [Fact]
    public async Task TheChangesAreUndoneInReverse()
    {
        string path = Write(
            NewManifestPath(),
            new MountChange(MountChange.File, MountChange.Guest, "/opt/splat/splat-agent"),
            new MountChange(MountChange.Unit, MountChange.Guest, "/etc/systemd/system/splat-agent.service"),
            new MountChange(MountChange.Directory, MountChange.Guest, "/opt/splat"));

        var (exit, _, guest) = await UnmountAsync(path, apply: true);

        Assert.Equal(0, exit);
        int rmdir = guest.Commands.FindIndex(c => c.Contains("rmdir", StringComparison.Ordinal));
        int unit = guest.Commands.FindIndex(c => c.Contains("systemctl disable", StringComparison.Ordinal));
        int binary = guest.Commands.FindIndex(c => c.Contains("rm -f '/opt/splat/splat-agent'", StringComparison.Ordinal));

        Assert.True(rmdir >= 0 && unit > rmdir, "the directory is undone before the unit that came after it");
        Assert.True(binary > unit, "the binary must not be removed while its unit is still running");
        Assert.False(File.Exists(path), "everything was undone, so the manifest goes too");
    }

    /// <summary>
    /// Exactly the lines the mount appended, and nothing that looks like them. The operator's own
    /// stanza stays, which a sed for the same text would have taken out with it.
    /// </summary>
    [Fact]
    public async Task OnlyTheAppendedLinesAreTakenOut()
    {
        const string appended = "\n[automount]\noptions = \"umask=077\"\n";
        var guest = new ScriptedGuest
        {
            WslConf = "[boot]\nsystemd=true\n[interop]\nenabled=true\n" + appended,
        };

        string path = Write(
            NewManifestPath(),
            new MountChange(MountChange.Lines, MountChange.Guest, "/etc/wsl.conf", Appended: appended));

        var (exit, _, _) = await UnmountAsync(path, apply: true, guest);

        Assert.Equal(0, exit);
        Assert.Equal("[boot]\nsystemd=true\n[interop]\nenabled=true\n", guest.WslConf);
    }

    [Fact]
    public async Task LinesThatHaveAlreadyBeenEditedAreLeftAlone()
    {
        var guest = new ScriptedGuest { WslConf = "[boot]\nsystemd=true\n" };
        string path = Write(
            NewManifestPath(),
            new MountChange(MountChange.Lines, MountChange.Guest, "/etc/wsl.conf", Appended: "\n[automount]\noptions = \"umask=077\"\n"));

        var (exit, report, _) = await UnmountAsync(path, apply: true, guest);

        Assert.Equal(1, exit);
        Assert.Contains("gone or changed", report, StringComparison.Ordinal);
        Assert.Equal("[boot]\nsystemd=true\n", guest.WslConf);
        Assert.True(File.Exists(path), "the manifest is the only record of what is still on the host");
    }

    /// <summary>
    /// The honest half. Nothing kept a copy of the binary the mount overwrote, so unmount removes the
    /// replacement and says what cannot come back - rather than leaving the operator to find the hole.
    /// </summary>
    [Fact]
    public async Task AFileThatReplacedAnotherIsReportedAsUnrestorable()
    {
        const string previous = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
        string path = Write(
            NewManifestPath(),
            new MountChange(MountChange.File, MountChange.Guest, "/opt/splat/splat-agent", PreviousSha256: previous));

        var (exit, report, guest) = await UnmountAsync(path, apply: true);

        Assert.Equal(1, exit);
        Assert.Contains("could not restore", report, StringComparison.Ordinal);
        Assert.Contains(previous, report, StringComparison.Ordinal);
        Assert.Contains(guest.Commands, c => c.Contains("rm -f '/opt/splat/splat-agent'", StringComparison.Ordinal));
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task ADirectorySomethingElseIsUsingIsLeftInPlace()
    {
        string path = Write(
            NewManifestPath(),
            new MountChange(MountChange.Directory, MountChange.Guest, "/etc/splat"));

        var (exit, report, _) = await UnmountAsync(path, apply: true, new ScriptedGuest { RmdirSucceeds = false });

        // Not an unrestored change: the directory is still there because it holds something that was
        // never this mount's, which is the right outcome and not a failure to report as one.
        Assert.Equal(0, exit);
        Assert.Contains("not empty", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AChangeKindThisBuildCannotReverse_IsNamedRatherThanSkipped()
    {
        string path = Write(NewManifestPath(), new MountChange("registry-key", MountChange.Host, @"HKCU\Software\Splat"));

        var (exit, report, _) = await UnmountAsync(path, apply: true);

        Assert.Equal(1, exit);
        Assert.Contains("registry-key", report, StringComparison.Ordinal);
    }

    [Fact]
    public void AManifestFromAnotherVersion_IsRefusedWholeRatherThanReadInPart()
    {
        string path = NewManifestPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, """
        {"Version": 99, "MountedUtc": "2026-09-25T00:00:00Z", "Host": "x", "Distro": "y", "Changes": []}
        """);

        var ex = Assert.Throws<InvalidOperationException>(() => MountManifest.Read(path));

        Assert.Contains("version 99", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AManifestRoundTripsThroughItsOwnFormat()
    {
        string path = Write(
            NewManifestPath(),
            new MountChange(MountChange.Lines, MountChange.Guest, "/etc/wsl.conf", Appended: "[boot]\nsystemd=true\n"),
            new MountChange(MountChange.File, MountChange.Guest, "/etc/splat/policy.json", PreviousSha256: new string('a', 64)));

        var read = MountManifest.Read(path);

        Assert.Equal(MountManifest.CurrentVersion, read.Version);
        Assert.Equal(2, read.Changes.Count);
        Assert.Equal("[boot]\nsystemd=true\n", read.Changes[0].Appended);
        Assert.True(read.Changes[1].Replaced);
        Assert.False(read.Changes[0].Replaced);
    }

    [Theory]
    [InlineData(new[] { "unmount" }, false, null)]
    [InlineData(new[] { "unmount", "--apply" }, true, null)]
    public void TheCommandLineParsesUnmount(string[] args, bool apply, string? manifest)
    {
        var command = Assert.IsType<McpServerCommand.Unmount>(McpServerCommand.Parse(args));

        Assert.Equal(apply, command.Apply);
        Assert.Equal(manifest, command.ManifestPath);
    }

    [Fact]
    public void AManifestPathIsMadeAbsolute_BecauseTwoHostsWouldResolveItDifferently()
    {
        var command = Assert.IsType<McpServerCommand.Unmount>(
            McpServerCommand.Parse(new[] { "unmount", "--manifest", "manifest.json" }));

        Assert.True(Path.IsPathRooted(command.ManifestPath), command.ManifestPath);
    }

    [Theory]
    [InlineData("unmount --workspace C:\\")]
    [InlineData("unmount --egress 1.1.1.1:53")]
    [InlineData("provision --manifest x.json")]
    [InlineData("doctor --apply")]
    public void OptionsThatBelongToSomethingElse_AreRefused(string commandLine) =>
        Assert.IsType<McpServerCommand.UsageError>(
            McpServerCommand.Parse(commandLine.Split(' ', StringSplitOptions.RemoveEmptyEntries)));
}
