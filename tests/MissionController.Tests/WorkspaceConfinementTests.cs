using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// F10. `fs_read` and `fs_write` decided containment with `Path.GetFullPath` and a prefix compare.
/// That defeats `..` traversal and a sibling whose name merely starts with the root's - but it is a
/// statement about a NAME, and a junction sitting inside the workspace normalises to a name under
/// the root while resolving somewhere else entirely.
///
/// These use real reparse points on disk, because the whole defect is that the string looks fine.
/// A test that mocked the filesystem would reproduce the reasoning that caused the bug.
/// </summary>
public class WorkspaceConfinementTests : IDisposable
{
    private readonly string _sandbox;
    private readonly string _workspace;
    private readonly string _outside;

    public WorkspaceConfinementTests()
    {
        _sandbox = Path.Combine(Path.GetTempPath(), $"splat_ws_{Guid.NewGuid():N}");
        _workspace = Path.Combine(_sandbox, "workspace");
        _outside = Path.Combine(_sandbox, "outside");
        Directory.CreateDirectory(_workspace);
        Directory.CreateDirectory(_outside);
        File.WriteAllText(Path.Combine(_outside, "secret.txt"), "OUT-OF-BOUNDS");
    }

    public void Dispose()
    {
        // Junctions must go before the tree, or the delete follows them out of the sandbox.
        try
        {
            foreach (var d in Directory.EnumerateDirectories(_workspace, "*", SearchOption.AllDirectories))
            {
                var info = new DirectoryInfo(d);
                if ((info.Attributes & FileAttributes.ReparsePoint) != 0) info.Delete();
            }
        }
        catch { }
        try { Directory.Delete(_sandbox, recursive: true); } catch { }
    }

    /// <summary>Creates a real directory junction, the reparse point an unprivileged user can make.</summary>
    private static bool TryMakeJunction(string link, string target)
    {
        var psi = new ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using var p = Process.Start(psi);
        p!.WaitForExit(10_000);
        return p.ExitCode == 0 && Directory.Exists(link);
    }

    private WorkspaceGuard Guard() => new(_workspace);

    // ---------------------------------------------------------------- the ordinary cases

    [Fact]
    public void AFileInsideTheWorkspaceIsReadable()
    {
        File.WriteAllText(Path.Combine(_workspace, "notes.txt"), "hello");

        using var handle = Guard().OpenForRead("notes.txt", out string? final);

        Assert.NotNull(handle);
        Assert.EndsWith("notes.txt", final);
    }

    [Theory]
    [InlineData("../outside/secret.txt")]
    [InlineData("..\\outside\\secret.txt")]
    [InlineData("subdir/../../outside/secret.txt")]
    public void TraversalOutOfTheWorkspaceIsRefused(string path)
    {
        using var handle = Guard().OpenForRead(path, out _);
        Assert.Null(handle);
    }

    [Fact]
    public void ASiblingWhoseNameStartsWithTheRootIsRefused()
    {
        // "…\workspace-evil" is a string prefix match against "…\workspace" and a different
        // directory. The trailing-separator test is what separates them.
        string evil = _workspace + "-evil";
        Directory.CreateDirectory(evil);
        try
        {
            File.WriteAllText(Path.Combine(evil, "x.txt"), "nope");
            using var handle = Guard().OpenForRead(Path.Combine(evil, "x.txt"), out _);
            Assert.Null(handle);
        }
        finally
        {
            try { Directory.Delete(evil, recursive: true); } catch { }
        }
    }

    // ---------------------------------------------------------------- the defect itself

    [Fact]
    public void AJunctionInsideTheWorkspaceCannotBeReadThrough()
    {
        string link = Path.Combine(_workspace, "escape");
        if (!TryMakeJunction(link, _outside))
        {
            return; // mklink /J unavailable on this host; nothing to assert
        }

        string viaJunction = Path.Combine(link, "secret.txt");

        // The lexical check this replaced: canonical, under the root, and pointing at a file the
        // workspace was never supposed to reach.
        Assert.StartsWith(_workspace, Path.GetFullPath(viaJunction), StringComparison.OrdinalIgnoreCase);
        Assert.Equal("OUT-OF-BOUNDS", File.ReadAllText(viaJunction));

        using var handle = Guard().OpenForRead(viaJunction, out _);
        Assert.Null(handle);
    }

    [Fact]
    public void AJunctionInsideTheWorkspaceCannotBeWrittenThrough()
    {
        string link = Path.Combine(_workspace, "escape");
        if (!TryMakeJunction(link, _outside))
        {
            return;
        }

        string target = Path.Combine(_outside, "planted.txt");
        using var handle = Guard().OpenForWrite(Path.Combine(link, "planted.txt"), out _);

        Assert.Null(handle);
        Assert.False(File.Exists(target), "a write escaped the workspace through a junction");
    }

    [Fact]
    public void ANestedJunctionIsRefusedToo()
    {
        // One level down, so the escape is not the first path segment.
        string deep = Path.Combine(_workspace, "a", "b");
        Directory.CreateDirectory(deep);
        string link = Path.Combine(deep, "escape");
        if (!TryMakeJunction(link, _outside))
        {
            return;
        }

        using var handle = Guard().OpenForRead(Path.Combine(link, "secret.txt"), out _);
        Assert.Null(handle);
    }

    [Fact]
    public void AJunctionThatPointsBackInsideIsAllowed()
    {
        // The boundary is the workspace, not the absence of links. A junction resolving to a
        // directory inside it has not crossed anything, and the handle check confirms where the
        // write actually landed - so refusing this would be a restriction with no security to show
        // for it. What matters is the destination, and the destination is verified.
        string inner = Path.Combine(_workspace, "real");
        Directory.CreateDirectory(inner);
        string link = Path.Combine(_workspace, "alias");
        if (!TryMakeJunction(link, inner))
        {
            return;
        }

        using (var handle = Guard().OpenForWrite(Path.Combine(link, "x.txt"), out string? final))
        {
            Assert.NotNull(handle);
            Assert.StartsWith(_workspace, final, StringComparison.OrdinalIgnoreCase);
        }

        Assert.True(File.Exists(Path.Combine(inner, "x.txt")), "the write should have landed in the real directory");
    }

    [Fact]
    public void AnExistingLeafThatIsItselfALinkIsRefused()
    {
        // Refused for a mechanical reason rather than a policy one, and the distinction matters:
        // CREATE_ALWAYS follows a link and truncates its target, so by the time a handle exists to
        // check, an out-of-bounds file has already been emptied. There is no safe check-then-
        // truncate order, so the link is refused before anything is opened for writing.
        string outsideFile = Path.Combine(_outside, "secret.txt");
        string link = Path.Combine(_workspace, "innocent.txt");

        var psi = new ProcessStartInfo("cmd.exe", $"/c mklink \"{link}\" \"{outsideFile}\"")
        {
            UseShellExecute = false, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true
        };
        using (var proc = Process.Start(psi))
        {
            proc!.WaitForExit(10_000);
            if (proc.ExitCode != 0)
            {
                return; // file symlinks need Developer Mode or elevation; nothing to assert
            }
        }

        using var handle = Guard().OpenForWrite("innocent.txt", out _);

        Assert.Null(handle);
        Assert.Equal("OUT-OF-BOUNDS", File.ReadAllText(outsideFile));
    }

    // ---------------------------------------------------------------- through the MCP tools

    private static async Task<McpJsonRpcMessage> CallAsync(McpServerHandler handler, string tool, object args)
    {
        return await handler.ProcessMessageAsync(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new { name = tool, arguments = args })
        });
    }

    [Fact]
    public async Task TheMcpToolsRefuseAJunctionAndSayItWasPolicy()
    {
        string link = Path.Combine(_workspace, "escape");
        if (!TryMakeJunction(link, _outside))
        {
            return;
        }

        var handler = new McpServerHandler(
            new NeverCalledExecutor(),
            new TemplatePolicyCompiler(),
            new SilentLedger(),
            workspaceRoot: _workspace);

        var read = await CallAsync(handler, "fs_read", new { path = Path.Combine(link, "secret.txt") });
        string readText = read.Result!.Value.ToString()!;
        Assert.Contains("SPLAT POLICY", readText);
        Assert.DoesNotContain("OUT-OF-BOUNDS", readText);

        await CallAsync(handler, "fs_write", new { path = Path.Combine(link, "planted.txt"), content = "x" });
        Assert.False(File.Exists(Path.Combine(_outside, "planted.txt")));
    }

    [Fact]
    public async Task TheMcpToolsStillReadAndWriteInsideTheWorkspace()
    {
        // The guard must not cost the ordinary case, or it would just be a broken feature.
        var handler = new McpServerHandler(
            new NeverCalledExecutor(),
            new TemplatePolicyCompiler(),
            new SilentLedger(),
            workspaceRoot: _workspace);

        await CallAsync(handler, "fs_write", new { path = "sub/dir/note.txt", content = "written" });
        Assert.Equal("written", File.ReadAllText(Path.Combine(_workspace, "sub", "dir", "note.txt")));

        var read = await CallAsync(handler, "fs_read", new { path = "sub/dir/note.txt" });
        Assert.Contains("written", read.Result!.Value.ToString());
    }

    private sealed class NeverCalledExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease, string command, System.Collections.Generic.IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null,
            System.Threading.CancellationToken ct = default) =>
            throw new InvalidOperationException("fs_* must never reach the executor");
    }

    private sealed class SilentLedger : IAuditLedger
    {
        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, System.Threading.CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<System.Collections.Generic.IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(
            Guid? missionId = null, int limit = 100, System.Threading.CancellationToken cancellationToken = default) =>
            Task.FromResult<System.Collections.Generic.IReadOnlyList<AuditLogEntry>>(
                Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(System.Threading.CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }
}
