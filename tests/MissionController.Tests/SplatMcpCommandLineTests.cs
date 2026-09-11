using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// What a stranger's MCP client meets before any tool runs: splat-mcp's command line, and the first
/// bytes it writes. A bad invocation must cost nothing and say why, a good one must reach the guard
/// with the directory it named, and the first byte on stdout must be the JSON itself.
/// </summary>
public sealed class SplatMcpCommandLineTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splat-mcp-cli-" + Guid.NewGuid().ToString("N"));

    public SplatMcpCommandLineTests() => Directory.CreateDirectory(_root);

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    [Theory]
    [InlineData(new[] { "--no-such-option" }, "unknown option '--no-such-option'")]
    [InlineData(new[] { "stray" }, "unexpected argument 'stray'")]
    [InlineData(new[] { "--workspace" }, "--workspace needs a directory")]
    [InlineData(new[] { "--workspace", "--no-such-option" }, "--workspace needs a directory")]
    [InlineData(new[] { "--workspace=" }, "--workspace needs a directory")]
    [InlineData(new[] { "--workspace", "   " }, "--workspace needs a directory")]
    [InlineData(new[] { "--egress" }, "--egress needs a list")]
    [InlineData(new[] { "--egress", "example.com:443" }, "is not an IPv4 endpoint")]
    [InlineData(new[] { "--egress", "203.0.113.7:443", "--egress=127.0.0.1:80" }, "--egress was given more than once")]
    [InlineData(new[] { "--egress", ", ;" }, "names no endpoints")]
    [InlineData(new[] { "--egress", "203.0.113.7:443,", "127.0.0.1:80" }, "unexpected argument '127.0.0.1:80'")]
    public void ABadInvocation_IsRefusedWithItsReason(string[] args, string reason)
    {
        var error = Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(args));
        Assert.Contains(reason, error.Message);
    }

    [Theory]
    [InlineData("--help")]
    [InlineData("-h")]
    public void Help_WinsWhereverItAppears(string help)
    {
        Assert.IsType<McpServerCommand.ShowHelp>(McpServerCommand.Parse(new[] { "--no-such-option", help, "stray" }));
    }

    [Fact]
    public void NoArguments_ServesWithTheNamedDefault()
    {
        var serve = Assert.IsType<McpServerCommand.Serve>(McpServerCommand.Parse(Array.Empty<string>()));
        Assert.Null(serve.WorkspaceRoot);
        Assert.Contains(McpServerHandler.DefaultWorkspaceRoot, McpServerCommand.Usage);
        Assert.True(serve.Egress.IsEmpty);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnEgressList_ReachesTheServerAsTheOperatorWroteIt(bool equalsForm)
    {
        const string list = "203.0.113.7:443, 127.0.0.1:80";
        string[] args = equalsForm ? new[] { "--egress=" + list, "--workspace", _root } : new[] { "--egress", list };

        var serve = Assert.IsType<McpServerCommand.Serve>(McpServerCommand.Parse(args));

        // Canonical and in a stable order: this is the line an operator reads on stderr at startup.
        Assert.Equal("127.0.0.1:80, 203.0.113.7:443", serve.Egress.ToString());
        Assert.Equal(new uint[] { 443 }, serve.Egress.Authorize(new[] { "203.0.113.7" }).Ports);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AnExistingWorkspace_IsAcceptedAsAFullPath(bool equalsForm)
    {
        string[] args = equalsForm ? new[] { "--workspace=" + _root } : new[] { "--workspace", _root };

        var serve = Assert.IsType<McpServerCommand.Serve>(McpServerCommand.Parse(args));

        Assert.Equal(Path.GetFullPath(_root), serve.WorkspaceRoot);
    }

    [Fact]
    public void AMissingWorkspace_IsRefusedAndNeverCreated()
    {
        string missing = Path.Combine(_root, "not-here");

        var error = Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "--workspace", missing }));

        Assert.Contains("does not exist", error.Message);
        Assert.False(Directory.Exists(missing));
    }

    [Fact]
    public void AFile_IsRefusedAsAWorkspace()
    {
        string file = Path.Combine(_root, "a-file.txt");
        File.WriteAllText(file, "x");

        var error = Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "--workspace", file }));

        Assert.Contains("is a file", error.Message);
    }

    [Fact]
    public void ASecondWorkspace_IsRefusedRatherThanSilentlyWinning()
    {
        var error = Assert.IsType<McpServerCommand.UsageError>(
            McpServerCommand.Parse(new[] { "--workspace", _root, "--workspace=" + _root }));

        Assert.Contains("more than once", error.Message);
    }

    [Fact]
    public async Task Main_ExitsWithTheUsageStatusBeforeBuildingAnything()
    {
        // Had Main fallen through to serving, it would have built the ledger, read stdin to its end
        // and returned 0 - so the usage status on its own shows it stopped at the verdict.
        Assert.Equal(McpServerCommand.UsageExitCode, await Program.Main(new[] { "--no-such-option" }));
    }

    [Fact]
    public async Task Main_ExitsZeroOnHelp()
    {
        Assert.Equal(0, await Program.Main(new[] { "--help" }));
    }

    [Fact]
    public async Task TheFirstByteAClientReceives_IsTheJsonItself()
    {
        var handler = new McpServerHandler(
            new NeverCalledExecutor(), new TemplatePolicyCompiler(), new SilentLedger(), workspaceRoot: _root);
        using var output = new MemoryStream();

        await Program.ServeAsync(
            new StringReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"),
            output,
            handler,
            CancellationToken.None);

        byte[] bytes = output.ToArray();
        Assert.NotEmpty(bytes);
        // Not EF BB BF: a byte order mark here is what a strict JSON parser rejects first.
        Assert.Equal((byte)'{', bytes[0]);
        using var response = JsonDocument.Parse(Encoding.UTF8.GetString(bytes).Split('\n')[0]);
        Assert.True(response.RootElement.TryGetProperty("result", out _));
    }

    /// <summary>A `ping` frame padded to exactly <paramref name="length"/> characters.</summary>
    private static string PingFrameOfLength(int length)
    {
        const string prefix = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"pad\":\"";
        const string suffix = "\"}}";
        string frame = prefix + new string('x', length - prefix.Length - suffix.Length) + suffix;
        Assert.Equal(length, frame.Length);
        return frame;
    }

    private async Task<List<JsonDocument>> ServeAsync(string input)
    {
        var handler = new McpServerHandler(
            new NeverCalledExecutor(), new TemplatePolicyCompiler(), new SilentLedger(), workspaceRoot: _root);
        using var output = new MemoryStream();

        await Program.ServeAsync(new StringReader(input), output, handler, CancellationToken.None);

        return Encoding.UTF8.GetString(output.ToArray())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => JsonDocument.Parse(line))
            .ToList();
    }

    /// <summary>
    /// The cap is the frame, not the frame plus its newline: one of exactly this size is served.
    /// </summary>
    [Fact]
    public async Task AFrameAtTheLimit_IsAnswered()
    {
        var responses = await ServeAsync(PingFrameOfLength(Program.MaxFrameChars) + "\n");

        var response = Assert.Single(responses);
        Assert.True(response.RootElement.TryGetProperty("result", out _));
    }

    /// <summary>
    /// One character more is refused without being buffered, and the session survives it. A stdio
    /// client has no second connection to fall back on, so the reader skips to the next newline
    /// rather than hanging up - and the frame after the bad one is still answered, which is what
    /// proves the tail of the refused frame was not parsed as requests of its own.
    /// </summary>
    [Fact]
    public async Task AFrameOverTheLimit_IsRefusedAndTheSessionContinues()
    {
        string oversized = new string('x', Program.MaxFrameChars + 1);

        var responses = await ServeAsync(oversized + "\n" + PingFrameOfLength(200) + "\n");

        Assert.Equal(2, responses.Count);
        var error = responses[0].RootElement.GetProperty("error");
        Assert.Equal(-32700, error.GetProperty("code").GetInt32());
        Assert.Contains("may not exceed", error.GetProperty("message").GetString());
        Assert.True(responses[1].RootElement.TryGetProperty("result", out _));
    }

    private sealed class NeverCalledExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default) =>
            throw new InvalidOperationException("tools/list must never reach the executor");
    }

    private sealed class SilentLedger : IAuditLedger
    {
        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(
            Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }
}
