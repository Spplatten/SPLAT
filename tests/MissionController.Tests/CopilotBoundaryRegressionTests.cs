using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Windows.Copilot;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;

namespace MissionController.Tests;

[Collection(SerialProcessSpawning.Name)]
public sealed class CopilotBoundaryRegressionTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "splat_copilot_boundary_" + Guid.NewGuid().ToString("N"));
    private readonly List<string> _junctions = [];
    private readonly SqliteStorageContext _storage;
    private readonly CopilotSafetySubstrate _substrate;

    public CopilotBoundaryRegressionTests()
    {
        Directory.CreateDirectory(Path.Combine(_root, "workspace"));
        Directory.CreateDirectory(Path.Combine(_root, "outside"));
        _storage = new SqliteStorageContext(Path.Combine(_root, "audit.db"));
        _substrate = new CopilotSafetySubstrate(new SuspendedProcessLauncher(new RestrictedTokenProvider()),
            new RestrictedTokenProvider(), new NtAclJailManager(), new SqliteChainedAuditLedger(_storage));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WorkspaceAliasesCannotReadOrModifyOutsideFiles(bool directoryJunction)
    {
        string outside = Path.Combine(_root, "outside", "canary.txt");
        await File.WriteAllTextAsync(outside, "SYNTHETIC_OUTSIDE_CANARY");
        string link = Path.Combine(_root, "workspace", "alias");
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"))
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        start.Arguments = $"/d /c mklink {(directoryJunction ? "/J" : "/H")} \"{link}\" \"{(directoryJunction ? Path.GetDirectoryName(outside) : outside)}\"";
        using var process = Process.Start(start)!;
        await process.WaitForExitAsync();
        Assert.True(process.ExitCode == 0, await process.StandardError.ReadToEndAsync());
        if (directoryJunction) _junctions.Add(link);
        string relative = directoryJunction ? "alias/canary.txt" : "alias";
        Assert.Equal("SYNTHETIC_OUTSIDE_CANARY", await File.ReadAllTextAsync(Path.Combine(_root, "workspace", relative)));
        var plugin = new SplatCopilotPlugin(_substrate, workspaceRoot: Path.Combine(_root, "workspace"));
        AssertRefused(await plugin.ReadSandboxedFileAsync(relative));
        AssertRefused(await plugin.WriteSandboxedFileAsync(relative, "changed"));
        Assert.Equal("SYNTHETIC_OUTSIDE_CANARY", await File.ReadAllTextAsync(outside));
        if (directoryJunction)
        {
            AssertRefused(await plugin.WriteSandboxedFileAsync("alias/new/created.txt", "changed"));
            Assert.False(Directory.Exists(Path.Combine(_root, "outside", "new")));
        }
    }

    [Theory]
    [InlineData("report.txt:hidden")]
    [InlineData("folder./report.txt")]
    [InlineData("../outside/report.txt")]
    public async Task AmbiguousWorkspaceNamesAreRefused(string path)
    {
        var plugin = new SplatCopilotPlugin(_substrate, workspaceRoot: Path.Combine(_root, "workspace"));
        AssertRefused(await plugin.ReadSandboxedFileAsync(path));
        AssertRefused(await plugin.WriteSandboxedFileAsync(path, "synthetic"));
    }

    [Fact]
    public async Task UnmappedFunctionsAndExecutableOverridesFailBeforeExecution()
    {
        var filter = new SplatCopilotInvocationFilter(_substrate, bindings:
            [new("Approved", "Echo", "cmd.exe", [], _ => "/c echo approved")]);
        var context = new SplatFunctionInvocationContext("Unknown", "Read", new Dictionary<string, object?>(),
            Guid.NewGuid(), "synthetic-agent", "synthetic-operator");
        await Assert.ThrowsAsync<SecurityException>(() => filter.InterceptAndExecuteAsync(context));
        await Assert.ThrowsAsync<SecurityException>(() => filter.InterceptAndExecuteAsync(context with
        {
            PluginName = "Approved", FunctionName = "Echo", Arguments = new Dictionary<string, object?> { ["command"] = "powershell.exe" }
        }));
    }

    [Fact]
    public async Task WindowsPowerShellUsesItsOwnBuiltInModules()
    {
        string script = "$ErrorActionPreference='Stop'; foreach ($n in @('Get-ExecutionPolicy','Get-FileHash')) { " +
            "$p=(Get-Command $n).Module.Path; [Console]::WriteLine($p) }";
        var context = new CopilotToolCallContext(Guid.NewGuid(), "synthetic-agent", "ModuleProbe",
            Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),
            null, "synthetic-operator");
        var result = await _substrate.ExecuteSafeToolAsync(context,
            CopilotSafetyPolicy.CreateEnterpriseDefault() with { TimeoutSeconds = 60 });
        Assert.True(result.IsSuccess, result.StandardError);
        Assert.Contains(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "Modules"),
            result.StandardOutput, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task CopilotNetworkPolicyDeniesARealSocketWithAnAllowedPositiveControl()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string script = $"try {{ $c = [Net.Sockets.TcpClient]::new(); if ($c.ConnectAsync('127.0.0.1',{port}).Wait(3000)) {{ exit 0 }}; exit 9 }} catch {{ exit 9 }}";
        var context = new CopilotToolCallContext(Guid.NewGuid(), "synthetic-agent", "SocketProbe",
            Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"),
            "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),
            null, "synthetic-operator");
        var policy = CopilotSafetyPolicy.CreateEnterpriseDefault() with { TimeoutSeconds = 60 };
        var allowed = await _substrate.ExecuteSafeToolAsync(context, policy with { AllowNetworkEgress = true });
        Assert.True(allowed.IsSuccess, allowed.StandardError);
        var denied = await _substrate.ExecuteSafeToolAsync(context with { SessionId = Guid.NewGuid() }, policy);
        Assert.False(denied.TimedOut);
        Assert.Equal(9, denied.ExitCode);
        Assert.NotNull(denied.ResourceMetrics);
        Assert.NotNull(denied.MerkleEntryHash);
        Assert.True(await new SqliteChainedAuditLedger(_storage).VerifyLedgerIntegrityAsync());
    }

    private static void AssertRefused(string response)
    {
        using var json = JsonDocument.Parse(response);
        Assert.False(json.RootElement.GetProperty("success").GetBoolean(), response);
    }

    public void Dispose()
    {
        foreach (string link in _junctions) Directory.Delete(link);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(_root, recursive: true);
    }
}
