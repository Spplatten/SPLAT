using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Host;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Identity;
using SplatMcp;

namespace MissionController.Tests;

/// <summary>
/// A managed instance installed where WSL is unavailable. Measured on 2026-10-28: with every wsl.exe call
/// failing, splat-mcp and the console ran, but the managed installer aborted, because Install always
/// imported a guest. Windows-only installs create none. An instance's manifest records which kind it is,
/// and the Linux-lease tools refuse with that reason instead of reaching for a distro.
/// </summary>
public sealed class ManagedWindowsOnlyTests
{
    private const string Operator = "S-1-5-21-1-2-3-1001";
    private const string Service = "S-1-5-21-1-2-3-1002";

    private static string Script()
    {
        using var resource = typeof(ManagedBridgeCommand).Assembly.GetManifestResourceStream("managed-deployment.ps1");
        Assert.NotNull(resource);
        return new StreamReader(resource).ReadToEnd();
    }

    [Fact]
    public void AWindowsOnlyInstallTakesNoRootfsAndOnlyANewInstallTakesTheFlag()
    {
        var install = ManagedBridgeCommand.ParseDeployment(new[] { "provision", "--managed", "--windows-only", "--operator-sid", Operator });

        Assert.Equal(("Install", true), (install.Mode, install.WindowsOnly));
        Assert.False(ManagedBridgeCommand.ParseDeployment(new[] { "provision", "--managed", "--rootfs", @"C:\rootfs.wsl",
            "--rootfs-sha256", new string('a', 64), "--operator-sid", Operator }).WindowsOnly);
        foreach (var refused in new[]
        {
            new[] { "provision", "--managed", "--windows-only", "--operator-sid", Operator, "--rootfs", @"C:\rootfs.wsl" },
            new[] { "provision", "--managed", "--windows-only", "--operator-sid", Operator, "--rootfs-sha256", new string('a', 64) },
            new[] { "provision", "--managed", "--windows-only" },
            new[] { "provision", "--managed", "--windows-only", "--windows-only", "--operator-sid", Operator },
            new[] { "provision", "--managed", "--upgrade", "--windows-only" },
            new[] { "unmount", "--managed", "--windows-only" },
        })
            Assert.Throws<ArgumentException>(() => ManagedBridgeCommand.ParseDeployment(refused));
    }

    [Fact]
    public void AWindowsOnlyConfigurationNamesNoGuest()
    {
        ManagedBridgeConfiguration Config(string distribution, int port, string substrate) =>
            new(1, "SplatTest", Service, "pipe", distribution, port, @"C:\private", @"C:\work", new[] { Operator }, Substrate: substrate);

        Config("", 0, ManagedBridgeConfiguration.WindowsOnly).Validate();
        Config("SplatTest", 55555, ManagedBridgeConfiguration.LinuxLease).Validate();
        Assert.Throws<InvalidDataException>(() => Config("SplatTest", 0, ManagedBridgeConfiguration.WindowsOnly).Validate());
        Assert.Throws<InvalidDataException>(() => Config("", 55555, ManagedBridgeConfiguration.WindowsOnly).Validate());
        Assert.Throws<InvalidDataException>(() => Config("", 0, ManagedBridgeConfiguration.LinuxLease).Validate());
        // Shaped like a valid Windows-only configuration, so only the substrate check can refuse them.
        Assert.Throws<InvalidDataException>(() => Config("", 0, "hyper-v").Validate());
        Assert.Throws<InvalidDataException>(() => Config("", 0, "Windows-Only").Validate());

        // Every bridge.json written before Windows-only installs existed omits the field, and fronts a guest.
        var legacy = JsonSerializer.Deserialize<ManagedBridgeConfiguration>(
            $$"""{"Schema":1,"ServiceName":"SplatTest","ServiceSid":"{{Service}}","PipeName":"pipe","Distribution":"SplatTest","Port":55555,"StateDirectory":"C:\\private","WorkspaceDirectory":"C:\\work","OperatorSids":["{{Operator}}"]}""")!;
        Assert.True(legacy.HasLinuxLease);
        legacy.Validate();
    }

    /// <summary>
    /// The deployment script runs under Set-StrictMode -Version Latest, which throws when a missing property
    /// is read. Manifests written before Windows-only installs existed have no Substrate, so reading it
    /// directly would break the upgrade and removal of every existing instance.
    /// </summary>
    [Fact]
    public async Task AManifestWithoutASubstrateIsAGuestInstall()
    {
        var function = Regex.Match(Script(), @"function Test-WindowsOnly\(\$Manifest\) \{.*?\r?\n\}", RegexOptions.Singleline);
        Assert.True(function.Success, "Test-WindowsOnly is missing from the deployment script.");
        string probe = "Set-StrictMode -Version Latest; $ErrorActionPreference = 'Stop'\n" + function.Value + "\n"
            + "'{\"Schema\":1}', '{\"Schema\":1,\"Substrate\":\"LinuxLease\"}', '{\"Schema\":1,\"Substrate\":\"Windows\"}' | "
            + "ForEach-Object { Test-WindowsOnly ($_ | ConvertFrom-Json) }";
        var start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"))
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(probe)) })
            start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        using var budget = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var output = process.StandardOutput.ReadToEndAsync(budget.Token);
        var error = process.StandardError.ReadToEndAsync(budget.Token);
        await process.WaitForExitAsync(budget.Token);

        Assert.True(process.ExitCode == 0, await error);
        Assert.Equal(new[] { "False", "False", "True" },
            (await output).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
    }

    /// <summary>Each of the three guest steps runs only for an instance that has a guest.</summary>
    [Fact]
    public void AWindowsOnlyInstanceNeverStartsAGuestStep()
    {
        string script = Script();

        Assert.Equal(3, Regex.Matches(script, @"Start-Owner .*'Guest(Install|Upgrade|Remove)'").Count);
        Assert.Matches(@"if \(-not \$WindowsOnly\) \{\s*Start-Owner \$credential 'GuestInstall'", script);
        Assert.Matches(@"if \(-not \(Test-WindowsOnly \$manifest\)\) \{ Start-Owner .*'GuestUpgrade' \}", script);
        Assert.Matches(@"if \(\$account -and -not \$windowsOnly\) \{[^}]*'GuestRemove'", script);
        Assert.Contains("$windowsOnly = Test-WindowsOnly $manifest", script);
        Assert.Contains("if (Test-WindowsOnly $manifest) { throw 'This instance was installed Windows-only and has no guest.' }", script);
        Assert.Contains("if ($Rootfs -or $RootfsSha256) { throw 'A Windows-only install takes no rootfs.' }", script);
    }

    /// <summary>
    /// A deployment script from before Windows-only installs accepts only schema 1. Run from an older
    /// publish against a Windows-only instance it read the manifest as a guest install: its upgrade stopped
    /// the service, failed on the missing distro, and failed its own rollback the same way.
    /// </summary>
    [Fact]
    public void AWindowsOnlyManifestIsOneOlderScriptsRefuse()
    {
        string script = Script();

        Assert.Contains("Schema = $(if ($WindowsOnly) { 2 } else { 1 })", script);
        Assert.Contains("if ($manifest.Schema -notin @(1, 2) -or", script);
        Assert.Contains("if (($manifest.Schema -eq 2) -ne (Test-WindowsOnly $manifest)) { throw 'Manifest schema and substrate disagree.' }", script);
    }

    /// <summary>
    /// Nothing reaches an executor, and the sealed record says the call was refused before a lease existed.
    /// Handed to an executor, the refusal read as a tool that ran in a WSL2 guest and failed.
    /// </summary>
    [Fact]
    public async Task AWindowsOnlyHostRefusesLeasesAndSaysWhy()
    {
        var executor = new CountingExecutor();
        var ledger = new RecordingLedger();
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), ledger,
            identityProvider: new McpOperatorIdentityProvider(new StaticOperatorIdentityProvider(
                new OperatorIdentity(@"CONTOSO\op", Operator, OperatorAuthenticationMethod.WindowsAuthenticated))))
        {
            LinuxLeaseAbsent = AbsentLinuxLease.Reason
        };

        string run = JsonSerializer.Serialize((await handler.ProcessMessageAsync(Call("run_command", new { command = "/usr/bin/id" }))).Result);
        string code = JsonSerializer.Serialize((await handler.ProcessMessageAsync(Call("run_code", new { language = "python", code = "print(1)" }))).Result);
        string health = JsonSerializer.Serialize((await handler.ProcessMessageAsync(Call("get_substrate_health", new { }))).Result);

        Assert.Equal(0, executor.Calls);
        Assert.Contains("LINUX_LEASE_ABSENT", run);
        Assert.Contains("LINUX_LEASE_ABSENT", code);
        Assert.Contains("installed Windows-only", health);
        Assert.Contains("\"isError\":true", health, StringComparison.OrdinalIgnoreCase);
        var sealedFacts = ledger.Rows.Where(row => row.Action == MissionRunFacts.LedgerAction)
            .Select(row => JsonSerializer.Deserialize<MissionRunFacts>(row.Details)!).ToList();
        Assert.Equal(2, sealedFacts.Count);
        Assert.All(sealedFacts, facts =>
        {
            Assert.Equal("Refused", facts.ExecutionState);
            Assert.Null(facts.WorkspacePath);
            Assert.DoesNotContain("WSL2", facts.OsDescription ?? "");
        });

        // The backstop refuses too, for any path that still reaches an executor.
        var backstop = await new AbsentLinuxLease().ExecuteLeasedAsync(null!, "/usr/bin/id", Array.Empty<string>());
        Assert.Equal(("LinuxLeaseAbsent", -1), (backstop.TerminalReason, backstop.ExitCode));
    }

    private static McpJsonRpcMessage Call(string tool, object arguments) => new()
    {
        JsonRpc = "2.0",
        Id = JsonSerializer.SerializeToElement(1),
        Method = "tools/call",
        Params = JsonSerializer.SerializeToElement(new { name = tool, arguments })
    };

    private sealed class CountingExecutor : ILeasedExecutor
    {
        public int Calls;
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Calls);
            return Task.FromResult(new ProcessExecutionResult(0, "", "", false, JobResourceMetrics.Unavailable));
        }
    }

    private sealed class RecordingLedger : IAuditLedger
    {
        public readonly List<(string Action, string Details)> Rows = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (Rows) Rows.Add((action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }
}
