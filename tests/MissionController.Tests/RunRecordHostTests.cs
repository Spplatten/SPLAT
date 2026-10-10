using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Host;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Roadmap 3.1 at the hosts: the signing key is checked before the server starts, `doctor` says
/// whether bundles would be signed, and an MCP client can export one mission's record.
/// </summary>
public sealed class RunRecordHostTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "splat-run-record-" + Guid.NewGuid().ToString("N"));

    public RunRecordHostTests() => Directory.CreateDirectory(_dir);

    private string NewKeyFile(string name = "signing.pem")
    {
        string path = Path.Combine(_dir, name);
        File.WriteAllText(path, RunRecordKeyFile.NewKeyPem(out _));
        return path;
    }

    [Fact]
    public void TheSigningKey_IsCheckedBeforeTheServerStarts()
    {
        string good = NewKeyFile();

        var serve = Assert.IsType<McpServerCommand.Serve>(McpServerCommand.Parse(new[] { "--run-record-key", good }));
        Assert.Equal(good, serve.RunRecordKeyPath);
        var doctor = Assert.IsType<McpServerCommand.Doctor>(McpServerCommand.Parse(new[] { "doctor", $"--run-record-key={good}" }));
        Assert.Equal(good, doctor.RunRecordKeyPath);

        Assert.Contains("does not exist", Assert.IsType<McpServerCommand.UsageError>(
            McpServerCommand.Parse(new[] { "--run-record-key", Path.Combine(_dir, "missing.pem") })).Message);
        Assert.Contains("folder", Assert.IsType<McpServerCommand.UsageError>(
            McpServerCommand.Parse(new[] { "--run-record-key", _dir })).Message);
        Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "provision", "--run-record-key", good }));
    }

    [Fact]
    public void TheEnvironment_SuppliesTheSigningKey_OnlyWhenTheCommandLineDoesNot()
    {
        string fromEnvironment = NewKeyFile("env.pem");
        string fromArgument = NewKeyFile("arg.pem");
        string? Environment(string name) => name == RunRecordKeyFile.EnvironmentVariable ? fromEnvironment : null;

        var filled = McpServerCommand.WithRunRecordKeyFromEnvironment(McpServerCommand.Parse(Array.Empty<string>()), Environment);
        Assert.Equal(fromEnvironment, Assert.IsType<McpServerCommand.Serve>(filled).RunRecordKeyPath);

        var kept = McpServerCommand.WithRunRecordKeyFromEnvironment(
            McpServerCommand.Parse(new[] { "--run-record-key", fromArgument }), Environment);
        Assert.Equal(fromArgument, Assert.IsType<McpServerCommand.Serve>(kept).RunRecordKeyPath);

        var refused = McpServerCommand.WithRunRecordKeyFromEnvironment(
            McpServerCommand.Parse(new[] { "doctor" }), _ => Path.Combine(_dir, "missing.pem"));
        Assert.Contains(RunRecordKeyFile.EnvironmentVariable, Assert.IsType<McpServerCommand.UsageError>(refused).Message);
    }

    [Fact]
    public void MakingAKey_IsItsOwnCommand_AndTakesOnePath()
    {
        var made = Assert.IsType<McpServerCommand.NewRunRecordKey>(McpServerCommand.Parse(new[] { "new-run-record-key", Path.Combine(_dir, "made.pem") }));
        Assert.Equal(Path.Combine(_dir, "made.pem"), made.Path);

        Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "new-run-record-key" }));
        Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "new-run-record-key", "a.pem", "b.pem" }));
    }

    [Fact]
    public async Task TheDoctor_SaysWhetherBundlesWouldBeSigned()
    {
        string key = NewKeyFile();
        using var signer = RunRecordKeyFile.Load(key);

        string signed = await DoctorReportAsync(key);
        Assert.Contains("run records", signed);
        Assert.Contains(signer.KeyId, signed);

        string unsigned = await DoctorReportAsync(null);
        Assert.Contains("UNSIGNED", unsigned);
    }

    [Fact]
    public async Task AnMcpClient_CanExportOneMissionsRunRecord()
    {
        string dbPath = Path.Combine(_dir, "ledger.db");
        var missionId = Guid.NewGuid();
        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(dbPath));
        var facts = new MissionRunFacts
        {
            MissionId = missionId,
            TemplateId = "net-dns-audit",
            TemplateSha256 = "sha256:" + new string('b', 64),
            Principal = "windows:operator",
            StartedAtUtc = DateTimeOffset.UtcNow,
            ExecutablePath = "cmd.exe",
            ExecutionState = "Completed",
            ExitCode = 0
        };
        await ledger.AppendLogAsync(missionId, facts.TemplateId, MissionRunFacts.LedgerAction, JsonSerializer.Serialize(facts), facts.Principal);

        var merkle = new MerkleTreeEngine();
        var handler = new McpServerHandler(
            new StubLeasedExecutor(),
            new TemplatePolicyCompiler(),
            ledger,
            runRecords: new MissionRunRecordAssembler(ledger, merkle, new ComplianceArchiveExporter(merkle)));

        var listed = await handler.ProcessMessageAsync(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "tools/list"
        });
        Assert.Contains("export_run_record", listed.Result!.Value.GetRawText());

        var response = await handler.ProcessMessageAsync(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(2),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "export_run_record",
                arguments = new { missionId = missionId.ToString("D"), outputDirectory = _dir }
            })
        });

        string text = response.Result!.Value.GetRawText();
        Assert.Contains("RUN-RECORD-", text);
        Assert.Contains(missionId.ToString("D"), text);
        Assert.Single(Directory.GetFiles(_dir, "RUN-RECORD-*.zip"));

        // A mission the ledger knows nothing about is refused, not described.
        var refused = await handler.ProcessMessageAsync(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(3),
            Method = "tools/call",
            Params = JsonSerializer.SerializeToElement(new
            {
                name = "export_run_record",
                arguments = new { missionId = Guid.NewGuid().ToString("D") }
            })
        });
        Assert.Contains(MissionRunFacts.LedgerAction, refused.Result!.Value.GetRawText());
    }

    /// <summary>
    /// What is under test here is one line of the report - whether bundles would be signed - which is
    /// a pure function of the key file. Left to their defaults the probes shell into the real WSL
    /// distro and dial the real daemon, each on its own timeout, and the whole test then turns on
    /// whether those answered while the rest of the suite had the CPU. It failed once in a full run
    /// and passed alone, which is the signature. Both seams already exist for exactly this; port 1 is
    /// reserved, so nothing listens there, and the token is supplied outright so no test reads the
    /// host's real secret.
    /// </summary>
    private async Task<string> DoctorReportAsync(string? keyPath)
    {
        var report = new StringWriter();
        await SubstrateDoctor.RunAsync(
            new DoctorOptions(null, McpEgressPolicy.None, null, keyPath),
            report,
            wsl: (_, _) => Task.FromResult((0, "6.6.0-stub\n---\nBOOT_IMAGE=/vmlinux lsm=bpf\n")),
            health: new WslSubstrateHealthChecker("127.0.0.1", 1, new WslAgentToken(authToken: "0123456789abcdef")),
            ledgerPath: Path.Combine(_dir, "doctor-ledger.db"));
        return report.ToString();
    }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { }
    }

    private sealed class StubLeasedExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default) =>
            Task.FromResult(new ProcessExecutionResult(0, string.Empty, string.Empty, false, JobResourceMetrics.Unavailable));
    }
}
