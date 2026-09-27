using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Audit;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Data.Compliance;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The wedge, end to end: an outside agent calls the MCP tool, and what it did is assemblable as a
/// run record from the ledger alone.
///
/// Until 2026-09-27 run_command wrote two lines of prose and nothing else. Every claim SPLAT makes
/// about verifiable evidence was true of missions the UI ran and false of the one entry point an
/// external agent has. These tests drive the real handler over a real chained ledger and then ask
/// the real assembler for the record, because a stub on either end would prove only that the test
/// agrees with itself.
/// </summary>
public class McpRunRecordTests : IDisposable
{
    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"splat-mcp-record-{Guid.NewGuid():N}.db");

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        try { File.Delete(_dbPath); } catch (IOException) { }
    }

    /// <summary>
    /// A daemon that reports a lease it really installed: enforcing, jailed, with the kernel's own
    /// refusal count and a signature over its outcome. Everything the enforcement group of a record
    /// is allowed to claim has to come from frames like these.
    /// </summary>
    private sealed class ReportingLeasedExecutor : ILeasedExecutor
    {
        public LeaseSpec? LastLease { get; private set; }
        public LeaseOutcome Outcome { get; set; } = new(
            CgroupId: 4211,
            CgroupPath: "/sys/fs/cgroup/splat/mission",
            Enforcing: true,
            Jailed: true,
            ReadOnlyFs: false,
            Workspace: "/var/lib/splat/missions/m1",
            WorkspaceCreated: true,
            WorkspaceRemoved: true,
            WorkloadUid: 65534,
            Installed: true,
            ViolationsCounted: 2,
            ViolationsReported: 2,
            ViolationsComplete: true,
            ViolationsDropped: 0,
            SignedOutcome: "splat-lease-outcome-v1\nmission m1\nexit 0\n",
            OutcomeSignature: "c2lnbmF0dXJl",
            OutcomeKeyId: "guest-ed25519-1",
            OutcomePublicKey: "cHVibGlj");

        public int ExitCode { get; set; }

        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease,
            string command,
            IReadOnlyList<string> argv,
            IProgress<string>? stdout = null,
            IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default)
        {
            LastLease = lease;
            return Task.FromResult(new ProcessExecutionResult(
                ExitCode: ExitCode,
                StandardOutput: "6.6.87.2-microsoft-standard-WSL2\n",
                StandardError: string.Empty,
                TimedOut: false,
                FinalMetrics: new JobResourceMetrics(1024, 0, 10, 10, 0),
                TerminalReason: null,
                AppliedControls: null,
                LimitsReadBack: new JobLimitsReadback(512 * 1024 * 1024, 512 * 1024 * 1024, 50, 8, true),
                Lease: Outcome));
        }
    }

    private static MissionRunRecordAssembler AssemblerFor(IAuditLedger ledger)
    {
        var merkle = new MerkleTreeEngine();
        return new MissionRunRecordAssembler(ledger, merkle, new ComplianceArchiveExporter(merkle));
    }

    private static McpJsonRpcMessage ToolCall(object arguments, string tool) => new()
    {
        JsonRpc = "2.0",
        Id = JsonSerializer.SerializeToElement(1),
        Method = "tools/call",
        Params = JsonSerializer.SerializeToElement(new { name = tool, arguments })
    };

    private static string TextOf(McpJsonRpcMessage response)
    {
        Assert.NotNull(response.Result);
        var doc = JsonDocument.Parse(response.Result!.Value.GetRawText());
        return doc.RootElement.GetProperty("content")[0].GetProperty("text").GetString() ?? string.Empty;
    }

    /// <summary>
    /// The pointer the caller is handed. Parsing it rather than reading the ledger is the point: an
    /// agent that cannot find the mission id in what it was told cannot ask for the bundle either.
    /// </summary>
    private static Guid MissionIdIn(string toolText)
    {
        var match = Regex.Match(toolText, @"\[SPLAT RUN RECORD\] mission ([0-9a-fA-F-]{36})");
        Assert.True(match.Success, $"The tool result names no run record:\n{toolText}");
        return Guid.Parse(match.Groups[1].Value);
    }

    [Fact]
    public async Task RunCommand_SealsFacts_SoTheAssemblerBuildsARecordFromTheLedgerAlone()
    {
        var executor = new ReportingLeasedExecutor();
        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(_dbPath));
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), ledger);

        var response = await handler.ProcessMessageAsync(ToolCall(new
        {
            command = "/bin/uname",
            args = new[] { "-r" },
            workingDirectory = "/var/lib/splat/missions/m1"
        }, "run_command"));

        string text = TextOf(response);
        var missionId = MissionIdIn(text);

        var record = await AssemblerFor(ledger).AssembleRunRecordAsync(missionId);

        Assert.Equal(missionId, record.RequestIdentity.MissionId);

        // The policy in force was the lease, named by its content. A record whose policy field says
        // "run_command" names the tool, not the envelope, and two calls with different egress would
        // be indistinguishable in the evidence.
        Assert.Equal(MissionRunFacts.HashLease(executor.LastLease!), record.RequestIdentity.PolicyVersionOrHash);

        Assert.Equal("/bin/uname", record.EffectivePermission.ExecutablePath);
        Assert.Equal("-r", record.EffectivePermission.CommandLine);

        Assert.Equal(LinuxLeaseSubstrate.SubstrateName, record.EnforcementState.SubstrateType);
        Assert.Contains("lease:enforcing", record.EnforcementState.AttachedControls!);
        Assert.Contains("workload:uid=65534", record.EnforcementState.AttachedControls!);
        Assert.Equal("/sys/fs/cgroup/splat/mission", record.EnforcementState.CgroupOrJobId);

        // The caller asked for no network, so the kernel refused every destination - and the record
        // has to reach that sentence through the daemon's own "lease:enforcing", not through a
        // second vocabulary this path invented.
        Assert.StartsWith("enforced:", record.EffectivePermission.EgressEnforcement);
        Assert.Contains("refused every connect", record.EffectivePermission.EgressEnforcement);

        Assert.Equal(2ul, record.EnforcementState.KernelRefusals);
        Assert.True(record.EnforcementState.KernelRefusalEvidenceComplete);
        Assert.Equal("guest-ed25519-1", record.EnforcementState.GuestOutcomeKeyId);
        Assert.Equal("splat-lease-outcome-v1\nmission m1\nexit 0\n", record.EnforcementState.GuestSignedOutcome);

        Assert.Equal("Completed", record.Outcome.ExecutionState);
        Assert.Equal(0, record.Outcome.ExitCode);
        Assert.True(record.Outcome.ExitContractMet);

        Assert.Equal("removed", record.Cleanup.WorkspaceDisposition);

        // The flight-recorder row and the facts row, both under this mission, both in one chain.
        Assert.Equal(2, record.Integrity.TotalAuditEntries);
        Assert.Equal("Unkeyed", record.Integrity.ChainKind);
        Assert.NotNull(record.Integrity.MerkleRootHash);
    }

    [Fact]
    public async Task RunCommand_ThatFails_RecordsTheSameVerdictTheCallerWasGiven()
    {
        var executor = new ReportingLeasedExecutor { ExitCode = 3 };
        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(_dbPath));
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), ledger);

        var response = await handler.ProcessMessageAsync(ToolCall(new
        {
            command = "/bin/false",
            args = Array.Empty<string>()
        }, "run_command"));

        var doc = JsonDocument.Parse(response.Result!.Value.GetRawText());
        Assert.True(doc.RootElement.GetProperty("isError").GetBoolean());

        var record = await AssemblerFor(ledger).AssembleRunRecordAsync(MissionIdIn(TextOf(response)));

        // isError and ExitContractMet are the same claim told to two audiences. They drifted apart
        // once already on the mission path, and a record that disagrees with the answer the agent
        // has already acted on is worse than no record.
        Assert.Equal("ToolFailed", record.Outcome.ExecutionState);
        Assert.Equal(3, record.Outcome.ExitCode);
        Assert.False(record.Outcome.ExitContractMet);
    }

    [Fact]
    public async Task RunCommand_RefusedBeforeAnyLease_StillLeavesARecord()
    {
        var executor = new ReportingLeasedExecutor();
        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(_dbPath));
        // No operator egress policy, so asking for network is refused in the host.
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), ledger);

        var response = await handler.ProcessMessageAsync(ToolCall(new
        {
            command = "/usr/bin/curl",
            args = new[] { "https://example.invalid" },
            allowNetwork = true,
            allowedEgressIps = new[] { "93.184.216.34" }
        }, "run_command"));

        Assert.Null(executor.LastLease);

        var record = await AssemblerFor(ledger).AssembleRunRecordAsync(MissionIdIn(TextOf(response)));

        Assert.Equal("Refused", record.Outcome.ExecutionState);
        Assert.StartsWith("Refused:", record.EnforcementState.AdmissionVerdict);
        Assert.Null(record.Outcome.ExitCode);
        Assert.Contains("93.184.216.34", record.EffectivePermission.DeclaredEgress);

        // Nothing was installed, so nothing may be claimed as enforcement.
        Assert.Null(record.EnforcementState.AttachedControls);
        Assert.Equal("not applicable: no tool ran", record.EffectivePermission.EgressEnforcement);
    }

    [Fact]
    public async Task RunCode_SealsUnderItsOwnName_NotRunCommands()
    {
        var executor = new ReportingLeasedExecutor();
        var ledger = new SqliteChainedAuditLedger(new SqliteStorageContext(_dbPath));
        var handler = new McpServerHandler(executor, new TemplatePolicyCompiler(), ledger);

        var response = await handler.ProcessMessageAsync(ToolCall(new
        {
            language = "python",
            code = "print(1, 2)"
        }, "run_code"));

        var missionId = MissionIdIn(TextOf(response));
        var entries = await ledger.GetAuditLogsAsync(missionId, 100);
        var facts = entries.Single(e => e.Action == MissionRunFacts.LedgerAction);

        Assert.Equal("mcp-tool-run_code", facts.TemplateId);
        Assert.All(entries, e => Assert.Equal("mcp-tool-run_code", e.TemplateId));

        var record = await AssemblerFor(ledger).AssembleRunRecordAsync(missionId);
        Assert.Equal("/usr/bin/python3", record.EffectivePermission.ExecutablePath);
    }
}
