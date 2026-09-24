using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Dlp;
using MissionController.Infrastructure.Network.Identity;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A governed mission on the Linux lease: the product's own specialist, through the engine's whole
/// pipeline, with its tool run by the guest daemon under a lease compiled from its template.
///
/// Until 2026-09-24 the one-pager's "not proven" list carried the sentence "the console never routes
/// a governed mission through the daemon", and it was true: the lease held what a visiting agent sent
/// through run_command and nothing of SPLAT's own. These tests drive the engine against a stand-in
/// daemon on a loopback socket - the same stand-in the bridge's wire tests use - and read what crossed:
/// the lease the mission authored, and what the mission recorded of the daemon's answer.
/// </summary>
public sealed class LeasedMissionTests
{
    private const string Token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string MissionsRoot = "/var/lib/splat/missions";

    /// <summary>A plausible answer the judge accepts: it quotes the sensor's own lines.</summary>
    private const string DfOutput =
        "Filesystem     1024-blocks     Used Available Capacity Mounted on\n" +
        "/dev/sdc         263174212 12345678 237388120       5% /\n" +
        "tmpfs              4041924        0   4041924       0% /tmp\n";

    private const string Answer =
        "The root filesystem is at 5% and the jail's tmpfs is empty.\n" +
        "```json\n" +
        "{\"status\":\"Healthy\",\"headline\":\"Root filesystem /dev/sdc at 5%\"," +
        "\"findings\":[\"/dev/sdc is 5% used with 237388120 blocks available, mounted on /\"," +
        "\"tmpfs on /tmp is at 0%\"]}\n" +
        "```";

    [Fact]
    public async Task ALinuxTemplate_RunsThroughTheEngineUnderALeaseCompiledFromIt_AndRecordsWhatTheDaemonHeld()
    {
        var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "linux-disk-usage");
        Assert.Equal(ToolSubstrate.LinuxLease, template.Tool.Substrate);

        string leaseFrame = JsonSerializer.Serialize(new
        {
            type = "LEASE",
            missionId = "any",
            cgroupId = 4242UL,
            cgroupPath = "/sys/fs/cgroup/splat_leases/mission_test",
            enforcing = true,
            limitsReadBack = true,
            limits = new { maxMemoryBytes = 134217728L, maxCpuPercent = 40, maxPids = 50 },
            jailed = true,
            readOnlyFs = false,
            workspace = MissionsRoot + "/test",
            workspaceCreated = true,
            workloadUid = 65534,
        });
        string stdoutFrame = JsonSerializer.Serialize(new { type = "STDOUT", data = DfOutput });
        const string exitFrame = "{\"type\":\"EXIT\",\"exitCode\":0,\"violationsDropped\":0,\"workspaceRemoved\":true}";

        var (chunks, facts, request) = await RunAsync(template, new[] { leaseFrame, stdoutFrame, exitFrame });

        // 1. The lease is the template, compiled: the one guest executable, its arguments split, no
        //    network, the tool's clamps, the mission's own workspace for the daemon to make.
        Assert.NotNull(request);
        using var lease = JsonDocument.Parse(request!);
        var root = lease.RootElement;
        Assert.Equal("EXECUTE_TOOL", root.GetProperty("type").GetString());
        Assert.Equal("/bin/df", root.GetProperty("command").GetString());
        Assert.Equal(new[] { "-hP" }, root.GetProperty("argv").EnumerateArray().Select(a => a.GetString()).ToArray());
        Assert.Equal(new[] { "/bin/df" }, root.GetProperty("allowedExecPaths").EnumerateArray().Select(a => a.GetString()).ToArray());
        Assert.False(root.GetProperty("allowNetwork").GetBoolean());
        Assert.True(root.GetProperty("ephemeralWorkspace").GetBoolean());
        Assert.Equal(facts.MissionId.ToString(), root.GetProperty("missionId").GetString());
        Assert.Equal($"{MissionsRoot}/{facts.MissionId:N}", root.GetProperty("workingDirectory").GetString());
        Assert.Equal(128L * 1024 * 1024, root.GetProperty("limits").GetProperty("maxMemoryBytes").GetInt64());
        Assert.Equal(40, root.GetProperty("limits").GetProperty("maxCpuPercent").GetInt32());
        Assert.Equal(30, root.GetProperty("leaseDurationSeconds").GetInt32());
        Assert.Contains("/etc/shadow", root.GetProperty("protectedPaths").EnumerateArray().Select(a => a.GetString()));

        // 2. The mission ran to its verdict on the daemon's output.
        Assert.Equal(DfOutput, chunks.Single(c => c.ChunkType == MissionChunkType.Stdout).Content);
        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.Completed);

        // 3. The record says which substrate, and what the guest held - read from the daemon's frames,
        //    never repeated from the request.
        Assert.Equal(LinuxLeaseSubstrate.SubstrateName, facts.Substrate);
        Assert.Equal("Completed", facts.ExecutionState);
        Assert.True(facts.ExitContractMet);
        Assert.True(facts.NetworkDenialRequested);
        Assert.Equal($"{MissionsRoot}/{facts.MissionId:N}", facts.WorkspacePath);
        Assert.Contains("lease:enforcing", facts.AppliedControls);
        Assert.Contains("cgroup:/sys/fs/cgroup/splat_leases/mission_test", facts.AppliedControls);
        Assert.Contains("jail:mount-namespace", facts.AppliedControls);
        Assert.Contains("workload:uid=65534", facts.AppliedControls);
        Assert.Contains($"workspace:{MissionsRoot}/test (created by the daemon)", facts.AppliedControls);
        Assert.NotNull(facts.LimitsReadBack);
        Assert.Equal(134217728L, facts.LimitsReadBack!.ProcessMemoryLimitBytes);
        Assert.Equal(40, facts.LimitsReadBack.CpuRatePercent);
        Assert.Equal(50u, facts.LimitsReadBack.ActiveProcessLimit);
        Assert.True(facts.JailRemoved);
        Assert.Contains("jail: drained and removed", facts.TeardownOrder);
        Assert.Equal(0u, facts.ProcessesLeftAtTeardown);
    }

    /// <summary>
    /// A daemon that refuses the lease - here for a policy it cannot enforce - ends the mission as a
    /// tool failure with the refusal in the transcript, no analysis, and a record that says nothing
    /// about a workspace or a cgroup it never saw.
    /// </summary>
    [Fact]
    public async Task ALeaseTheDaemonRefuses_FailsTheMissionHonestly_AndRecordsNoContainmentItDidNotGet()
    {
        var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "linux-guest-identity");

        const string refusal = "{\"type\":\"STDERR\",\"data\":\"SPLAT refused the request: this daemon does not enforce readOnlyFs.\\n\"}";
        const string exit = "{\"type\":\"EXIT\",\"exitCode\":-1}";

        var (chunks, facts, request) = await RunAsync(template, new[] { refusal, exit });

        Assert.NotNull(request);
        Assert.Equal("ToolFailed", facts.ExecutionState);
        Assert.False(facts.ExitContractMet);
        Assert.Equal(-1, facts.ExitCode);
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.AiToken);
        Assert.Contains(chunks, c => c.ChunkType == MissionChunkType.Stderr && c.Content.Contains("SPLAT refused the request", StringComparison.Ordinal));
        Assert.DoesNotContain(facts.AppliedControls, c => c.StartsWith("lease:", StringComparison.Ordinal));
        // Nothing was read back: the pre-launch read of a lease that has not run yet is the unavailable
        // readback, every field null, and no LEASE frame arrived to replace it.
        Assert.True(facts.LimitsReadBack is null or { ProcessMemoryLimitBytes: null, JobMemoryLimitBytes: null, CpuRatePercent: null, ActiveProcessLimit: null },
            "a refused lease recorded a limit nobody read back");
        Assert.Null(facts.JailRemoved);
        Assert.Contains("jail: drained; whether it remains is not recorded", facts.TeardownOrder);
    }

    [Fact]
    public async Task ARefusalAfterTheWorkspaceWasMade_RecordsThatItWentAndClaimsNothingElse()
    {
        // The daemon makes the workspace before it installs the lease, so a lease it cannot install
        // leaves a directory behind unless the refusal removes it - which three did not on 2026-09-24.
        // It now removes it and says so on EXIT without a LEASE frame, and the record must carry that
        // one fact without inventing a cgroup, a jail or a uid the daemon never reported.
        var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "linux-guest-identity");

        const string refusal = "{\"type\":\"STDERR\",\"data\":\"SPLAT refused to execute: the capability lease could not be installed (1 of 3 protected path(s) could not be resolved to an inode; refusing to register a lease that would leave them unprotected).\\n\"}";
        const string exit = "{\"type\":\"EXIT\",\"exitCode\":-1,\"workspaceRemoved\":true}";

        var (chunks, facts, request) = await RunAsync(template, new[] { refusal, exit });

        Assert.NotNull(request);
        Assert.Equal("ToolFailed", facts.ExecutionState);
        Assert.Equal(-1, facts.ExitCode);
        Assert.DoesNotContain(chunks, c => c.ChunkType == MissionChunkType.AiToken);
        Assert.DoesNotContain(facts.AppliedControls, c => c.StartsWith("lease:", StringComparison.Ordinal));
        Assert.DoesNotContain(facts.AppliedControls, c => c.StartsWith("cgroup:", StringComparison.Ordinal));
        Assert.DoesNotContain(facts.AppliedControls, c => c.StartsWith("workload:", StringComparison.Ordinal));
        Assert.Contains(facts.AppliedControls, c => c == $"workspace:{MissionsRoot}/{facts.MissionId:N} (created by the daemon, removed with the refusal)");
        Assert.True(facts.JailRemoved);
        Assert.Contains(facts.TeardownOrder, step => step.StartsWith("jail:", StringComparison.Ordinal) && step.Contains("removed", StringComparison.Ordinal));
    }

    // ------------------------------------------------------------------ the run

    private static async Task<(List<MissionChunk> Chunks, MissionRunFacts Facts, string? Request)> RunAsync(
        SingleToolTemplate template, IReadOnlyList<string> replies)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var daemon = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            return await StandInAgent.ServeAsync(stream, Token, replies);
        });

        try
        {
            var executor = new WslLeasedExecutor("127.0.0.1", port, authToken: Token, holdGuestAwake: () => new NoGuest());
            var substrate = new LinuxLeaseSubstrate(executor, new TemplatePolicyCompiler(new NoResolver()), MissionsRoot);
            var ledger = new RecordingLedger();

            var engine = new MissionExecutionEngine(
                new NeverCalledJail(),
                new NeverCalledLauncher(),
                new ScriptedModel(Answer),
                ledger,
                _ => throw new InvalidOperationException("a leased mission must not make a Windows job object"),
                semanticMemoryIndex: null,
                dlpSanitizer: new RegexDataLossPreventionSanitizer(),
                credentialSanitizer: new PromptCredentialSanitizer(),
                revocationManager: null,
                findingsExtractor: new JsonFindingsExtractor(),
                substrates: substrate);

            var chunks = new List<MissionChunk>();
            await foreach (var chunk in engine.ExecuteMissionAsync(template, new Dictionary<string, string>(), "leased-test-operator"))
            {
                chunks.Add(chunk);
            }

            var exchange = await daemon;
            return (chunks, ledger.Facts(), exchange.Request);
        }
        finally
        {
            listener.Stop();
        }
    }

    // ------------------------------------------------------------------ stand-ins

    private sealed class NoGuest : IDisposable
    {
        public void Dispose() { }
    }

    private sealed class NoResolver : IHostAddressResolver
    {
        public IPAddress[] GetHostAddresses(string hostNameOrAddress) =>
            throw new InvalidOperationException("no Linux template in these tests declares a sensor destination");
    }

    private sealed class NeverCalledJail : IJailManager
    {
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("a leased mission must not provision a Windows jail");

        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) =>
            throw new InvalidOperationException("a leased mission must not drain a Windows jail");

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);
    }

    private sealed class NeverCalledLauncher : IProcessLauncher
    {
        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false) =>
            throw new InvalidOperationException("a leased mission must not launch on Windows");
    }

    private sealed class ScriptedModel : IModelStreamClient
    {
        private readonly string _answer;
        public ScriptedModel(string answer) => _answer = answer;

        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, "Scripted", requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel, string systemPrompt, string userPrompt,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return _answer;
        }
    }

    private sealed class RecordingLedger : IAuditLedger
    {
        private readonly List<(string Action, string Details)> _rows = new();

        public MissionRunFacts Facts()
        {
            lock (_rows)
            {
                var row = _rows.LastOrDefault(r => r.Action == MissionRunFacts.LedgerAction);
                Assert.True(row.Details is not null, "the mission sealed no run facts");
                return JsonSerializer.Deserialize<MissionRunFacts>(row.Details!)!;
            }
        }

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (_rows) _rows.Add((action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }
}
