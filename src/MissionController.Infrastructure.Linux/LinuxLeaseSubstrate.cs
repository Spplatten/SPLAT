using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Linux;

/// <summary>
/// Runs a governed mission's tool under the Linux capability lease instead of the Windows sensor sandbox.
///
/// Until 2026-09-24 the only route into the daemon was <c>run_command</c> from an outside agent: the
/// product's own specialists ran on Windows, and its thesis - that its agents run under the lease -
/// was true of nobody's agents but a visitor's. This is the missing route. The mission engine asks
/// this selector for every template; one whose tool names <see cref="ToolSubstrate.LinuxLease"/> gets a
/// jail, a job and a launcher that are the lease: the workspace the daemon creates for the mission, the
/// cgroup it clamps, and one <c>EXECUTE_TOOL</c> whose policy is compiled from the template. Everything
/// around the tool - the scrub, the judge, the ledger, the run record - is the engine's, unchanged.
///
/// The lease is authored by <see cref="ITemplatePolicyCompiler"/> from the template alone: the executable
/// is the one allow-listed path, egress is the template's declared sensor destination or nothing, and
/// the clamps are the tool's. The request is not its own authorization here any more than it is for
/// <c>run_command</c>; the ceiling in the guest still bounds all of it.
/// </summary>
public sealed class LinuxLeaseSubstrate : IMissionSubstrateSelector
{
    /// <summary>The substrate's name, as the run facts and the record carry it.</summary>
    public const string SubstrateName = "Linux lease";

    /// <summary>Where the daemon makes each mission's workspace, unless the host names another root.</summary>
    public const string DefaultMissionsRoot = "/var/lib/splat/missions";

    private readonly ILeasedExecutor _executor;
    private readonly ITemplatePolicyCompiler _compiler;
    private readonly string _missionsRoot;

    public LinuxLeaseSubstrate(ILeasedExecutor executor, ITemplatePolicyCompiler compiler, string missionsRoot = DefaultMissionsRoot)
    {
        _executor = executor ?? throw new ArgumentNullException(nameof(executor));
        _compiler = compiler ?? throw new ArgumentNullException(nameof(compiler));
        _missionsRoot = string.IsNullOrWhiteSpace(missionsRoot) ? DefaultMissionsRoot : missionsRoot.TrimEnd('/');
    }

    public MissionSubstrate? For(SingleToolTemplate template, Guid missionId)
    {
        if (template.Tool.Substrate != ToolSubstrate.LinuxLease)
        {
            return null;
        }

        var mission = new LeasedMission(_executor, _compiler, template, missionId, _missionsRoot);
        return new MissionSubstrate(SubstrateName, mission, _ => mission.Sandbox, mission);
    }

    /// <summary>
    /// One mission's jail, job and launcher, which under the lease are one thing: the daemon makes the
    /// workspace, clamps the cgroup and runs the tool in a single request, so one object plays all three
    /// roles and what it learns from the daemon's frames is what each role reports.
    /// </summary>
    internal sealed class LeasedMission : IJailManager, IProcessLauncher
    {
        private readonly ILeasedExecutor _executor;
        private readonly ITemplatePolicyCompiler _compiler;
        private readonly SingleToolTemplate _template;
        private readonly Guid _missionId;
        private readonly string _missionsRoot;
        private LeaseOutcome? _outcome;

        public LeasedMission(ILeasedExecutor executor, ITemplatePolicyCompiler compiler, SingleToolTemplate template, Guid missionId, string missionsRoot)
        {
            _executor = executor;
            _compiler = compiler;
            _template = template;
            _missionId = missionId;
            _missionsRoot = missionsRoot;
            Sandbox = new LeaseCgroupSandbox(missionId);
        }

        public LeaseCgroupSandbox Sandbox { get; }

        // ---------------------------------------------------------------- the jail

        /// <summary>
        /// The mission's workspace: a guest path under the missions root, which the daemon creates for the
        /// lease and removes with it. Nothing exists yet; the daemon's frames say when it does.
        /// </summary>
        public Task<string> ProvisionJailAsync(Guid missionId, CancellationToken cancellationToken = default) =>
            Task.FromResult($"{_missionsRoot}/{missionId:N}");

        /// <summary>The daemon removes the workspace when the lease ends; there is nothing for this side to drain.</summary>
        public Task DrainAndCleanupJailAsync(string jailPath, int maxRetries = 5, int retryDelayMs = 200) => Task.CompletedTask;

        public Task<int> SweepOrphanJailsAsync(CancellationToken cancellationToken = default) => Task.FromResult(0);

        /// <summary>Nothing is read back before the lease runs; the LEASE frame is the readback, and it lands in the applied controls.</summary>
        public string? DescribeJail(string jailPath) => null;

        /// <summary>What the daemon said at EXIT, or nothing when it said nothing.</summary>
        public bool? IsJailRemoved(string jailPath) => _outcome?.WorkspaceRemoved;

        // ---------------------------------------------------------------- the launcher

        public async Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable,
            string arguments,
            string workingDirectory,
            IJobSandbox jobSandbox,
            bool dropAdminPrivileges,
            int timeoutSeconds,
            IProgress<string>? stdoutProgress = null,
            IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default,
            bool denyNetworkAccess = false)
        {
            // Split where the text is intact, as run_command does: the daemon takes argv, never a string.
            IReadOnlyList<string> argv = PosixArgumentSplitter.Split(arguments);

            LeaseSpec lease = _compiler.CompileTemplatePolicy(_template, _missionId, workingDirectory, (uint)Math.Max(5, timeoutSeconds));

            // The engine's decision about the network is final, and the lease can only be narrower than
            // the compiler's: a template with no sensor destination gets no addresses at all.
            if (denyNetworkAccess)
            {
                lease = lease with { AllowNetwork = false, AllowedEgressIps = Array.Empty<string>(), AllowedEgressPorts = Array.Empty<uint>() };
            }

            lease = lease with
            {
                Limits = Sandbox.RequestedLimits(lease.Limits),
                EphemeralWorkspace = true,
            };

            argv = LeaseEgressArguments.Append(_template.Tool, lease, argv);

            var violations = new BoundedViolationLog();
            var collect = new SynchronousProgress<LeaseViolationEvent>(violations.Add);

            ProcessExecutionResult result = await _executor.ExecuteLeasedAsync(
                lease,
                _template.Tool.ExecutablePath,
                argv,
                stdoutProgress,
                stderrProgress,
                collect,
                cancellationToken);

            _outcome = result.Lease;
            Sandbox.Learn(result);

            // The kernel's refusals belong in the transcript the findings are grounded against, not only
            // in the live stream: a sensor that was refused something said so, and the model and the
            // record both need to read it.
            string stderr = result.StandardError;
            if (violations.Total > 0)
            {
                var sb = new StringBuilder(stderr);
                if (sb.Length > 0 && !stderr.EndsWith('\n')) sb.Append('\n');
                foreach (var v in violations.Retained.OrderBy(v => v.Sequence))
                {
                    sb.Append("[KERNEL -EPERM BLOCK] [").Append(v.ProcessComm).Append(" pid ").Append(v.ProcessId).Append("] ")
                      .Append(v.Hook).Append(' ').Append(v.DetailText).Append('\n');
                }

                if (violations.OmittedNote is { } omitted)
                    sb.Append(omitted).Append('\n');
                stderr = sb.ToString();
            }

            return result with
            {
                StandardError = stderr,
                AppliedControls = AppliedControls(result),
            };
        }

        /// <summary>
        /// What the daemon reported, in the vocabulary the run record reads. The vocabulary itself lives
        /// in <see cref="LeaseControls"/>, shared with the MCP lease tools, because the assembler matches
        /// these strings exactly and two copies of them drift apart silently.
        /// </summary>
        private static IReadOnlyList<string>? AppliedControls(ProcessExecutionResult result) =>
            LeaseControls.Describe(result.Lease, result.AppliedControls);
    }

    /// <summary>
    /// The lease's cgroup, seen from the host. Limits are configured here as the engine configures a job
    /// object, sent in the lease, and read back only from what the daemon reports its controllers took.
    /// </summary>
    internal sealed class LeaseCgroupSandbox : IJobSandbox
    {
        private readonly Guid _missionId;
        private long _maxMemoryBytes;
        private int _maxCpuPercent;
        private JobLimitsReadback? _readBack;
        private uint? _leftAtExit;
        private string? _cgroupPath;

        public LeaseCgroupSandbox(Guid missionId) => _missionId = missionId;

        public string JobName => _cgroupPath ?? $"lease:{_missionId:N}";

        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent)
        {
            _maxMemoryBytes = maxMemoryBytes;
            _maxCpuPercent = maxCpuPercent;
        }

        /// <summary>The compiler's limits, lowered to what the engine configured where it configured anything.</summary>
        public LeaseResourceLimits RequestedLimits(LeaseResourceLimits compiled) => compiled with
        {
            MaxMemoryBytes = _maxMemoryBytes > 0 ? Math.Min(compiled.MaxMemoryBytes, (ulong)_maxMemoryBytes) : compiled.MaxMemoryBytes,
            MaxCpuPercent = _maxCpuPercent > 0 ? Math.Min(compiled.MaxCpuPercent, (uint)_maxCpuPercent) : compiled.MaxCpuPercent,
        };

        public void AssignProcess(SafeProcessHandle processHandle)
        {
            // The daemon joins the tool to its cgroup in pre_exec, before exec. Nothing to do from here.
        }

        /// <summary>
        /// Nothing measured on this side. The count of processes left is the daemon's word: a lease that
        /// ended with an EXIT frame was drained in the guest, and one that did not says nothing.
        /// </summary>
        public JobResourceMetrics GetResourceMetrics() => new(null, null, null, null, _leftAtExit);

        /// <summary>The daemon kills the cgroup when the lease ends or expires; there is no handle here to kill through.</summary>
        public void TerminateAllProcesses(uint exitCode = 1) { }

        public JobLimitsReadback ReadBackLimits() => _readBack ?? JobLimitsReadback.Unavailable;

        public void Learn(ProcessExecutionResult result)
        {
            _readBack = result.LimitsReadBack;
            _cgroupPath = result.Lease?.CgroupPath;
            _leftAtExit = result.TerminalReason == "ExplicitExit" ? 0u : null;
        }

        public void Dispose() { }
    }

    private sealed class SynchronousProgress<T> : IProgress<T>
    {
        private readonly Action<T> _handler;
        public SynchronousProgress(Action<T> handler) => _handler = handler;
        public void Report(T value) => _handler(value);
    }
}
