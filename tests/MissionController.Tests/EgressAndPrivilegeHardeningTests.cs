using System;
using System.Net.Http;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Network.Egress;
using MissionController.Infrastructure.Network.Siem;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Regression guards for two controls that used to degrade silently: the Layer-4 egress firewall
/// (which only inspected traffic when a caller remembered to arm it) and the restricted-token
/// sandbox (which fell back to a full-privilege launch when the drop failed).
/// </summary>
public class EgressAndPrivilegeHardeningTests
{
    /// <summary>Terminates the handler chain so nothing actually leaves the machine.</summary>
    private sealed class SinkHandler : HttpMessageHandler
    {
        public bool WasReached;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            WasReached = true;
            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK));
        }
    }

    private static (HttpClient Client, EgressFirewallHandler Firewall, SinkHandler Sink) BuildPipeline()
    {
        var sink = new SinkHandler();
        var firewall = new EgressFirewallHandler { InnerHandler = sink };
        return (new HttpClient(firewall), firewall, sink);
    }

    // ---------------------------------------------------------------- egress firewall

    [Fact]
    public async Task UnarmedRequest_IsBlocked_RatherThanSilentlyAllowed()
    {
        var (client, _, sink) = BuildPipeline();

        var ex = await Assert.ThrowsAsync<SecurityException>(
            () => client.GetAsync("https://evil.example.com/exfil"));

        Assert.Contains("no egress policy is active", ex.Message);
        // The decisive assertion: the request never reached the transport.
        Assert.False(sink.WasReached);
    }

    [Fact]
    public async Task ArmedScope_AllowsTheDeclaredHost_AndBlocksEveryOther()
    {
        var (client, firewall, sink) = BuildPipeline();

        using (firewall.BeginScope("api.anthropic.com"))
        {
            var response = await client.GetAsync("https://api.anthropic.com/v1/messages");
            Assert.True(response.IsSuccessStatusCode);
            Assert.True(sink.WasReached);

            await Assert.ThrowsAsync<SecurityException>(
                () => client.GetAsync("https://api.anthropic.com.evil.example.com/v1/messages"));
        }
    }

    [Fact]
    public async Task Scope_RestoresPreviousPolicyOnDispose_SoAStaleHostCannotLeak()
    {
        var (client, firewall, _) = BuildPipeline();

        using (firewall.BeginScope("api.anthropic.com"))
        {
            using (firewall.BeginScope("generativelanguage.googleapis.com"))
            {
                await client.GetAsync("https://generativelanguage.googleapis.com/v1beta/models");
            }

            // Inner scope closed - the outer policy must be back in force, not the inner one.
            await Assert.ThrowsAsync<SecurityException>(
                () => client.GetAsync("https://generativelanguage.googleapis.com/v1beta/models"));
            var ok = await client.GetAsync("https://api.anthropic.com/v1/messages");
            Assert.True(ok.IsSuccessStatusCode);
        }

        // Outermost scope closed - back to deny-by-default.
        await Assert.ThrowsAsync<SecurityException>(
            () => client.GetAsync("https://api.anthropic.com/v1/messages"));
    }

    // ---------------------------------------------------------------- sentinel host pinning

    [Theory]
    [InlineData("contoso.attacker.example.com/api/logs?x=")]
    [InlineData("evil.example.com#")]
    [InlineData("workspace@attacker.example.com")]
    [InlineData("not-a-guid")]
    [InlineData("")]
    public void SentinelWorkspaceId_ThatCouldRedirectAuditRecords_IsRejected(string workspaceId)
    {
        // Audit records are the most sensitive payload this app transmits; the workspace id is
        // operator-supplied and lands directly in the hostname.
        Assert.Throws<SecurityException>(() => SiemForwarder.BuildSentinelHost(workspaceId));
    }

    [Fact]
    public void SentinelWorkspaceId_ThatIsAGuid_BuildsTheAzureIngestionHost()
    {
        string workspaceId = Guid.NewGuid().ToString();

        string host = SiemForwarder.BuildSentinelHost(workspaceId);

        Assert.Equal($"{workspaceId}.ods.opinsights.azure.com", host);
        Assert.EndsWith(".ods.opinsights.azure.com", host);
    }

    // ---------------------------------------------------------------- privilege drop

    private sealed class FailingTokenProvider : MissionController.Core.Interfaces.IRestrictedTokenProvider
    {
        public IntPtr CreateLowPrivilegeToken() =>
            throw new InvalidOperationException("CreateRestrictedToken failed (simulated)");
    }

    [Fact]
    public async Task PrivilegeDropFailure_RefusesToLaunch_InsteadOfRunningWithFullToken()
    {
        var launcher = new SuspendedProcessLauncher(new FailingTokenProvider());
        using var job = new Win32JobSandbox("privdrop-test");

        var ex = await Assert.ThrowsAsync<SecurityException>(() => launcher.LaunchSuspendedInJobAsync(
            @"C:\Windows\System32\cmd.exe",
            "/c echo this must not run",
            Environment.CurrentDirectory,
            job,
            dropAdminPrivileges: true,
            timeoutSeconds: 10));

        Assert.Contains("was NOT launched", ex.Message);
    }

    /// <summary>
    /// Proves the real restricted-token sandbox actually functions here. This matters because
    /// RequiresRestrictedToken defaults to true on every tool definition: if CreateProcessAsUserW
    /// could not work on this platform, the fail-closed behaviour above would break every mission -
    /// and the old silent fallback would have meant the sandbox was never engaged in the first place.
    /// </summary>
    [Fact]
    public async Task RestrictedTokenLaunch_ActuallyWorks_SoFailClosedIsSafe()
    {
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        using var job = new Win32JobSandbox("privdrop-live-test");

        var result = await launcher.LaunchSuspendedInJobAsync(
            @"C:\Windows\System32\cmd.exe",
            "/c echo sandboxed",
            Environment.CurrentDirectory,
            job,
            dropAdminPrivileges: true,
            timeoutSeconds: 20);

        Assert.Equal(0, result.ExitCode);
        Assert.Contains("sandboxed", result.StandardOutput);
    }

    /// <summary>
    /// whoami is invoked by ABSOLUTE path on purpose. <c>cmd /c whoami</c> resolves through PATH,
    /// and on any machine with Git for Windows installed that finds the GNU coreutils
    /// <c>whoami</c> first, which rejects <c>/priv</c> as an operand and exits 1 - a green
    /// implementation failing on a toolchain accident. It is also a live demonstration of the
    /// bare-name resolution hazard this suite exists to guard.
    /// </summary>
    private static async Task<string> WhoAmIInsideSandbox(string switchArg, bool dropAdminPrivileges = true)
    {
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        using var job = new Win32JobSandbox($"privdrop-proof-{Guid.NewGuid():N}");

        var result = await launcher.LaunchSuspendedInJobAsync(
            @"C:\Windows\System32\cmd.exe",
            $@"/c C:\Windows\System32\whoami.exe {switchArg}",
            Environment.CurrentDirectory,
            job,
            dropAdminPrivileges,
            timeoutSeconds: 20);

        Assert.Equal(0, result.ExitCode);
        return result.StandardOutput;
    }

    /// <summary>
    /// Proves the restricted token actually REDUCES authority, not merely that a process launches.
    /// The launch test above passes for ANY token - including a full-privilege one - so on its own it
    /// cannot catch a sandbox that silently stopped stripping privilege (the exact failure mode the
    /// fail-closed guard exists for).
    /// </summary>
    [Fact]
    public async Task RestrictedTokenLaunch_ActuallyStripsPrivileges_NotJustLaunches()
    {
        string restricted = await WhoAmIInsideSandbox("/priv");

        // SeChangeNotifyPrivilege is the one privilege DISABLE_MAX_PRIVILEGE preserves; its presence
        // confirms whoami actually enumerated this token's privileges.
        Assert.Contains("SeChangeNotifyPrivilege", restricted);

        // Present in the baseline user token - elevated or not - and removed by the privilege strip.
        Assert.DoesNotContain("SeTimeZonePrivilege", restricted);
        Assert.DoesNotContain("SeShutdownPrivilege", restricted);
    }

    /// <summary>
    /// The privilege strip above is only half the claim. DISABLE_MAX_PRIVILEGE does not touch group
    /// SIDs or the integrity level, so the README's "Administrators SID (S-1-5-32-544) removed from
    /// the token" and the Medium-integrity drop are separate calls that have to be asserted
    /// separately - for a long time the comments described both and neither existed.
    ///
    /// Honest limit: on a NON-elevated host the parent token is already UAC-filtered, so both
    /// properties would hold even if the code did nothing. This is therefore a regression guard on
    /// the token's end state - the assertion that bites is on an elevated host, which is exactly the
    /// configuration where a SecOps operator runs this product and where the drop actually matters.
    /// </summary>
    [Fact]
    public async Task RestrictedTokenLaunch_DeniesAdministratorsAndRunsAtMediumIntegrity()
    {
        string groups = await WhoAmIInsideSandbox("/groups");

        int adminLine = groups.IndexOf("S-1-5-32-544", StringComparison.OrdinalIgnoreCase);
        Assert.True(adminLine >= 0, "whoami did not report the Administrators alias at all.");

        // "Group used for deny only" must appear on the Administrators row itself, not merely
        // somewhere in the output - S-1-5-114 carries the same attribute and would mask a regression.
        int lineEnd = groups.IndexOf('\n', adminLine);
        string administratorsRow = lineEnd < 0 ? groups[adminLine..] : groups[adminLine..lineEnd];
        Assert.Contains("deny only", administratorsRow, StringComparison.OrdinalIgnoreCase);

        // S-1-16-8192 is Medium. High (S-1-16-12288) or System (S-1-16-16384) means the drop failed.
        Assert.Contains("S-1-16-8192", groups);
        Assert.DoesNotContain("S-1-16-12288", groups);
        Assert.DoesNotContain("S-1-16-16384", groups);
    }

    // ---------------------------------------------------------------------------------------------
    // Job Object containment. The flags below are read back out of the live kernel object rather
    // than asserted against the C# constant, because the property under test is what Windows was
    // actually told - a SetInformationJobObject call that silently failed would still leave the
    // source looking correct.
    // ---------------------------------------------------------------------------------------------

    private const uint LIMIT_BREAKAWAY_OK = 0x00000800;
    private const uint LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;
    private const uint LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const uint LIMIT_ACTIVE_PROCESS = 0x00000008;
    private const uint LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400;

    /// <summary>
    /// SILENT_BREAKAWAY_OK detaches a job member's children from the job with no opt-in from the
    /// child, so every clamp and TerminateJobObject stopped at the first process: one Start-Process
    /// and the workload was outside containment and outliving the mission. If either breakaway flag
    /// ever comes back, this fails.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void JobSandbox_NeverPermitsBreakaway_SoChildrenCannotLeaveContainment(bool withExplicitLimits)
    {
        using var job = new Win32JobSandbox($"breakaway-guard-{Guid.NewGuid():N}");
        if (withExplicitLimits)
        {
            // ConfigureExtendedLimits REPLACES LimitFlags, so it must re-arm containment itself.
            job.ConfigureExtendedLimits(64L * 1024 * 1024, 50);
        }

        uint limitFlags = ReadJobLimitFlags(job);

        Assert.Equal(0u, limitFlags & LIMIT_BREAKAWAY_OK);
        Assert.Equal(0u, limitFlags & LIMIT_SILENT_BREAKAWAY_OK);
        Assert.NotEqual(0u, limitFlags & LIMIT_KILL_ON_JOB_CLOSE);
        Assert.NotEqual(0u, limitFlags & LIMIT_ACTIVE_PROCESS);
        Assert.NotEqual(0u, limitFlags & LIMIT_DIE_ON_UNHANDLED_EXCEPTION);
    }

    /// <summary>
    /// Metrics must describe what was measured. The old positional construction was misaligned
    /// against JobResourceMetrics - ActiveProcesses landed in PeakMemoryBytes and the two real tail
    /// fields were hardcoded 0 - so a process count was reported to the ledger as a memory figure.
    /// </summary>
    [Fact]
    public async Task JobMetrics_ReportCpuAsCpu_AndLeaveUnmeasuredMemoryNull()
    {
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        using var job = new Win32JobSandbox($"metrics-shape-{Guid.NewGuid():N}");

        var result = await launcher.LaunchSuspendedInJobAsync(
            @"C:\Windows\System32\cmd.exe",
            "/c echo metrics",
            Environment.CurrentDirectory,
            job,
            dropAdminPrivileges: false,
            timeoutSeconds: 20);

        var metrics = result.FinalMetrics;

        // BasicAndIoAccounting carries CPU and process counts, so these are real measurements.
        Assert.NotNull(metrics.TotalCpuKernelTimeMs);
        Assert.NotNull(metrics.TotalCpuUserTimeMs);
        Assert.NotNull(metrics.ActiveProcessCount);
        Assert.True(metrics.TotalCpuKernelTimeMs >= 0);

        // It carries no memory figures, so they stay null. Null means "not measured", never zero.
        Assert.Null(metrics.PeakMemoryBytes);
        Assert.Null(metrics.CurrentMemoryBytes);
    }

    /// <summary>
    /// The Linux substrate's daemon frame carries no cgroup accounting. It used to answer with
    /// MaxMemoryBytes/4 as peak memory and half the wall clock as each CPU figure - arithmetic on
    /// constants, surfaced as observed telemetry and sealed into the ledger as evidence.
    /// </summary>
    [Fact]
    public async Task LeasedExecutor_WithNoDaemon_ReportsUnavailableMetrics_NotInventedOnes()
    {
        // Port 1 has no listener; the executor's transport-failure path is what is under test.
        var executor = new MissionController.Infrastructure.Linux.WslLeasedExecutor("127.0.0.1", 1);
        var lease = new LeaseSpec(
            MissionId: Guid.NewGuid(),
            WorkingDirectory: "/tmp",
            AllowNetwork: false,
            AllowedEgressIps: Array.Empty<string>(),
            AllowedEgressPorts: Array.Empty<uint>(),
            ReadOnlyFs: true,
            ProtectedInodes: Array.Empty<InodeIdentifierModel>(),
            AllowedExecInodes: Array.Empty<InodeIdentifierModel>(),
            LeaseDurationSeconds: 5,
            Limits: new LeaseResourceLimits(256L * 1024 * 1024, 50, 100));

        var result = await executor.ExecuteLeasedAsync(lease, "/bin/true", Array.Empty<string>());

        Assert.Null(result.FinalMetrics.PeakMemoryBytes);
        Assert.Null(result.FinalMetrics.TotalCpuKernelTimeMs);
        Assert.Null(result.FinalMetrics.TotalCpuUserTimeMs);
        Assert.Null(result.FinalMetrics.ActiveProcessCount);

        // Specifically NOT a quarter of the configured cap, which is what it used to answer.
        Assert.NotEqual(64L * 1024 * 1024, result.FinalMetrics.PeakMemoryBytes);
    }

    /// <summary>
    /// Redirects are followed inside SocketsHttpHandler, which sits BELOW the firewall in the
    /// pipeline - so a 302 off an approved FQDN never re-entered EgressFirewallHandler.SendAsync and
    /// the allow-list held for the first request only.
    /// </summary>
    [Fact]
    public void HardenedClient_DoesNotFollowRedirects_SoTheAllowListCannotBeStepped()
    {
        var (_, firewall) = MissionController.Infrastructure.Network.Http
            .HardenedHttpClientFactory.CreateHardenedClient();

        var innerProperty = typeof(DelegatingHandler).GetProperty(
            "InnerHandler",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Public |
            System.Reflection.BindingFlags.NonPublic);

        var inner = Assert.IsType<SocketsHttpHandler>(innerProperty!.GetValue(firewall));
        Assert.False(inner.AllowAutoRedirect);
    }

    private static uint ReadJobLimitFlags(Win32JobSandbox job)
    {
        var handleField = typeof(Win32JobSandbox).GetField(
            "_jobHandle",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        IntPtr handle = (IntPtr)handleField!.GetValue(job)!;

        int size = System.Runtime.InteropServices.Marshal.SizeOf<JobObjectExtendedLimitInformation>();
        IntPtr buffer = System.Runtime.InteropServices.Marshal.AllocHGlobal(size);
        try
        {
            Assert.True(
                QueryInformationJobObject(handle, 9 /* JobObjectExtendedLimitInformation */, buffer, (uint)size, out _),
                "QueryInformationJobObject failed; the job's limits could not be read back.");

            return System.Runtime.InteropServices.Marshal
                .PtrToStructure<JobObjectExtendedLimitInformation>(buffer)
                .BasicLimitInformation.LimitFlags;
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);
        }
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    private static extern bool QueryInformationJobObject(
        IntPtr hJob, int infoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength, out uint lpReturnLength);
}
