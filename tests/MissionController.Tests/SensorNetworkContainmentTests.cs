using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Proof for the Windows egress gap: a job object clamps CPU, memory, PIDs and privilege but has no
/// concept of a socket, so until AppContainer isolation landed a template that declared it only reads
/// the local machine could still open any connection it liked.
///
/// These tests are deliberately DIFFERENTIAL. Asserting only that a confined tool fails to connect
/// would stay green if the tool never launched, if PowerShell were missing, or if the machine were
/// simply offline - so every containment assertion is paired with the same command run unconfined,
/// which must succeed. A green run therefore means "the container is what stopped it", not merely
/// "something went wrong".
/// </summary>
public class SensorNetworkContainmentTests
{
    private const string PowerShellExe = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    /// <summary>
    /// Runs a probe script through the real launcher, inside a real ACL jail.
    ///
    /// The jail is genuine rather than a convenient temp folder because provisioning is part of what
    /// is under test: the jail strips ACL inheritance, so the AppContainer SID matches none of its
    /// ACEs unless NtAclJailManager grants one. Without that ACE the child cannot reach its own
    /// working directory and CreateProcess fails - which would look like "network blocked" to a test
    /// that only inspected the exit code.
    /// </summary>
    private static async Task<int> RunProbeAsync(string script, bool denyNetworkAccess)
    {
        var jailManager = new NtAclJailManager();
        string jailPath = await jailManager.ProvisionJailAsync(Guid.NewGuid());

        try
        {
            var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
            using var job = new Win32JobSandbox($"netcontain-{Guid.NewGuid():N}");

            // The probe scripts are PowerShell, so the host has to be PowerShell. Running them
            // through cmd.exe /c makes every control fail with exit 1 on a syntax error, which
            // reads identically to a launch failure and tells you nothing about containment.
            var result = await launcher.LaunchSuspendedInJobAsync(
                PowerShellExe,
                $"-NoProfile -NonInteractive -Command \"{script}\"",
                jailPath,
                job,
                dropAdminPrivileges: true,
                timeoutSeconds: 30,
                stdoutProgress: null,
                stderrProgress: null,
                cancellationToken: default,
                denyNetworkAccess: denyNetworkAccess);

            // 0xC0000142: the image could not initialise. Inside an AppContainer that means the
            // profile SID cannot read something the interpreter needs to start, so the process
            // never ran its script - a distinct outcome from a script that ran and was denied.
            if (result.ExitCode == -1073741502)
            {
                throw new InvalidOperationException(
                    $"The probe process failed to initialise (0xC0000142) with denyNetworkAccess={denyNetworkAccess}. " +
                    "Nothing about containment can be concluded: the interpreter never started.");
            }

            return result.ExitCode;
        }
        finally
        {
            await jailManager.DrainAndCleanupJailAsync(jailPath);
        }
    }

    private const int ConnectSucceeded = 0;
    private const int ConnectRefused = 9;

    /// <summary>
    /// Does THIS process have a route to the internet? Deliberately independent of the sandbox, so
    /// an offline machine and a defeated container can never be confused for one another.
    /// </summary>
    private static bool TestHostCanReachInternet()
    {
        try
        {
            using var client = new TcpClient();
            return client.ConnectAsync("1.1.1.1", 443).Wait(TimeSpan.FromSeconds(5))
                   && client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static string ConnectScript(string host, int port) =>
        $"try {{ (New-Object Net.Sockets.TcpClient).Connect('{host}',{port}); exit {ConnectSucceeded} }} catch {{ exit {ConnectRefused} }}";

    /// <summary>
    /// The load-bearing test, and the one that needs no internet: a listener inside this test process
    /// is a destination that provably exists and provably answers, so an unconfined sensor reaching it
    /// and a confined sensor failing to isolates the container as the only variable.
    /// </summary>
    [Fact]
    public async Task ContainedSensor_CannotOpenASocket_WhileTheSameCommandUnconfinedCan()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        try
        {
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            string script = ConnectScript("127.0.0.1", port);

            int unconfined = await RunProbeAsync(script, denyNetworkAccess: false);
            Assert.True(
                unconfined == ConnectSucceeded,
                $"Control failed: an UNCONFINED sensor could not reach a listener in this very process " +
                $"(exit {unconfined}). Nothing about containment can be concluded from this run.");

            int confined = await RunProbeAsync(script, denyNetworkAccess: true);
            Assert.True(
                confined == ConnectRefused,
                $"CONTAINMENT BREACH: a network-denied sensor opened a socket (exit {confined}).");
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// The egress claim proper. A raw IP is used so the result cannot be explained by DNS being
    /// unavailable inside the container - name resolution failing would block a tool that resolves a
    /// hostname while leaving one that hardcodes an address free to reach the internet.
    ///
    /// Skipped rather than failed when the host itself is offline: the control below is what tells
    /// the two apart, and a machine with no route out cannot prove or disprove containment.
    /// </summary>
    [Fact]
    public async Task ContainedSensor_CannotReachTheInternet_NotEvenByRawIpThatSkipsDns()
    {
        // Whether this machine has a route out is established INDEPENDENTLY, from the test process
        // itself, before any sandbox is involved. Inferring it from the unconfined sensor's own exit
        // code would make "the sandbox is broken" and "the network is down" indistinguishable, and
        // the test would quietly pass in both cases.
        if (!TestHostCanReachInternet())
        {
            return;
        }

        string script = ConnectScript("1.1.1.1", 443);

        int unconfined = await RunProbeAsync(script, denyNetworkAccess: false);
        Assert.True(
            unconfined == ConnectSucceeded,
            $"Control failed: this host has a route to 1.1.1.1:443 but an UNCONFINED sensor could not " +
            $"use it (exit {unconfined}). The launch path is broken, not the network.");

        int confined = await RunProbeAsync(script, denyNetworkAccess: true);
        Assert.True(
            confined == ConnectRefused,
            $"CONTAINMENT BREACH: a network-denied sensor reached 1.1.1.1:443 by raw IP (exit {confined}).");
    }

    /// <summary>
    /// Containment must not be achieved by breaking the tool. If the confined process could not run
    /// at all, every connection test above would pass for the wrong reason.
    /// </summary>
    [Fact]
    public async Task ContainedSensor_StillExecutesAndReportsItsExitCode()
    {
        int exitCode = await RunProbeAsync("exit 42", denyNetworkAccess: true);
        Assert.Equal(42, exitCode);
    }

    /// <summary>
    /// The catalogue-wide claim, asserted rather than promised in prose: a template is contained
    /// unless it explicitly declares that its SENSOR opens the destination. Fails if a future
    /// template quietly widens its scope, which is the drift this gate exists to prevent.
    /// </summary>
    [Fact]
    public void OnlyTemplatesThatDeclareASensorDestination_AreExemptFromNetworkDenial()
    {
        var reaching = GovernedTemplateCatalog.All
            .Where(t => t.EgressRule.ToolProcessNeedsNetwork)
            .ToList();

        Assert.All(reaching, t => Assert.Equal("api.grants.gov", t.EgressRule.AllowedFqdn));

        // Every other template in the catalogue is launched with no network stack whatsoever.
        var contained = GovernedTemplateCatalog.All.Except(reaching).ToList();
        Assert.NotEmpty(contained);
        Assert.All(contained, t => Assert.Equal(EgressScope.ModelGateway, t.EgressRule.Scope));
    }

    /// <summary>
    /// The same conflation on the Linux substrate. Every template carries an EgressRule, and the
    /// default one names the AI gateway that SPLAT's own process calls - so reading the FQDN alone
    /// opened a kernel network lease for the entire catalogue when almost no sensor needs one.
    /// </summary>
    [Fact]
    public void PolicyCompiler_LeavesTheNetworkClosed_ForASensorThatDeclaresNoDestination()
    {
        var compiler = new TemplatePolicyCompiler();
        var gatewayOnly = GovernedTemplateCatalog.All.First(t => !t.EgressRule.ToolProcessNeedsNetwork);

        var lease = compiler.CompileTemplatePolicy(gatewayOnly, Guid.NewGuid(), "/tmp/splat-test");

        Assert.False(lease.AllowNetwork);
        Assert.Empty(lease.AllowedEgressIps);
    }

    /// <summary>
    /// The complement: a declared sensor destination must still compile to a real lease, or the fix
    /// above would have been achieved by closing the network for everyone.
    /// </summary>
    [Fact]
    public void PolicyCompiler_StillPinsTheDestination_ForASensorThatDeclaresOne()
    {
        var compiler = new TemplatePolicyCompiler();
        var reaching = GovernedTemplateCatalog.All.First(t => t.EgressRule.ToolProcessNeedsNetwork);

        var lease = compiler.CompileTemplatePolicy(reaching, Guid.NewGuid(), "/tmp/splat-test");

        Assert.True(lease.AllowNetwork);
        Assert.Contains(443u, lease.AllowedEgressPorts);
    }

    /// <summary>
    /// The cost of containment, measured rather than assumed. The AppContainer that removes the
    /// network is also an RPC wall, so WMI stops answering inside it - which is why templates built
    /// on WMI are exempted instead of contained. Asserting it here keeps that exemption honest: if a
    /// future Windows admits AppContainers to WMI, this test fails and the exemption can be dropped.
    /// </summary>
    [Fact]
    public async Task Containment_AlsoBlocksWmi_WhichIsWhyWmiTemplatesAreExempt()
    {
        const string wmiProbe = "try { Get-CimInstance Win32_OperatingSystem -EA Stop | Out-Null; exit 0 } catch { exit 72 }";

        int unconfined = await RunProbeAsync(wmiProbe, denyNetworkAccess: false);
        Assert.True(unconfined == 0, $"Control failed: WMI is unavailable even unconfined (exit {unconfined}).");

        int confined = await RunProbeAsync(wmiProbe, denyNetworkAccess: true);
        Assert.Equal(72, confined);
    }

    /// <summary>
    /// The exemption applied to the catalogue. A sensor that reads the event log, WMI or Defender
    /// keeps its network stack because the alternative is a tool that cannot do its job - and a
    /// silently broken sensor is worse than an uncontained one, since the operator sees only a
    /// confusing error while the mission reports success at containing it.
    /// </summary>
    [Fact]
    public void TemplatesBuiltOnLocalSubsystems_AreExemptFromContainment()
    {
        var exempt = GovernedTemplateCatalog.All.Where(t => t.ToolNeedsLocalSubsystems).ToList();

        // The catalogue is heavily WMI- and event-log-based; an empty set here means the marker
        // list stopped matching and every one of those templates is about to break at run time.
        Assert.NotEmpty(exempt);

        var stillContained = GovernedTemplateCatalog.All
            .Where(t => !t.EgressRule.ToolProcessNeedsNetwork && !t.ToolNeedsLocalSubsystems)
            .ToList();

        Assert.NotEmpty(stillContained);
        Assert.All(stillContained, t => Assert.DoesNotContain("Get-CimInstance", t.Tool.ArgumentsTemplate));
    }

    /// <summary>
    /// The container identity has to resolve on this machine, because the launcher REFUSES to run a
    /// network-denied template when it cannot - so a broken profile would take the catalogue down
    /// rather than quietly downgrade containment.
    /// </summary>
    [Fact]
    public void SensorAppContainerProfile_ResolvesOnThisMachine()
    {
        bool resolved = SensorAppContainer.TryGetSid(out var sid, out string? failureReason);

        Assert.True(resolved, $"AppContainer profile could not be resolved: {failureReason}");
        Assert.NotNull(sid);
        Assert.StartsWith("S-1-15-2-", sid!.Value);
    }
}
