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
                timeoutSeconds: ProbeTimeoutSeconds,
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

            // Killed by the launcher, so the script never reached either exit. Reported as a breach
            // instead, this read "opened a socket" on an elevated run whose probe had connected to nothing.
            if (result.TimedOut)
            {
                throw new InvalidOperationException(
                    $"The probe was killed at the {ProbeTimeoutSeconds} s launch timeout with denyNetworkAccess={denyNetworkAccess}. " +
                    "Nothing about containment can be concluded: the script never finished.");
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

    /// <summary>
    /// Waits out OS timeouts inside the container: a denied WMI call and TCP's own retransmissions both
    /// run about 20 s, and an elevated interpreter starts slower - 29.3 s and 30.8 s against the old 30.
    /// </summary>
    private const int ProbeTimeoutSeconds = 90;

    /// <summary>
    /// The container drops a denied SYN rather than refusing it, so an unbounded Connect waits out
    /// TCP's retransmissions. Both controls connect in milliseconds - one to a listener in this very
    /// process - so a connection still pending after this long has been denied, not delayed.
    /// </summary>
    private const int ConnectBudgetMs = 5000;

    /// <summary>Only a connection is a breach; any other exit is a probe that proved nothing either way.</summary>
    private static string BreachOrNothing(int confined, string breach) => confined == ConnectSucceeded
        ? "CONTAINMENT BREACH: " + breach
        : $"The network-denied sensor exited {confined}, neither connecting nor refused. Nothing about containment can be concluded.";

    // Wait throws for a refused connection and returns false for a dropped one; both are the denial.
    private static string ConnectScript(string host, int port) =>
        $"try {{ if ((New-Object Net.Sockets.TcpClient).ConnectAsync('{host}',{port}).Wait({ConnectBudgetMs})) {{ exit {ConnectSucceeded} }} exit {ConnectRefused} }} catch {{ exit {ConnectRefused} }}";

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
                BreachOrNothing(confined, "a network-denied sensor connected to a listener in this very process."));
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
    /// A missing positive control fails this proof as unproven: an offline host cannot certify denial.
    /// </summary>
    [Fact]
    public async Task ContainedSensor_CannotReachTheInternet_NotEvenByRawIpThatSkipsDns()
    {
        // Whether this machine has a route out is established INDEPENDENTLY, from the test process
        // itself, before any sandbox is involved. Inferring it from the unconfined sensor's own exit
        // code would make "the sandbox is broken" and "the network is down" indistinguishable, and
        // the test would quietly pass in both cases.
        Assert.True(TestHostCanReachInternet(),
            "UNPROVEN: no host Internet positive control; this run cannot certify Internet denial.");

        string script = ConnectScript("1.1.1.1", 443);

        int unconfined = await RunProbeAsync(script, denyNetworkAccess: false);
        Assert.True(
            unconfined == ConnectSucceeded,
            $"Control failed: this host has a route to 1.1.1.1:443 but an UNCONFINED sensor could not " +
            $"use it (exit {unconfined}). The launch path is broken, not the network.");

        int confined = await RunProbeAsync(script, denyNetworkAccess: true);
        Assert.True(
            confined == ConnectRefused,
            BreachOrNothing(confined, "a network-denied sensor reached 1.1.1.1:443 by raw IP."));
    }

    private const int Resolved = 0;
    private const int NotResolved = 9;

    /// <summary>
    /// The name channel. A process that resolves a hostname does not send the query itself: the DNS
    /// Client service does, from svchost, on its behalf. The operator's threat-model note of
    /// 2026-09-22 asked whether that carries a model-chosen name out of a network-denied tool. It
    /// does not - the service refuses a container with no capabilities - and this holds that answer,
    /// because the roadmap's WFP candidate would lose it: a filter keyed to the tool's SID never sees
    /// the service's query.
    ///
    /// Each lookup is a fresh label under a public wildcard domain, so nothing can answer from a
    /// cache and a resolved name proves the query left. The confined label is then looked for in the
    /// DNS Client service's own cache beside the control's, which tells "refused before it left"
    /// apart from "sent, and the answer withheld" - the second would still leak the name.
    /// </summary>
    [Fact]
    public async Task ContainedSensor_CannotResolveAName_NotEvenThroughTheDnsClientService()
    {
        static string FreshName() => $"splat{Guid.NewGuid():N}.192.0.2.1.nip.io";
        static string LookupScript(string name) =>
            $"try {{ [Net.Dns]::GetHostAddresses('{name}') | Out-Null; exit {Resolved} }} catch {{ exit {NotResolved} }}";

        Assert.True(TestHostCanReachInternet() && HostResolves(FreshName()),
            "UNPROVEN: DNS positive control unavailable; this run cannot certify DNS-service containment.");

        string open = FreshName();
        int unconfined = await RunProbeAsync(LookupScript(open), denyNetworkAccess: false);
        Assert.True(
            unconfined == Resolved,
            $"Control failed: this host resolves the wildcard domain but an UNCONFINED sensor could not " +
            $"(exit {unconfined}). The launch path is broken, not the network.");

        string denied = FreshName();
        int confined = await RunProbeAsync(LookupScript(denied), denyNetworkAccess: true);
        Assert.True(
            confined == NotResolved,
            confined == Resolved
                ? "CONTAINMENT BREACH: a network-denied sensor resolved a name it chose."
                : $"The network-denied sensor exited {confined}, neither resolving nor refused. Nothing about containment can be concluded.");

        string? cache = ResolverCache();
        Assert.True(cache is not null,
            "UNPROVEN: DNS Client cache is unavailable. Resolution refusal alone does not prove the query never left.");

        Assert.True(cache.Contains(open, StringComparison.OrdinalIgnoreCase),
            "Control failed: the unconfined lookup is not in the DNS Client cache, so the cache cannot say where the confined one went.");
        Assert.False(cache.Contains(denied, StringComparison.OrdinalIgnoreCase),
            "CONTAINMENT BREACH: the network-denied sensor's name reached the DNS Client service's cache, so the query left even though the answer was withheld.");
    }

    private static bool HostResolves(string name)
    {
        try
        {
            return Dns.GetHostAddresses(name).Length > 0;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private static string? ResolverCache()
    {
        var psi = new System.Diagnostics.ProcessStartInfo(@"C:\Windows\System32\ipconfig.exe", "/displaydns")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true
        };
        using var ipconfig = System.Diagnostics.Process.Start(psi)!;
        string text = ipconfig.StandardOutput.ReadToEnd();
        ipconfig.WaitForExit();
        return ipconfig.ExitCode == 0 ? text : null;
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

        // Eight destinations, each declared by a template whose script names it literally. The
        // assertion is the set rather than a count: a template that acquires a network stack
        // without appearing here is the regression, and it would otherwise look like a bigger number.
        var destinations = reaching.Select(t => t.EgressRule.AllowedFqdn).Distinct().OrderBy(f => f, StringComparer.Ordinal);
        Assert.Equal(
            new[] { "api.bls.gov", "api.census.gov", "api.eia.gov", "api.grants.gov", "apps.apple.com", "itunes.apple.com", "rareresources.net", "wikimedia.org" },
            destinations.ToArray());

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
