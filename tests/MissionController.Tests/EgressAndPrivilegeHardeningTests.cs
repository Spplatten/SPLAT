using System;
using System.Net.Http;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
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
    /// Proves the restricted token actually REDUCES authority, not merely that a process launches.
    /// The launch test above passes for ANY token - including a full-privilege one - so on its own it
    /// cannot catch a sandbox that silently stopped stripping privilege (the exact failure mode the
    /// fail-closed guard exists for). This runs `whoami /priv` inside the sandbox and asserts the
    /// privilege set was genuinely cut down.
    /// </summary>
    [Fact]
    public async Task RestrictedTokenLaunch_ActuallyStripsPrivileges_NotJustLaunches()
    {
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        using var job = new Win32JobSandbox("privdrop-proof-test");

        var result = await launcher.LaunchSuspendedInJobAsync(
            @"C:\Windows\System32\cmd.exe",
            "/c whoami /priv",
            Environment.CurrentDirectory,
            job,
            dropAdminPrivileges: true,
            timeoutSeconds: 20);

        Assert.Equal(0, result.ExitCode);

        // SeChangeNotifyPrivilege is the one privilege DISABLE_MAX_PRIVILEGE preserves; its presence
        // confirms whoami actually enumerated this token's privileges.
        Assert.Contains("SeChangeNotifyPrivilege", result.StandardOutput);

        // SeTimeZonePrivilege and SeShutdownPrivilege exist in every baseline user token - elevated
        // or not - but are removed by the privilege strip. Their absence is what a full-token launch
        // (the old silent-fallback bug, or a token that quietly stopped restricting) would fail.
        Assert.DoesNotContain("SeTimeZonePrivilege", result.StandardOutput);
        Assert.DoesNotContain("SeShutdownPrivilege", result.StandardOutput);
    }
}
