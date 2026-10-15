using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

public class LinuxSubstrateAndCompilerTests
{
    private readonly TemplatePolicyCompiler _compiler = new();

    private static SingleToolTemplate CreateMockTemplate(
        string toolName = "ping.exe",
        string fqdn = "none",
        int port = 443,
        long maxRam = 128 * 1024 * 1024,
        int maxCpu = 40,
        EgressScope scope = EgressScope.ModelGateway)
    {
        var toolDef = new SingleToolDefinition(
            ToolId: "test-tool-1",
            Name: "Test Tool",
            ExecutablePath: toolName,
            ArgumentsTemplate: "-c 4 127.0.0.1",
            AllowedExitCodes: new[] { 0 },
            TimeoutSeconds: 30,
            MaxMemoryBytes: maxRam,
            MaxCpuPercent: maxCpu);

        var egress = new EgressRule(
            AllowedFqdn: fqdn,
            AllowedPort: port,
            Scope: scope);

        return new SingleToolTemplate(
            TemplateId: "atlas-net-test",
            Name: "Network Agent Test",
            Description: "Network latency test",
            Category: "Network",
            TargetModel: "claude-3-opus",
            Tool: toolDef,
            EgressRule: egress,
            SystemPrompt: "Diagnose network latency",
            ParameterFields: Array.Empty<TemplateParameterField>());
    }

    [Fact]
    public void PolicyCompiler_ProtectsSensitiveInodesByDefault()
    {
        var template = CreateMockTemplate();
        var missionId = Guid.NewGuid();

        var lease = _compiler.CompileTemplatePolicy(template, missionId, "/tmp/splat_test");

        Assert.NotNull(lease);
        Assert.Equal(missionId, lease.MissionId);
        Assert.NotEmpty(lease.ProtectedInodes);

        var protectedPaths = lease.ProtectedInodes.Select(i => i.SourcePath).ToList();
        Assert.Contains("/etc/shadow", protectedPaths);
        Assert.Contains("/etc/sudoers", protectedPaths);
        Assert.Contains("/root/.ssh", protectedPaths);
    }

    [Fact]
    public void PolicyCompiler_NamesOnlyTheDaemonsOwnGuardedPaths_ForATemplateUnderTheLease()
    {
        // The daemon refuses a lease naming a protected path it cannot resolve, and this side of the
        // wire cannot know what the guest holds: the first leased catalog mission was refused on
        // 2026-09-24 for /root/.gnupg, /var/run/docker.sock and /proc/kcore. A template that runs
        // under the lease therefore names exactly what the daemon guards of its own accord, the way
        // run_command does, and relies on the jail for the rest.
        var template = CreateMockTemplate("/bin/df");
        template = template with { Tool = template.Tool with { Substrate = ToolSubstrate.LinuxLease } };

        var lease = _compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/var/lib/splat/missions/x");

        Assert.Equal(new[] { "/etc/shadow", "/etc/sudoers" }, lease.ProtectedInodes.Select(i => i.SourcePath).ToArray());
        Assert.True(lease.EphemeralWorkspace);
        Assert.Equal(new[] { "/bin/df" }, lease.AllowedExecInodes.Select(i => i.SourcePath).ToArray());
    }

    [Fact]
    public void PolicyCompiler_AllowsCorrectLinuxExecutables()
    {
        var template = CreateMockTemplate("curl.exe");
        var missionId = Guid.NewGuid();

        var lease = _compiler.CompileTemplatePolicy(template, missionId, "/tmp/splat_test");

        Assert.NotEmpty(lease.AllowedExecInodes);
        var execPaths = lease.AllowedExecInodes.Select(i => i.SourcePath).ToList();
        Assert.Contains("/bin/curl", execPaths);
        Assert.Contains("/bin/sh", execPaths);
    }

    [Fact]
    public void PolicyCompiler_EnforcesAirgapWhenNoEgressConfigured()
    {
        var template = CreateMockTemplate(fqdn: "none");
        var lease = _compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/splat_test");

        Assert.False(lease.AllowNetwork);
        Assert.Empty(lease.AllowedEgressIps);
    }

    [Fact]
    public void PolicyCompiler_AllowsLocalhostWhenExplicitlyConfigured()
    {
        // "Explicitly configured" now means the rule names ToolProcess scope. A destination alone
        // no longer opens the tool's network: the default rule names the model gateway, which the
        // host reaches, and reading that as tool egress is what opened the whole catalogue.
        var template = CreateMockTemplate(fqdn: "127.0.0.1", port: 8080, scope: EgressScope.ToolProcess);
        var lease = _compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/splat_test");

        Assert.True(lease.AllowNetwork);
        Assert.Contains("127.0.0.1", lease.AllowedEgressIps);
        Assert.Contains(8080u, lease.AllowedEgressPorts);
    }

    [Fact]
    public void PolicyCompiler_ClampsResourceLimitsAndDuration()
    {
        var template = CreateMockTemplate(maxRam: 512 * 1024 * 1024, maxCpu: 60);
        var lease = _compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/splat_test", leaseDurationSeconds: 10);

        Assert.Equal(10u, lease.LeaseDurationSeconds);
        Assert.Equal(512UL * 1024 * 1024, lease.Limits.MaxMemoryBytes);
        Assert.Equal(60u, lease.Limits.MaxCpuPercent);
        // The overlay SHAPE is compiled - paths and all - but copy-on-write is not requested. The
        // daemon mounts it inside the child's namespace now, and it is a separate explicit grant:
        // compiling a template must never turn it on. This assertion used to demand the promise.
        Assert.NotNull(lease.OverlayFs);
        Assert.False(lease.OverlayFs.EnableCow);
        Assert.Equal("/var/splat/baseline", lease.OverlayFs.LowerDir);
    }

    [Fact]
    public void HealthChecker_DetectsWslConfig()
    {
        var checker = new WslSubstrateHealthChecker(token: new WslAgentToken(authToken: "cafebabe"));
        // Since we wrote .wslconfig in %USERPROFILE%\.wslconfig, this should be true
        bool configured = checker.IsWslConfiguredForBpf();
        Assert.True(configured);
    }

    [Fact]
    public async Task HealthChecker_ReturnsCleanStatusWhenDaemonOffline()
    {
        var checker = new WslSubstrateHealthChecker("127.0.0.1", 59999, new WslAgentToken(authToken: "cafebabe")); // unused port
        var status = await checker.CheckHealthAsync();

        Assert.NotNull(status);
        Assert.True(status.WslConfiguredForBpf);
        Assert.False(status.DaemonReachable);
        Assert.False(status.BpfLsmActive);
        Assert.Contains("Daemon unreachable", status.Message);
    }

    [Fact]
    public void LeaseViolationEvent_RecordInitializesCorrectly()
    {
        var vEvent = new LeaseViolationEvent(
            CgroupId: 12345,
            ProcessId: 9999,
            Hook: KernelViolationHook.Open,
            Detail: 67890,
            DetailText: "file_open: denied access to /etc/shadow",
            ProcessComm: "cat",
            TimestampUtc: DateTime.UtcNow);

        Assert.Equal(12345UL, vEvent.CgroupId);
        Assert.Equal(9999u, vEvent.ProcessId);
        Assert.Equal(KernelViolationHook.Open, vEvent.Hook);
        Assert.Equal("cat", vEvent.ProcessComm);
    }

    [Fact]
    public void PolicyCompiler_RefusesUnresolvableHost_WhenToolNetworkRequested()
    {
        // R1: A throwing resolver must cause CompileTemplatePolicy to fail closed
        // and throw PolicyCompilationException rather than silently granting loopback (127.0.0.1).
        var throwingResolver = new ThrowingHostAddressResolver(
            new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.HostNotFound));
        var compiler = new TemplatePolicyCompiler(throwingResolver);

        var template = CreateMockTemplate(
            fqdn: "unresolvable.mission.internal",
            port: 443,
            scope: EgressScope.ToolProcess);

        var ex = Assert.Throws<PolicyCompilationException>(() =>
            compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/splat_test"));

        Assert.Contains("unresolvable.mission.internal", ex.Message);
    }

    [Fact]
    public void PolicyCompiler_RefusesIpv6OnlyResolution_WithoutFabricatingIpv4Success()
    {
        // R1: Resolving to IPv6-only addresses must fail closed, not produce an empty/broken lease or fabricated IPv4.
        var ipv6Resolver = new StubHostAddressResolver(System.Net.IPAddress.Parse("2001:db8::1"));
        var compiler = new TemplatePolicyCompiler(ipv6Resolver);

        var template = CreateMockTemplate(
            fqdn: "ipv6.mission.internal",
            port: 443,
            scope: EgressScope.ToolProcess);

        var ex = Assert.Throws<PolicyCompilationException>(() =>
            compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/splat_test"));

        Assert.Contains("no usable IPv4 addresses", ex.Message);
    }

    [Fact]
    public void PolicyCompiler_DeduplicatesAndPinsIpv4Addresses()
    {
        var stubResolver = new StubHostAddressResolver(
            System.Net.IPAddress.Parse("93.184.216.34"),
            System.Net.IPAddress.Parse("93.184.216.34"),
            System.Net.IPAddress.Parse("93.184.216.35"));
        var compiler = new TemplatePolicyCompiler(stubResolver);

        var template = CreateMockTemplate(
            fqdn: "example.com",
            port: 8443,
            scope: EgressScope.ToolProcess);

        var lease = compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/splat_test");

        Assert.True(lease.AllowNetwork);
        Assert.Equal(2, lease.AllowedEgressIps.Count);
        Assert.Contains("93.184.216.34", lease.AllowedEgressIps);
        Assert.Contains("93.184.216.35", lease.AllowedEgressIps);
        Assert.Contains(8443u, lease.AllowedEgressPorts);
    }

    [Fact]
    public void PolicyCompiler_ExplicitLoopback_BypassesResolver()
    {
        // Explicit localhost/127.0.0.1 should not query the DNS resolver
        var throwingResolver = new ThrowingHostAddressResolver(
            new InvalidOperationException("Resolver must not be called for explicit loopback"));
        var compiler = new TemplatePolicyCompiler(throwingResolver);

        var template = CreateMockTemplate(
            fqdn: "127.0.0.1",
            port: 8080,
            scope: EgressScope.ToolProcess);

        var lease = compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/splat_test");

        Assert.True(lease.AllowNetwork);
        Assert.Contains("127.0.0.1", lease.AllowedEgressIps);
        Assert.Contains(8080u, lease.AllowedEgressPorts);
    }

    [Fact]
    public void PolicyCompiler_RejectsInvalidPortRange()
    {
        var templateNegative = CreateMockTemplate(fqdn: "127.0.0.1", port: -5, scope: EgressScope.ToolProcess);
        Assert.Throws<PolicyCompilationException>(() =>
            _compiler.CompileTemplatePolicy(templateNegative, Guid.NewGuid(), "/tmp/splat_test"));

        var templateOverflow = CreateMockTemplate(fqdn: "127.0.0.1", port: 70000, scope: EgressScope.ToolProcess);
        Assert.Throws<PolicyCompilationException>(() =>
            _compiler.CompileTemplatePolicy(templateOverflow, Guid.NewGuid(), "/tmp/splat_test"));
    }

    private sealed class ThrowingHostAddressResolver : IHostAddressResolver
    {
        private readonly Exception _exceptionToThrow;
        public ThrowingHostAddressResolver(Exception ex) => _exceptionToThrow = ex;
        public System.Net.IPAddress[] GetHostAddresses(string hostNameOrAddress) => throw _exceptionToThrow;
    }

    private sealed class StubHostAddressResolver : IHostAddressResolver
    {
        private readonly System.Net.IPAddress[] _addresses;
        public StubHostAddressResolver(params System.Net.IPAddress[] addresses) => _addresses = addresses;
        public System.Net.IPAddress[] GetHostAddresses(string hostNameOrAddress) => _addresses;
    }
}