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
        Assert.NotNull(lease.OverlayFs);
        Assert.True(lease.OverlayFs.EnableCow);
    }

    [Fact]
    public void HealthChecker_DetectsWslConfig()
    {
        var checker = new WslSubstrateHealthChecker();
        // Since we wrote .wslconfig in %USERPROFILE%\.wslconfig, this should be true
        bool configured = checker.IsWslConfiguredForBpf();
        Assert.True(configured);
    }

    [Fact]
    public async Task HealthChecker_ReturnsCleanStatusWhenDaemonOffline()
    {
        var checker = new WslSubstrateHealthChecker("127.0.0.1", 59999); // unused port
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
}