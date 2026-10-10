using System.Net;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;

namespace MissionController.Tests;

public sealed class LeasedWebProbeTests
{
    [Fact]
    public async Task EveryPublicSource_ReceivesOnlyItsCompiledPins_AndRunsThroughTheLinuxLauncher()
    {
        var templates = GovernedTemplateCatalog.All.Where(t => t.Tool.PassLeaseEgressAsArguments).ToArray();
        Assert.Equal(8, templates.Length);
        foreach (var template in templates)
        {
            var executor = new Capture();
            var resolver = new Resolver();
            Guid mission = Guid.NewGuid();
            var selector = new LinuxLeaseSubstrate(executor, new TemplatePolicyCompiler(resolver));
            var substrate = Assert.IsType<MissionSubstrate>(selector.For(template, mission));
            string directory = await substrate.Jails.ProvisionJailAsync(mission);
            using var job = substrate.Jobs("test");
            await substrate.Launcher.LaunchSuspendedInJobAsync(template.Tool.ExecutablePath,
                GovernedArgumentBinder.Bind(template, new Dictionary<string, string>()), directory, job, true, 60);

            Assert.Equal(template.EgressRule.AllowedFqdn, resolver.Host);
            Assert.Equal("/usr/bin/python3", executor.Command);
            Assert.Equal("192.0.2.7,192.0.2.8", executor.Arguments![^1]);
            Assert.Equal(new[] { "192.0.2.7", "192.0.2.8" }, executor.Lease!.AllowedEgressIps);
            Assert.Equal(new uint[] { 443 }, executor.Lease.AllowedEgressPorts);
            Assert.Single(executor.Lease.AllowedExecInodes);
            Assert.True(executor.Lease.EphemeralWorkspace);
            Assert.Equal("-I", executor.Arguments[0]);
            Assert.Equal("-B", executor.Arguments[1]);
        }
    }

    [Fact]
    public void PublicSourceParameters_AreLiteralArgv_AndCannotChangePythonSource()
    {
        var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "source-dataset-catalog-search");
        var original = PosixArgumentSplitter.Split(GovernedArgumentBinder.Bind(template, new Dictionary<string, string>()));
        var bound = PosixArgumentSplitter.Split(GovernedArgumentBinder.Bind(template,
            new Dictionary<string, string> { ["Topic"] = "Housing $(touch /tmp/not-executed)" }));
        Assert.Equal(original[3], bound[3]);
        Assert.Contains("Housing $(touch /tmp/not-executed)", bound);
        Assert.Throws<TemplateParameterRejectedException>(() => GovernedArgumentBinder.Bind(template,
            new Dictionary<string, string> { ["Topic"] = "'; import os; '" }));
    }

    private sealed class Resolver : IHostAddressResolver
    {
        internal string? Host;
        public IPAddress[] GetHostAddresses(string hostNameOrAddress)
        {
            Host = hostNameOrAddress;
            return new[] { IPAddress.Parse("192.0.2.7"), IPAddress.Parse("192.0.2.8") };
        }
    }

    private sealed class Capture : ILeasedExecutor
    {
        internal LeaseSpec? Lease;
        internal string? Command;
        internal IReadOnlyList<string>? Arguments;
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(LeaseSpec lease, string command, IReadOnlyList<string> argv,
            IProgress<string>? stdout = null, IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
        {
            Lease = lease; Command = command; Arguments = argv;
            return Task.FromResult(new ProcessExecutionResult(0, "fixture", "", false, JobResourceMetrics.Unavailable));
        }
    }
}
