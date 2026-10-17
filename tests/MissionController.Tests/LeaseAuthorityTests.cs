using System.Net;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Linux;

namespace MissionController.Tests;

public sealed class LeaseAuthorityTests
{
    private sealed class Resolver : IHostAddressResolver
    {
        internal readonly List<string> Calls = [];
        internal string Address = "1.1.1.1";
        public IPAddress[] GetHostAddresses(string name) { Calls.Add(name); return [IPAddress.Parse(Address)]; }
    }

    [Fact]
    public void MultipleHostsAreResolvedAgainForEveryAdmissionAndPinnedSeparately()
    {
        var source = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "source-consumer-catalog");
        var template = source with { EgressRule = source.EgressRule with { AdditionalFqdns = ["apps.apple.com"] } };
        var resolver = new Resolver();
        var compiler = new TemplatePolicyCompiler(resolver);
        var first = compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/one");
        resolver.Address = "8.8.8.8";
        var second = compiler.CompileTemplatePolicy(template, Guid.NewGuid(), "/tmp/two");
        Assert.Equal(new[] { "itunes.apple.com", "apps.apple.com", "itunes.apple.com", "apps.apple.com" }, resolver.Calls);
        Assert.Equal("1.1.1.1", Assert.Single(first.AllowedEgressIps));
        Assert.Equal("8.8.8.8", Assert.Single(second.AllowedEgressIps));
        Assert.Equal(2, second.ResolvedEgressHosts!.Count);
        Assert.DoesNotContain("1.1.1.1", LeaseEgressArguments.Append(template.Tool, second, []).Single());
    }

    [Theory]
    [InlineData("https://apps.apple.com/path")]
    [InlineData("*.apple.com")]
    [InlineData("itunes.apple.com")]
    [InlineData(" apps.apple.com")]
    public void InvalidAdditionalDestinationsRefuseTheLease(string host)
    {
        var source = GovernedTemplateCatalog.All.Single(t => t.TemplateId == "source-consumer-catalog");
        Assert.Throws<PolicyCompilationException>(() => new TemplatePolicyCompiler(new Resolver()).CompileTemplatePolicy(
            source with { EgressRule = source.EgressRule with { AdditionalFqdns = [host] } }, Guid.NewGuid(), "/tmp/test"));
    }

    [Fact]
    public void AllRareSensorsCanBindToAnAgentWithoutWindowsFallback()
    {
        var compiled = AgentManifestCompiler.Compile("""
            {"schemaVersion":1,"agentId":"rare-research","name":"RARE","description":"Public evidence",
             "instructions":"Use evidence only","targetModel":"local-model","tools":[
             {"name":"catalog","templateId":"source-consumer-catalog","allowNetwork":true},
             {"name":"reviews","templateId":"source-consumer-reviews","allowNetwork":true},
             {"name":"offers","templateId":"source-consumer-offers","allowNetwork":true}]}
            """);
        Assert.All(compiled.Templates, t => { Assert.Equal(ToolSubstrate.LinuxLease, t.Tool.Substrate);
            Assert.Equal("/usr/bin/python3", t.Tool.ExecutablePath); Assert.True(t.Tool.PassLeaseHostPinsAsArguments); });
    }

    [Fact]
    public void FileAndSyscallIntersectionNeverLendsParentOrChildExclusiveRights()
    {
        string[] calls = ["execve", "exit_group", "write", "close", "read", "openat"];
        var parent = new ExecutionPolicy(1, "x86_64", calls, [new("/data", ["read"], "tree")]);
        var child = new ExecutionPolicy(1, "x86_64", calls.Append("socket").ToArray(),
            [new("/data/customer.db", ["read", "write"]), new("/private/key", ["read"])]);
        var intersection = LeaseAuthority.Intersect(parent, child)!;
        Assert.DoesNotContain("socket", intersection.Syscalls);
        var file = Assert.Single(intersection.FileGrants);
        Assert.Equal("/data/customer.db", file.Path);
        Assert.Equal(new[] { "read" }, file.Access);
        Assert.Equal("file", file.Scope);
    }
}
