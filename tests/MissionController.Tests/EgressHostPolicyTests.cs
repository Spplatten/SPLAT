using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Host;
using MissionController.Infrastructure.Linux;
using SplatMcp;

namespace MissionController.Tests;

/// <summary>
/// The Windows half of hostname egress: the operator's --egress-host list, what a caller may ask of
/// it, what is written into the guest's ceiling, and what a signed receipt must say about the hosts
/// a lease reached. The proxy itself is the daemon's and is tested there (egress_proxy.rs).
/// </summary>
public sealed class EgressHostPolicyTests
{
    [Theory]
    [InlineData("pypi.org", "pypi.org:443")]
    [InlineData("pypi.org:8443", "pypi.org:8443")]
    [InlineData("*.pythonhosted.org", "*.pythonhosted.org:443")]
    public void AHostRuleIsANameWithAnOptionalWildcardAndPort(string entry, string canonical)
    {
        Assert.True(EgressHostRule.TryParse(entry, out EgressHostRule rule));
        Assert.Equal(canonical, rule.ToString());
    }

    // The same refusals the daemon's parser makes, entry for entry: the two must not drift.
    [Theory]
    [InlineData("")]
    [InlineData("localhost")]
    [InlineData("Pypi.org")]
    [InlineData("pypi.org:0")]
    [InlineData("pypi.org:70000")]
    [InlineData("pypi.org:")]
    [InlineData("*.com.")]
    [InlineData("a..b")]
    [InlineData("-a.com")]
    [InlineData("a-.com")]
    [InlineData("*")]
    [InlineData("*.")]
    [InlineData("a.*.com")]
    [InlineData("**.a.com")]
    [InlineData("1.2.3.4")]
    [InlineData("1.2.3.4:443")]
    [InlineData("0x7f.1")]
    [InlineData("a.b/c")]
    [InlineData("a.b c")]
    [InlineData("[::1]:443")]
    [InlineData("::1")]
    [InlineData("exaсmple.com")]
    public void AnythingElseIsNotAHostRule(string entry)
    {
        Assert.False(EgressHostRule.TryParse(entry, out _));
    }

    [Fact]
    public void ACallerMayAskForPartOfTheOperatorsHostsAndNeverForMore()
    {
        var policy = McpEgressPolicy.None.WithHosts("pypi.org, *.pythonhosted.org git.example.com:22");
        Assert.True(policy.HasHosts);
        Assert.True(policy.IsEmpty, "naming hosts must not invent pinned endpoints");

        // Nothing named: everything the operator wrote.
        Assert.Equal(new[] { "pypi.org:443", "*.pythonhosted.org:443", "git.example.com:22" }, policy.AuthorizeHosts([]).Rules);

        var inside = policy.AuthorizeHosts(["pypi.org", "files.pythonhosted.org", "*.cdn.pythonhosted.org", "*.pythonhosted.org"]);
        Assert.Null(inside.Refusal);
        Assert.Equal(new[] { "pypi.org:443", "files.pythonhosted.org:443", "*.cdn.pythonhosted.org:443", "*.pythonhosted.org:443" }, inside.Rules);

        foreach (string outside in new[] { "pypi.org:80", "*.pypi.org", "pythonhosted.org", "badpythonhosted.org", "git.example.com", "evil.net", "1.2.3.4" })
        {
            var refused = policy.AuthorizeHosts(["pypi.org", outside]);
            Assert.Contains(outside, refused.Refusal);
            Assert.Empty(refused.Rules);
        }

        Assert.Contains("no operator egress host policy", McpEgressPolicy.None.AuthorizeHosts(["pypi.org"]).Refusal);
        Assert.Throws<FormatException>(() => McpEgressPolicy.None.WithHosts("pypi.org,1.2.3.4"));
        Assert.Throws<FormatException>(() => McpEgressPolicy.None.WithHosts(" , "));
    }

    [Fact]
    public void TheCeilingNamesHostsOnlyWhenTheOperatorDid()
    {
        using var silent = JsonDocument.Parse(SubstrateProvisioner.CeilingDocument(McpEgressPolicy.Parse("1.1.1.1:443")));
        Assert.False(silent.RootElement.TryGetProperty("allowedEgressHosts", out _));

        using var named = JsonDocument.Parse(SubstrateProvisioner.CeilingDocument(McpEgressPolicy.None.WithHosts("pypi.org,*.pythonhosted.org")));
        Assert.Equal(new[] { "pypi.org:443", "*.pythonhosted.org:443" },
            named.RootElement.GetProperty("allowedEgressHosts").EnumerateArray().Select(rule => rule.GetString()));
        Assert.False(named.RootElement.TryGetProperty("allowedEgress", out _), "hosts alone must not bound pinned endpoints to an empty list");
    }

    [Fact]
    public void TheCommandLineTakesEgressHostForTheServerAndForProvision()
    {
        var serve = Assert.IsType<McpServerCommand.Serve>(McpServerCommand.Parse(new[] { "--egress-host", "pypi.org,*.pythonhosted.org" }));
        Assert.Equal(new[] { "pypi.org:443", "*.pythonhosted.org:443" }, serve.Egress.HostRules);

        var provision = Assert.IsType<McpServerCommand.Provision>(McpServerCommand.Parse(new[] { "provision", "--egress-host", "pypi.org" }));
        Assert.Equal(new[] { "pypi.org:443" }, provision.CeilingEgress.HostRules);

        Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "--egress-host", "PyPI.org" }));
        Assert.IsType<McpServerCommand.UsageError>(McpServerCommand.Parse(new[] { "--egress-host" }));
    }

    [Fact]
    public void ALeaseWithoutHostsSerializesAsItDidBeforeTheFieldExisted()
    {
        var lease = new LeaseSpec(Guid.Empty, "/tmp", false, [], [], false, [], [], 20, new());
        Assert.DoesNotContain("AllowedEgressHosts", JsonSerializer.Serialize(lease));
        Assert.Contains("AllowedEgressHosts", JsonSerializer.Serialize(lease with { AllowedEgressHosts = ["pypi.org:443"] }));
    }

    [Theory]
    [InlineData("carried")]
    [InlineData("carried-nothing")]
    [InlineData("lease-named-hosts-receipt-silent")]
    [InlineData("lease-named-none-receipt-speaks")]
    [InlineData("shown-hosts-differ")]
    [InlineData("shown-count-differs")]
    [InlineData("shown-copies-missing")]
    [InlineData("half-the-fields")]
    public void ASignedReceiptAccountsForTheHostsALeaseNamed(string scenario)
    {
        bool named = scenario != "lease-named-none-receipt-speaks";
        var lease = new LeaseSpec(Guid.NewGuid(), "/tmp/test", true, [], [], false, [], [], 20, new(),
            ExecutionContext: new("worker", new string('a', 64), "tenant", "caller", "task"),
            AllowedEgressHosts: named ? ["pypi.org:443", "*.pythonhosted.org:443"] : null);
        var outcome = new LeaseOutcome(77, "/sys/fs/cgroup/test", true, true, false, null, false, null, 200000,
            ViolationsCounted: 0UL, ViolationsReported: 0);
        string context = JsonSerializer.Serialize(lease.ExecutionContext, BoundLeaseReceipt.Json);
        string effective = new('c', 64);

        string signedHosts = scenario == "carried-nothing" ? "" : "files.pythonhosted.org:443,pypi.org:443";
        string canonical = $"splat-lease-outcome/2|mission={lease.MissionId}|cgroup=77|enforcing=true|uid=200000|exit=0"
            + "|counted=0|reported=0|dropped=0|workspace=|workspaceRemoved=n/a|executionPolicySha256=none"
            + $"|executionContext={context}|effectivePolicySha256={effective}|workloadDrained=true|cancellationAccepted=false"
            + scenario switch
            {
                "lease-named-hosts-receipt-silent" => "",
                "half-the-fields" => $"|egressHosts={signedHosts}",
                _ => $"|egressHosts={signedHosts}|egressRefused=3",
            };
        string[] shownHosts = scenario switch
        {
            "carried-nothing" => [],
            "shown-hosts-differ" => ["pypi.org:443"],
            _ => ["files.pythonhosted.org:443", "pypi.org:443"],
        };
        using var key = RSA.Create(2048);
        byte[] publicKey = key.ExportRSAPublicKey();
        var body = new Dictionary<string, object>
        {
            ["outcomeCanonical"] = canonical,
            ["outcomeSignature"] = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)),
            ["outcomePublicKey"] = Convert.ToBase64String(publicKey),
            ["outcomeKeyId"] = Convert.ToHexStringLower(SHA256.HashData(publicKey)),
            ["executionContext"] = context,
            ["executionPolicySha256"] = "none",
            ["effectivePolicySha256"] = effective,
            ["workloadDrained"] = true,
            ["cancellationAccepted"] = false,
        };
        if (scenario != "shown-copies-missing")
        {
            body["egressHosts"] = shownHosts;
            body["egressRefused"] = scenario == "shown-count-differs" ? 2 : 3;
        }
        var frame = JsonSerializer.SerializeToElement(body);

        if (scenario is "carried" or "carried-nothing")
        {
            var verified = BoundLeaseReceipt.Verify(lease, outcome, 0, frame, context);
            Assert.Equal(shownHosts, verified.EgressHosts);
            Assert.Equal(3UL, verified.EgressRefused);
            Assert.Contains(LeaseControls.Describe(verified)!, control => control.StartsWith("egress-proxy:carried=", StringComparison.Ordinal)
                && control.Contains("refused=3") && control.Contains(scenario == "carried" ? "files.pythonhosted.org:443,pypi.org:443" : "carried=none"));
        }
        else Assert.Throws<InvalidOperationException>(() => BoundLeaseReceipt.Verify(lease, outcome, 0, frame, context));
    }
}
