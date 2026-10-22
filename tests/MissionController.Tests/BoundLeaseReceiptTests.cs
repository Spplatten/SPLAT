using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Linux;

namespace MissionController.Tests;

public sealed class BoundLeaseReceiptTests
{
    [Theory]
    [InlineData("valid")]
    [InlineData("other-agent")]
    [InlineData("other-policy")]
    [InlineData("other-mission")]
    [InlineData("undrained")]
    [InlineData("tampered-signature")]
    [InlineData("legacy")]
    [InlineData("altered-count")]
    [InlineData("altered-workspace")]
    public void OnlyAnAuthenticReceiptForThisInvocationConfirmsDrain(string scenario)
    {
        var policy = new ExecutionPolicy(1, "x86_64", ["execve", "exit_group", "write", "close"], []);
        var lease = new LeaseSpec(Guid.NewGuid(), "/tmp/test", false, [], [], false, [], [], 20, new(),
            ExecutionPolicy: policy, ExecutionContext: new("worker", new string('a', 64), "tenant", "caller", "task"));
        var outcome = new LeaseOutcome(77, "/sys/fs/cgroup/test", true, true, false,
            scenario == "altered-workspace" ? "/another/workspace" : null, false, null, 200000,
            ViolationsCounted: scenario == "altered-count" ? 1UL : 0UL, ViolationsReported: 0);
        string context = JsonSerializer.Serialize(lease.ExecutionContext, BoundLeaseReceipt.Json);
        string receiptContext = scenario == "other-agent" ? context.Replace("worker", "attacker") : context;
        string filter = scenario == "other-policy" ? new string('b', 64)
            : BoundLeaseReceipt.Hash(JsonSerializer.Serialize(policy, BoundLeaseReceipt.Json));
        string mission = scenario == "other-mission" ? Guid.NewGuid().ToString() : lease.MissionId.ToString();
        string effective = new('c', 64);
        bool drained = scenario != "undrained";
        string canonical = $"splat-lease-outcome/{(scenario == "legacy" ? 1 : 2)}|mission={mission}|cgroup=77|enforcing=true|uid=200000|exit=-1"
            + $"|counted=0|reported=0|dropped=0|workspace=|workspaceRemoved=n/a|executionPolicySha256={filter}"
            + $"|executionContext={receiptContext}|effectivePolicySha256={effective}|workloadDrained={drained.ToString().ToLowerInvariant()}|cancellationAccepted=true";
        using var key = RSA.Create(2048);
        var signature = key.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (scenario == "tampered-signature") signature[0] ^= 1;
        byte[] publicKey = key.ExportRSAPublicKey();
        var frame = JsonSerializer.SerializeToElement(new { outcomeCanonical = canonical,
            outcomeSignature = Convert.ToBase64String(signature), outcomePublicKey = Convert.ToBase64String(publicKey),
            outcomeKeyId = Convert.ToHexStringLower(SHA256.HashData(publicKey)), executionContext = receiptContext,
            executionPolicySha256 = filter, effectivePolicySha256 = effective, workloadDrained = drained, cancellationAccepted = true });
        if (scenario == "valid")
        {
            var verified = BoundLeaseReceipt.Verify(lease, outcome, -1, frame, context);
            Assert.True(verified.WorkloadDrained);
            Assert.Equal(BoundLeaseReceipt.Hash(context), verified.ExecutionContextSha256);
            Assert.Equal(filter, verified.ExecutionPolicySha256);
        }
        else Assert.Throws<InvalidOperationException>(() => BoundLeaseReceipt.Verify(lease, outcome, -1, frame, context));
    }
}
