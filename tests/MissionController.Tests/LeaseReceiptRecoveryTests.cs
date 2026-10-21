using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Linux;

namespace MissionController.Tests;

public sealed class LeaseReceiptRecoveryTests
{
    internal static (JsonElement Admission, JsonElement Exit) SignedFrames(LeaseSpec lease)
    {
        string context = JsonSerializer.Serialize(lease.ExecutionContext, BoundLeaseReceipt.Json);
        string policy = lease.ExecutionPolicy is null ? "none" : BoundLeaseReceipt.Hash(JsonSerializer.Serialize(lease.ExecutionPolicy, BoundLeaseReceipt.Json));
        string effective = new('e', 64);
        string canonical = $"splat-lease-outcome/2|mission={lease.MissionId}|cgroup=77|enforcing=true|uid=200000|exit=-1"
            + $"|counted=2|reported=1|dropped=0|workspace={lease.WorkingDirectory}|workspaceRemoved=true|executionPolicySha256={policy}"
            + $"|executionContext={context}|effectivePolicySha256={effective}|workloadDrained=true|cancellationAccepted=false";
        using var key = RSA.Create(2048);
        byte[] publicKey = key.ExportRSAPublicKey();
        var admission = JsonSerializer.SerializeToElement(new { type = "LEASE", cgroupId = 77, cgroupPath = "/sys/fs/cgroup/test",
            enforcing = true, jailed = true, readOnlyFs = lease.ReadOnlyFs, workspace = lease.WorkingDirectory,
            workspaceCreated = true, workloadUid = 200000 });
        var exit = JsonSerializer.SerializeToElement(new { type = "EXIT", exitCode = -1, workspaceRemoved = true,
            violationsCounted = 2, violationsReported = 1, violationsDropped = 0, violationsComplete = false,
            outcomeCanonical = canonical, outcomeSignature = Convert.ToBase64String(key.SignData(Encoding.UTF8.GetBytes(canonical),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)), outcomePublicKey = Convert.ToBase64String(publicKey),
            outcomeKeyId = Convert.ToHexStringLower(SHA256.HashData(publicKey)), executionContext = context,
            executionPolicySha256 = policy, effectivePolicySha256 = effective, workloadDrained = true, cancellationAccepted = false });
        return (admission, exit);
    }

    [Theory]
    [InlineData("complete")]
    [InlineData("pending")]
    [InlineData("unavailable")]
    [InlineData("wrong-context")]
    [InlineData("wrong-mission")]
    [InlineData("altered-count")]
    [InlineData("tampered-signature")]
    public async Task FreshAuthenticatedLookupNeverExecutes_AndAcceptsOnlyTheOriginalSignedBinding(string scenario)
    {
        var lease = new LeaseSpec(Guid.NewGuid(), "/var/lib/splat/missions/test", false, [], [], false, [], [], 20, new(),
            ExecutionContext: new("worker", new string('a', 64), "tenant", "caller", "task"));
        var frames = SignedFrames(scenario switch {
            "wrong-context" => lease with { ExecutionContext = lease.ExecutionContext! with { CallerId = "other" } },
            "wrong-mission" => lease with { MissionId = Guid.NewGuid() }, _ => lease });
        var exit = System.Text.Json.Nodes.JsonNode.Parse(frames.Exit.GetRawText())!;
        if (scenario == "altered-count") exit["violationsCounted"] = 0;
        if (scenario == "tampered-signature") exit["outcomeSignature"] = Convert.ToBase64String(new byte[256]);
        string reply = JsonSerializer.Serialize(new { type = "RECEIPT_RESPONSE",
            status = scenario is "pending" or "unavailable" ? scenario : "complete", lease = frames.Admission, outcome = exit });
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        const string token = "synthetic-receipt-token-never-a-real-credential";
        var server = Task.Run(async () => {
            using var connection = await listener.AcceptTcpClientAsync(timeout.Token);
            return await StandInAgent.ServeAsync(connection.GetStream(), token, [reply], timeout.Token);
        });
        var executor = new WslLeasedExecutor("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port,
            authToken: token, holdGuestAwake: () => new CancellationTokenSource());
        if (scenario == "complete")
        {
            var receipt = await executor.RecoverReceiptAsync(lease, timeout.Token);
            Assert.True(receipt!.WorkloadDrained);
            Assert.False(receipt.ViolationsComplete);
            Assert.Equal(2UL, receipt.ViolationsCounted);
        }
        else if (scenario is "pending" or "unavailable") Assert.Null(await executor.RecoverReceiptAsync(lease, timeout.Token));
        else await Assert.ThrowsAsync<InvalidOperationException>(() => executor.RecoverReceiptAsync(lease, timeout.Token));
        var exchange = await server;
        Assert.True(exchange.Proven);
        using var request = JsonDocument.Parse(exchange.Request!);
        Assert.Equal("RECEIPT_LOOKUP", request.RootElement.GetProperty("type").GetString());
        Assert.Equal(lease.MissionId.ToString(), request.RootElement.GetProperty("missionId").GetString());
        Assert.False(request.RootElement.TryGetProperty("command", out _));
    }
}
