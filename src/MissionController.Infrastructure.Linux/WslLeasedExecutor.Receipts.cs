using System.Text.Json;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Linux;

public partial class WslLeasedExecutor
{
    public async Task<LeaseOutcome?> RecoverReceiptAsync(LeaseSpec lease, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (lease.ExecutionContext is null) throw new InvalidOperationException("Receipt recovery requires a bound invocation.");
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(TimeSpan.FromSeconds(5));
        using var awake = _holdGuestAwake();
        using var client = await ConnectToDaemonAsync(budget.Token);
        using var stream = client.GetStream();
        string token = await _token.GetAsync(budget.Token)
            ?? throw new InvalidOperationException("The daemon authentication token is unavailable.");
        using var session = await OpenSessionAsync(stream, token, budget.Token);
        if (!session.FramesProven) throw new InvalidOperationException("Receipt recovery requires authenticated frames.");
        string context = JsonSerializer.Serialize(lease.ExecutionContext, BoundLeaseReceipt.Json);
        string policy = lease.ExecutionPolicy is null ? "none"
            : BoundLeaseReceipt.Hash(JsonSerializer.Serialize(lease.ExecutionPolicy, BoundLeaseReceipt.Json));
        await session.SendAsync(JsonSerializer.Serialize(new { type = "RECEIPT_LOOKUP",
            missionId = lease.MissionId.ToString(), executionContext = context, executionPolicySha256 = policy }), budget.Token);
        using var response = JsonDocument.Parse(await session.ReadLineAsync(budget.Token)
            ?? throw new IOException("Receipt connection ended before its response."));
        var root = response.RootElement;
        if (root.GetProperty("type").GetString() != "RECEIPT_RESPONSE")
            throw new InvalidOperationException("The daemon did not return a receipt response.");
        string? status = root.GetProperty("status").GetString();
        if (status is "pending" or "unavailable") return null;
        if (status != "complete") throw new InvalidOperationException("Invalid receipt status.");
        return ReadRecoveredReceipt(lease, root.GetProperty("lease"), root.GetProperty("outcome"), context);
    }

    internal static LeaseOutcome ReadRecoveredReceipt(LeaseSpec lease, JsonElement admission, JsonElement exit, string context)
    {
        if (admission.GetProperty("type").GetString() != "LEASE" || exit.GetProperty("type").GetString() != "EXIT"
            || !admission.GetProperty("enforcing").GetBoolean() || !admission.GetProperty("jailed").GetBoolean())
            throw new InvalidOperationException("Receipt recovery did not confirm an enforcing jail.");
        string? Text(JsonElement frame, string name) => frame.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
        bool created = admission.GetProperty("workspaceCreated").GetBoolean();
        var outcome = new LeaseOutcome(admission.GetProperty("cgroupId").GetUInt64(), Text(admission, "cgroupPath"),
            true, true, admission.GetProperty("readOnlyFs").GetBoolean(), Text(admission, "workspace"), created,
            created ? exit.GetProperty("workspaceRemoved").GetBoolean() : null,
            admission.GetProperty("workloadUid").GetUInt32(),
            ViolationsCounted: exit.GetProperty("violationsCounted").GetUInt64(),
            ViolationsReported: exit.GetProperty("violationsReported").GetUInt64(),
            // Event/output streams were not recovered. Even a complete guest stream cannot be
            // presented as a complete local event list after the transport disappeared.
            ViolationsComplete: false, ViolationsDropped: exit.GetProperty("violationsDropped").GetUInt64(),
            SignedOutcome: Text(exit, "outcomeCanonical"), OutcomeSignature: Text(exit, "outcomeSignature"),
            OutcomeKeyId: Text(exit, "outcomeKeyId"), OutcomePublicKey: Text(exit, "outcomePublicKey"));
        if (created && outcome.Workspace != lease.WorkingDirectory)
            throw new InvalidOperationException("Receipt workspace does not match the admitted lease.");
        return BoundLeaseReceipt.Verify(lease, outcome, exit.GetProperty("exitCode").GetInt32(), exit, context);
    }
}
