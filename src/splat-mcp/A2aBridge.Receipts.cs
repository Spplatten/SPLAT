using System.Text.Json;
using MissionController.Core.Interfaces;

namespace SplatMcp;

internal sealed partial class A2aBridge
{
    private A2aTaskRecord ReadOwned(A2aCaller caller, string id)
    {
        // Archival commits before removing the memory entry, so a reader sees one or the other.
        var record = _tasks.TryGetValue(id, out var work) ? work.Record
            : _store.ReadArchived(id, caller.TenantId, caller.CallerId);
        return record is not null && Owns(caller, record) ? record : throw new A2aException(-32001, "Task not found.");
    }

    private async Task<A2aTaskRecord> RecoverAsync(A2aCaller caller, A2aTaskRecord record, CancellationToken ct)
    {
        bool Eligible(A2aTaskRecord r) => r.State is "TASK_STATE_FAILED" or "TASK_STATE_CANCELED" && r.Dispatched != false
            && !r.WorkloadTerminationConfirmed && !r.ReceiptRecovered && r.AdmittedLease?.ExecutionContext is not null
            && (!_tasks.TryGetValue(r.Id, out var executing) || executing.Execution.IsCompleted);
        if (_receiptLookup is null || !Eligible(record)) return record;
        // Bounded stripes coalesce polls without retaining a lock for every archived task forever.
        var gate = _receiptGates[(uint)StringComparer.Ordinal.GetHashCode(record.Id) % (uint)_receiptGates.Length];
        if (!await gate.WaitAsync(0, ct)) return record;
        try
        {
            record = ReadOwned(caller, record.Id);
            if (!Eligible(record) || !await _receiptSlots.WaitAsync(0, ct)) return record;
            LeaseOutcome? receipt;
            try
            {
                try { receipt = await _receiptLookup.RecoverReceiptAsync(record.AdmittedLease!, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                // Lost connectivity, an old daemon, or an invalid signature leave the outcome
                // unresolved. Neither a miss nor a lookup failure is permission to execute again.
                catch (Exception) { return record; }
            }
            finally { _receiptSlots.Release(); }
            if (receipt is not { WorkloadDrained: true, SignedOutcome: not null }) return record;
            await CheckCallerAsync(caller, ct);
            // Coordinate the short persistence step with archival; no daemon I/O holds this lock.
            await _admissionGate.WaitAsync(ct);
            try
            {
                record = ReadOwned(caller, record.Id);
                if (!Eligible(record)) return record;
                var recovered = record with { ReceiptRecovered = true, WorkloadTerminationConfirmed = true,
                    CancellationEvidence = "termination-verified", UpdatedUtc = DateTimeOffset.UtcNow,
                    Failure = "Signed terminal receipt recovered; output and event streams remain unavailable. No replay.",
                    Result = JsonSerializer.SerializeToElement(new { isError = true, content = new[] {
                        new { type = "text", text = "Recovered termination evidence only; tool output was lost." },
                        new { type = "text", text = JsonSerializer.Serialize(new { agentLease = receipt }) }
                    } }) };
                await _store.RecoverAsync(recovered, (connection, transaction) => _admissionLedger.AppendWithinAsync(
                    connection, transaction, Guid.ParseExact(record.Id, "N"), "a2a:" + _config.AgentId,
                    "A2A_RECEIPT_RECOVERED", AuditDetails(caller, recovered), caller.Identity.ToLedgerIdentity(), ct), ct);
                if (_tasks.TryGetValue(record.Id, out var work)) work.Record = recovered;
                return recovered;
            }
            finally { _admissionGate.Release(); }
        }
        finally { gate.Release(); }
    }
}
