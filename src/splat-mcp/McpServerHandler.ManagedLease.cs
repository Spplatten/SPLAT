using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Host;

namespace SplatMcp;

public partial class McpServerHandler
{
    // Only ManagedBridgeHost calls this, after OS caller authentication and durable admission.
    // It is deliberately absent from ProcessMessageAsync and the public MCP tool list.
    internal async Task<McpJsonRpcMessage> ExecuteManagedLeaseAsync(McpJsonRpcMessage message, string actor, CancellationToken ct)
    {
        if (IsAgentBound)
            return CreateErrorResponse(message.Id, -32003, "This endpoint accepts only tools from its approved agent manifest; raw leases are refused.");
        if (_revocationManager is not null)
        {
            try
            {
                if ((await _revocationManager.CheckRevocationAsync(actor, ct)).IsRevoked)
                    return CreateErrorResponse(message.Id, -32003, "The managed caller has been revoked; no lease was requested.");
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                return CreateErrorResponse(message.Id, -32003, "The caller's revocation status is unavailable; no lease was requested.");
            }
        }

        ManagedLeaseRequest request;
        try
        {
            request = message.Params?.Deserialize<ManagedLeaseRequest>()
                ?? throw new InvalidDataException("The managed lease request is missing.");
            request.Validate(_egressPolicy);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or NotSupportedException)
        {
            return new McpJsonRpcMessage { JsonRpc = "2.0", Id = message.Id,
                Error = new McpError { Code = -32602, Message = "The managed lease request is invalid or exceeds the service policy." } };
        }

        var violations = new List<LeaseViolationEvent>();
        var collect = new SynchronousProgress<LeaseViolationEvent>(value => { lock (violations) violations.Add(value); });
        ProcessExecutionResult process = await _leasedExecutor.ExecuteLeasedAsync(request.Lease, request.Command,
            request.Arguments, violations: collect, ct: ct);
        // The service records its measured outcome under the same mission ID that the desktop seals.
        // No stdout, argv or credential-bearing response is copied into this admission ledger.
        await _auditLedger.AppendLogAsync(request.Lease.MissionId, "managed-linux-lease", "MANAGED_LEASE_COMPLETED",
            $"ExitCode={process.ExitCode}; TimedOut={process.TimedOut}; Enforcing={process.Lease?.Enforcing}; "
            + $"ViolationsCounted={process.Lease?.ViolationsCounted}; ViolationsComplete={process.Lease?.ViolationsComplete}",
            actor, CancellationToken.None);
        return new McpJsonRpcMessage { JsonRpc = "2.0", Id = message.Id,
            Result = JsonSerializer.SerializeToElement(new ManagedLeaseResult(process, violations)) };
    }
}
