using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Network.Identity;

public sealed class IncidentRevocationManager : IIncidentRevocationManager
{
    private readonly IAuditLedger _auditLedger;
    private readonly ConcurrentDictionary<string, RevocationEntry> _revocationIndex = new(StringComparer.OrdinalIgnoreCase);

    public IncidentRevocationManager(IAuditLedger auditLedger)
    {
        _auditLedger = auditLedger;
    }

    public async Task RevokeAsync(
        string identifier,
        string revocationType,
        string reason,
        string revokedBy,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(identifier))
            throw new ArgumentException("Identifier to revoke cannot be empty.", nameof(identifier));

        var entry = new RevocationEntry(
            Identifier: identifier,
            RevocationType: revocationType,
            Reason: reason,
            RevokedBy: revokedBy,
            RevokedAtUtc: DateTimeOffset.UtcNow);

        _revocationIndex[identifier] = entry;

        // Log emergency revocation event to immutable audit ledger
        await _auditLedger.AppendLogAsync(
            missionId: Guid.Empty,
            templateId: "SYSTEM_SECURITY",
            action: "EMERGENCY_REVOCATION",
            details: $"Identifier: {identifier} | Type: {revocationType} | Reason: {reason}",
            operatorIdentity: revokedBy,
            cancellationToken: cancellationToken);
    }

    public Task<RevocationStatus> CheckRevocationAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            return Task.FromResult(new RevocationStatus(false));
        }

        if (_revocationIndex.TryGetValue(identifier, out var entry))
        {
            return Task.FromResult(new RevocationStatus(true, entry));
        }

        return Task.FromResult(new RevocationStatus(false));
    }

    public Task<bool> IsRevokedAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            return Task.FromResult(false);
        }

        return Task.FromResult(_revocationIndex.ContainsKey(identifier));
    }
}
