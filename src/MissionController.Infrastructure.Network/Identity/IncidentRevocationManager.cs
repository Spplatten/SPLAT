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
    private readonly IRevocationStore? _revocationStore;
    private readonly ConcurrentDictionary<string, RevocationEntry> _revocationIndex = new(StringComparer.OrdinalIgnoreCase);
    private int _initialized;

    public IncidentRevocationManager(IAuditLedger auditLedger, IRevocationStore? revocationStore = null)
    {
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _revocationStore = revocationStore;
    }

    private async ValueTask EnsureInitializedAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref _initialized, 1, 0) == 0)
        {
            if (_revocationStore != null)
            {
                try
                {
                    var persisted = await _revocationStore.LoadRevocationsAsync(cancellationToken);
                    foreach (var entry in persisted)
                    {
                        _revocationIndex[entry.Identifier] = entry;
                    }
                }
                catch
                {
                    // Fall back to in-memory index if persistent store fails
                }
            }
        }
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

        await EnsureInitializedAsync(cancellationToken);

        var entry = new RevocationEntry(
            Identifier: identifier,
            RevocationType: revocationType,
            Reason: reason,
            RevokedBy: revokedBy,
            RevokedAtUtc: DateTimeOffset.UtcNow);

        _revocationIndex[identifier] = entry;

        if (_revocationStore != null)
        {
            await _revocationStore.SaveRevocationAsync(entry, cancellationToken);
        }

        // Log emergency revocation event to immutable audit ledger
        await _auditLedger.AppendLogAsync(
            missionId: Guid.Empty,
            templateId: "SYSTEM_SECURITY",
            action: "EMERGENCY_REVOCATION",
            details: $"Identifier: {identifier} | Type: {revocationType} | Reason: {reason}",
            operatorIdentity: revokedBy,
            cancellationToken: cancellationToken);
    }

    public async Task<RevocationStatus> CheckRevocationAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            return new RevocationStatus(false);
        }

        await EnsureInitializedAsync(cancellationToken);

        if (_revocationIndex.TryGetValue(identifier, out var entry))
        {
            return new RevocationStatus(true, entry);
        }

        int colonIdx = identifier.IndexOf(':');
        if (colonIdx > 0 && colonIdx < identifier.Length - 1)
        {
            string suffix = identifier[(colonIdx + 1)..];
            if (_revocationIndex.TryGetValue(suffix, out var suffixEntry))
            {
                return new RevocationStatus(true, suffixEntry);
            }
        }

        return new RevocationStatus(false);
    }

    public async Task<bool> IsRevokedAsync(string identifier, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(identifier))
        {
            return false;
        }

        var status = await CheckRevocationAsync(identifier, cancellationToken);
        return status.IsRevoked;
    }
}
