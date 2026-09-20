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
    private readonly SemaphoreSlim _loadGate = new(1, 1);
    private volatile bool _loaded;

    public IncidentRevocationManager(IAuditLedger auditLedger, IRevocationStore? revocationStore = null)
    {
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _revocationStore = revocationStore;
    }

    /// <summary>
    /// Loads the persisted list once, and makes every caller wait for that load rather than only the
    /// first one. A flag set before the read finishes would let a check that arrives during cold
    /// start walk past an empty index and report a revoked principal as clear - the window is short,
    /// and it is exactly the window an attacker whose credential was just revoked is in.
    /// A load that fails leaves the flag down, so the next call retries rather than serving an index
    /// it knows is incomplete.
    /// </summary>
    private async ValueTask EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_revocationStore is null || _loaded)
        {
            return;
        }

        await _loadGate.WaitAsync(cancellationToken);
        try
        {
            if (_loaded)
            {
                return;
            }

            var persisted = await _revocationStore.LoadRevocationsAsync(cancellationToken);
            foreach (var entry in persisted)
            {
                _revocationIndex[entry.Identifier] = entry;
            }

            _loaded = true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new RevocationUnavailableException(
                "The persisted revocation list could not be read, so no principal can be cleared: " + ex.Message,
                ex);
        }
        finally
        {
            _loadGate.Release();
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

        await EnsureLoadedAsync(cancellationToken);

        var entry = new RevocationEntry(
            Identifier: identifier,
            RevocationType: revocationType,
            Reason: reason,
            RevokedBy: revokedBy,
            RevokedAtUtc: DateTimeOffset.UtcNow);

        // In memory first: the revocation takes effect on the next check even if the write below
        // fails, because a database that is down is not a reason to leave a burned credential live.
        _revocationIndex[identifier] = entry;

        if (_revocationStore != null)
        {
            try
            {
                await _revocationStore.SaveRevocationAsync(entry, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // The caller is told, but not before the ledger records that this revocation holds
                // only until the process ends - otherwise the one durable account of the incident
                // would be the exception text in whatever called this.
                await _auditLedger.AppendLogAsync(
                    missionId: Guid.Empty,
                    templateId: "SYSTEM_SECURITY",
                    action: "EMERGENCY_REVOCATION_NOT_PERSISTED",
                    details: $"Identifier: {identifier} | Type: {revocationType} | Reason: {reason} | " +
                             $"In effect for this process only, the store refused the write: {ex.Message}",
                    operatorIdentity: revokedBy,
                    cancellationToken: cancellationToken);
                throw;
            }
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

        await EnsureLoadedAsync(cancellationToken);

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
