using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace SplatMcp;

/// <summary>
/// In-memory human-in-the-loop gate. Tokens are single-use, time-bounded, and bound to the
/// exact serialised request hash. The ledger records the lifecycle; this store holds only the
/// live state.
/// </summary>
public sealed class ConfirmationGate : IConfirmationGate
{
    private static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MaxTtl = TimeSpan.FromMinutes(15);

    private readonly ConcurrentDictionary<string, Entry> _pending = new();

    public Task<PendingConfirmation> RequestAsync(
        string toolName,
        string summary,
        string mutationVerb,
        string egressTarget,
        string? secretScope,
        string requestHash,
        string actor,
        TimeSpan? ttl = null,
        CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        var effectiveTtl = ttl ?? DefaultTtl;
        if (effectiveTtl > MaxTtl) effectiveTtl = MaxTtl;
        if (effectiveTtl <= TimeSpan.Zero) effectiveTtl = DefaultTtl;

        string token = RandomNumberGenerator.GetHexString(64);
        var expiry = DateTimeOffset.UtcNow + effectiveTtl;

        var confirmation = new PendingConfirmation(
            token, toolName, summary, mutationVerb, egressTarget, secretScope, expiry, actor)
        {
            RequestHash = requestHash
        };

        _pending[token] = new Entry(confirmation, Consumed: false);

        Scavenge();

        return Task.FromResult(confirmation);
    }

    public Task<ConfirmationOutcome> ConsumeAsync(string token, string requestHash, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();

        Scavenge();

        if (!_pending.TryGetValue(token, out var entry))
            return Task.FromResult(ConfirmationOutcome.NotFound);

        if (entry.Consumed)
            return Task.FromResult(ConfirmationOutcome.AlreadyConsumed);

        if (DateTimeOffset.UtcNow > entry.Confirmation.ExpiresUtc)
        {
            _pending.TryRemove(token, out _);
            return Task.FromResult(ConfirmationOutcome.Expired);
        }

        if (!string.Equals(entry.Confirmation.RequestHash, requestHash, StringComparison.Ordinal))
            return Task.FromResult(ConfirmationOutcome.RequestMismatch);

        // Mark consumed atomically via replace
        if (_pending.TryUpdate(token, entry with { Consumed = true }, entry))
            return Task.FromResult(ConfirmationOutcome.Granted);

        // Lost the race — another thread consumed it
        return Task.FromResult(ConfirmationOutcome.AlreadyConsumed);
    }

    public Task<IReadOnlyList<PendingConfirmation>> ListPendingAsync(string actor, CancellationToken ct = default)
    {
        ct.ThrowIfCancellationRequested();
        Scavenge();

        var now = DateTimeOffset.UtcNow;
        var results = _pending.Values
            .Where(e => !e.Consumed
                        && e.Confirmation.ExpiresUtc > now
                        && string.Equals(e.Confirmation.RequestingActor, actor, StringComparison.Ordinal))
            .Select(e => e.Confirmation)
            .OrderBy(c => c.ExpiresUtc)
            .ToList();

        return Task.FromResult<IReadOnlyList<PendingConfirmation>>(results);
    }

    private void Scavenge()
    {
        var cutoff = DateTimeOffset.UtcNow - TimeSpan.FromMinutes(30);
        foreach (var (token, entry) in _pending)
        {
            if (entry.Confirmation.ExpiresUtc < cutoff || (entry.Consumed && entry.Confirmation.ExpiresUtc < DateTimeOffset.UtcNow))
                _pending.TryRemove(token, out _);
        }
    }

    private sealed record Entry(PendingConfirmation Confirmation, bool Consumed);
}
