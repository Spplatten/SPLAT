using System.Collections.Generic;
using MissionController.Core.Interfaces;

namespace MissionController.Core;

/// <summary>
/// One lease's kernel refusals, as the host holds them: the first <see cref="Capacity"/> kept, the
/// rest only counted.
///
/// Every refusal used to become a line in the run transcript and in the MCP tool output, with no
/// ceiling. A workload that keeps provoking refusals - by design or by a bug - set the size of host
/// memory, of the response handed to the calling agent, and of the model context grounded on it. The
/// refusals themselves are enforced in the kernel either way; this bounds only the account of them,
/// and says how much it left out rather than reading as the whole of it. The lease receipt's own
/// counts (counted, reported, complete) stay the authoritative totals.
/// </summary>
public sealed class BoundedViolationLog
{
    public const int DefaultCapacity = 200;

    private readonly List<LeaseViolationEvent> _retained = new();
    private readonly object _gate = new();
    private long _total;

    public BoundedViolationLog(int capacity = DefaultCapacity)
    {
        System.ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        Capacity = capacity;
    }

    public int Capacity { get; }

    /// <summary>Every refusal that reached this host, listed or not.</summary>
    public long Total
    {
        get { lock (_gate) return _total; }
    }

    /// <summary>The refusals kept for listing, in arrival order.</summary>
    public IReadOnlyList<LeaseViolationEvent> Retained
    {
        get { lock (_gate) return _retained.ToArray(); }
    }

    // Called from the bridge's read loop through a synchronous progress sink; the lock keeps a
    // concurrent reader of Total or Retained from seeing a count and a list that disagree.
    public void Add(LeaseViolationEvent violation)
    {
        lock (_gate)
        {
            _total++;
            if (_retained.Count < Capacity)
                _retained.Add(violation);
        }
    }

    /// <summary>
    /// The line that follows a listing when it is short, or null when nothing was left out.
    /// </summary>
    public string? OmittedNote
    {
        get
        {
            long omitted;
            lock (_gate) omitted = _total - _retained.Count;
            return omitted > 0
                ? $"[KERNEL REFUSALS NOT LISTED] {omitted} further refusal(s) reached this host and are counted, not listed; the lease receipt's counts are authoritative."
                : null;
        }
    }
}
