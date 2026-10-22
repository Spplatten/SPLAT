namespace MissionController.Infrastructure.Linux;

/// <summary>Shares one Windows-to-guest session across overlapping leases and short idle gaps.</summary>
internal sealed class SharedGuestHold(
    Func<IDisposable> open, Func<IDisposable, bool>? alive = null, TimeProvider? clock = null) : IDisposable
{
    private readonly object _gate = new();
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private IDisposable? _session;
    private ITimer? _idle;
    private int _borrowers;
    private long _generation;
    private bool _stopping;

    internal IDisposable Acquire()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_stopping, this);
            _idle?.Dispose();
            _idle = null;
            ++_generation;
            if (_session is not null && alive is not null && !alive(_session))
            {
                _session.Dispose();
                _session = null;
            }
            _session ??= open();
            ++_borrowers;
            return new Borrow(this);
        }
    }

    private void Release()
    {
        lock (_gate)
        {
            if (--_borrowers != 0) return;
            if (_stopping) { Close(); return; }
            long generation = ++_generation;
            // A disposed timer may already be queued; its generation must not close a newer lease.
            _idle = _clock.CreateTimer(_ => Expire(generation), null,
                TimeSpan.FromSeconds(5), Timeout.InfiniteTimeSpan);
        }
    }

    private void Expire(long generation)
    {
        lock (_gate)
            if (_borrowers == 0 && generation == _generation) Close();
    }

    private void Close()
    {
        _idle?.Dispose();
        _idle = null;
        _session?.Dispose();
        _session = null;
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _stopping = true;
            _idle?.Dispose();
            if (_borrowers == 0) Close();
        }
    }

    private sealed class Borrow(SharedGuestHold owner) : IDisposable
    {
        private SharedGuestHold? _owner = owner;
        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release();
    }
}
