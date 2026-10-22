using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

public sealed class SharedGuestHoldTests
{
    private sealed class Session : IDisposable
    {
        internal int Disposals;
        public void Dispose() => ++Disposals;
    }

    private sealed class Clock : TimeProvider
    {
        internal readonly List<Alarm> Alarms = [];
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var alarm = new Alarm(callback, state);
            Alarms.Add(alarm);
            return alarm;
        }
        internal sealed class Alarm(TimerCallback callback, object? state) : ITimer
        {
            // Simulate a callback already queued when its timer was disposed.
            internal void Fire() => callback(state);
            public bool Change(TimeSpan dueTime, TimeSpan period) => true;
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    [Fact]
    public void ConcurrentAndSequentialLeasesShareOneHold_AndStaleIdleCallbacksCannotReleaseIt()
    {
        var clock = new Clock();
        var sessions = new List<Session>();
        using var pool = new SharedGuestHold(() => { var s = new Session(); sessions.Add(s); return s; }, clock: clock);
        var leases = new IDisposable[32];
        Parallel.For(0, leases.Length, i => leases[i] = pool.Acquire());
        Assert.Single(sessions);
        for (int i = 0; i < leases.Length - 1; ++i) leases[i].Dispose();
        Assert.Empty(clock.Alarms);
        leases[^1].Dispose();
        var firstIdle = Assert.Single(clock.Alarms);
        using (var next = pool.Acquire())
        {
            firstIdle.Fire();
            Assert.Equal(0, sessions[0].Disposals);
            Assert.Single(sessions);
        }
        clock.Alarms[^1].Fire();
        Assert.Equal(1, sessions[0].Disposals);
        leases[^1].Dispose();
        using var later = pool.Acquire();
        Assert.Equal(2, sessions.Count);
    }

    [Fact]
    public void FailedOpenAndDeadHoldDoNotPoisonLaterLeases_AndShutdownWaitsForBorrowers()
    {
        int attempts = 0;
        var first = new Session();
        var second = new Session();
        var pool = new SharedGuestHold(() => ++attempts switch
        {
            1 => throw new IOException("synthetic start failure"), 2 => first, _ => second
        }, alive: s => s != first);
        Assert.Throws<IOException>(() => pool.Acquire());
        var one = pool.Acquire();
        var two = pool.Acquire();
        Assert.Equal(1, first.Disposals);
        pool.Dispose();
        Assert.Throws<ObjectDisposedException>(() => pool.Acquire());
        one.Dispose();
        Assert.Equal(0, second.Disposals);
        two.Dispose();
        Assert.Equal(1, second.Disposals);
    }
}
