extern alias sidecar;
using sidecar::Splat.AlertSidecar;

namespace MissionController.Tests;

/// <summary>
/// The alert sidecar's own checks, run by the suite rather than only by
/// packaging/test-alert-sidecar.ps1, so an edit that breaks lease attribution, the latch or the
/// blindness policy fails the build that carries it instead of waiting for someone to run the gate.
/// </summary>
public sealed class AlertSidecarSelfTests
{
    // What ran on 2026-11-05, the run docs/DECOUPLED-SENSOR-ENFORCEMENT.md cites. A floor, not a pin:
    // a new check must not fail the suite, but a dropped check group passes every check it still has
    // and is visible only here.
    private const int ChecksAtLeast = 137;

    [Fact]
    public async Task TheSidecarsOwnChecks_AllRun_AndAllPass()
    {
        // Off xunit's synchronization context: the self-test blocks on its async check groups, and a
        // continuation queued to a context whose every worker is blocked never runs. The timeout turns
        // a hung watchdog check into a failure instead of a suite that never finishes.
        int checks = await Task.Run(SelfTest.Checks).WaitAsync(TimeSpan.FromMinutes(2));

        Assert.True(checks >= ChecksAtLeast,
            $"The sidecar ran {checks} checks where {ChecksAtLeast} ran on 2026-11-05: a check group was dropped.");
    }
}
