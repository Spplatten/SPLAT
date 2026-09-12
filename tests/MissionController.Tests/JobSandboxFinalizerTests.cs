using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using MissionController.Infrastructure.Windows.JobObjects;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The job handle used to be a raw <c>IntPtr</c> closed only from <c>Dispose</c>, with no finalizer
/// behind it. Because the containment job is armed with <c>KILL_ON_JOB_CLOSE</c>, the last handle
/// closing is what actually kills the contained tools - so a sandbox dropped without being disposed
/// did not merely leak a handle, it left everything inside it running for the life of the host
/// process. Moving the field to a SafeHandle buys a finalizer, which turns that from "containment
/// silently did not happen" into "containment happened one collection late".
/// </summary>
public sealed class JobSandboxFinalizerTests
{
    /// <summary>
    /// Deliberately never disposes the sandbox, and keeps no reference to it, so that the only
    /// thing that can still close the job handle is the finalizer. NoInlining keeps the JIT from
    /// extending the local's lifetime into the caller's frame.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static Process StartContainedProcessThenAbandonTheSandbox()
    {
        var sandbox = new Win32JobSandbox();

        var child = Process.Start(new ProcessStartInfo("ping.exe", "-n 60 127.0.0.1")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true
        })!;

        sandbox.AssignProcess(child.SafeHandle);
        return child; // sandbox is unreachable from here on; note the absent Dispose
    }

    [Fact]
    public void AnUndisposedSandbox_StillKillsWhatItContains_OnceItsHandleIsFinalized()
    {
        using var child = StartContainedProcessThenAbandonTheSandbox();

        Assert.False(child.HasExited, "Control failed: the contained process was not running to begin with.");

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        // The kill is asynchronous to the handle close, so allow the kernel a bounded moment.
        Assert.True(
            child.WaitForExit(TimeSpan.FromSeconds(20)),
            "An abandoned sandbox left its contained process running: the job handle was never " +
            "released, so KILL_ON_JOB_CLOSE never fired.");
    }
}
