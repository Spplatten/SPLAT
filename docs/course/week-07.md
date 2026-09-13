# Week 7 — concurrency, cancellation and observability

## Lesson A: awaiting is not stopping

**Outcome:** distinguish logical operation lifetime from OS process lifetime.

Async methods may suspend while waiting for I/O, freeing a thread to run other work. Await does not mean “create a new thread.” Progress callbacks may execute through a captured context; a callback posted to a UI context can arrive later than a result assembled elsewhere.

CancellationToken communicates a request cooperatively. It cannot forcibly terminate an arbitrary process or guarantee that a remote daemon killed descendants. [Microsoft's cancellation reference](https://learn.microsoft.com/en-us/dotnet/standard/threading/cancellation-in-managed-threads).

Compare the bridge's linked timeout token with the daemon's lease reaper. A caller cancellation, local communication timeout and confirmed remote termination are three different observations. The current bridge's generic cancellation catch collapses these distinctions; that is repair ticket R2.

## Lesson B: attach measurement without changing execution

**Outcome:** add tracing through the real ILeasedExecutor seam.

[MeasuredLeasedExecutor](../../coursework/Splat.CourseLab/MeasuredLeasedExecutor.cs) delegates the lease, command, argv, callbacks and token unchanged. It returns the same result object and rethrows exceptions. It records mission ID, wall duration and bounded outcome categories without putting raw arguments, output or exception messages into tags.

ActivitySource creates a span only when a listener wants it. The source's owner controls its lifetime; the decorator does not dispose an injected source. Wall duration includes scheduler and I/O waits and must not be reported as CPU time. [Microsoft's tracing walkthrough](https://learn.microsoft.com/en-us/dotnet/core/diagnostics/distributed-tracing-instrumentation-walkthroughs).

The wrapper is an observation component, not enforcement. It cannot recover a distinction that the inner executor already erased. If the bridge returns TimedOut after caller cancellation, the wrapper faithfully sees that result.

## Lab: a working attachable component

~~~powershell
.\coursework\Run-Course.ps1 -Gate Lab -LabMode executor
~~~

1. Inspect the supplied success, failure, timeout, cancellation and exception fixtures.
2. Explain why an exit code of zero with TimedOut true is still classified as timeout.
3. Follow the barrier that makes two missions overlap without arbitrary sleeps.
4. Verify one span per call, separate mission IDs, no implicit retries and no private payload tags.
5. Run the no-listener case and explain why the original result must still return.
6. In a teaching composition project referencing the Linux infrastructure, instantiate the decorator with a WslLeasedExecutor and an ActivitySource. Pass that interface into the existing McpServerHandler constructor. Supply the listener in the host. Keep actual guest execution gated on its normal prerequisites.

The completed fixture is a reference implementation. For a student exercise, add the case where an inner OperationCanceledException occurs without the caller token being cancelled; decide whether the wrapper should classify it as an exception.

**Cybersecurity case:** retries can duplicate a write after a lost reply. Observation must not add an automatic retry to a side-effecting interface.

**Repair practice:** R2 needs a bridge-level regression with cancellation during read and separate lease expiry. Kernel kill evidence must come from the daemon/process boundary.

**Submit:** passing lab output, an outcome table and a proposed composition change.

**Check yourself:** Does wall time equal CPU time? Does cancelling a Task prove a child died?

**Answer checkpoint:** no. Require actual CPU accounting and independent termination evidence.
