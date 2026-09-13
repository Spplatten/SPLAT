using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using Splat.CourseLab;

var mode = args.Length == 0 ? "all" : args[0];
if (args.Length > 1 || mode is not ("all" or "representation" or "executor"))
{
    Console.Error.WriteLine("Usage: Splat.CourseLab [all|representation|executor]");
    return 2;
}

int checks = 0;
void Check(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
    checks++;
}

if (mode is "all" or "representation")
{
    // This is a layout exercise; the production bridge sends JSON, not this struct.
    Check(Marshal.SizeOf<LeaseIpv4Layout>() == 16, "IPv4 key must occupy 16 bytes.");
    Check(Marshal.OffsetOf<LeaseIpv4Layout>(nameof(LeaseIpv4Layout.Address)).ToInt32() == 8,
        "Address offset must match the C/Rust key.");
    Check(Marshal.OffsetOf<LeaseIpv4Layout>(nameof(LeaseIpv4Layout.Port)).ToInt32() == 12,
        "Port offset must match the C/Rust key.");
    var portBytes = new byte[2];
    BinaryPrimitives.WriteUInt16BigEndian(portBytes, 443);
    Check(Convert.ToHexString(portBytes) == "01BB", "Port 443 is 01 BB in network byte order.");
    Check(checked(256UL * 1024 * 1024) == 268435456UL, "MiB and bytes are different units.");
    string[] argv = ["two words", "", "café", "a\\b", "\"quoted\""];
    var payload = JsonSerializer.SerializeToUtf8Bytes(new { protocolVersion = 2, argv });
    using var document = JsonDocument.Parse(payload);
    var decoded = document.RootElement.GetProperty("argv").EnumerateArray()
        .Select(item => item.GetString()).ToArray();
    Check(argv.SequenceEqual(decoded), "JSON must preserve every argument boundary.");
    Check(!payload.AsSpan().StartsWith(new byte[] { 0xEF, 0xBB, 0xBF }), "No UTF-8 BOM on the wire.");
    Check(Encoding.UTF8.GetByteCount("é") == 2, "Characters and UTF-8 bytes have different counts.");
}

if (mode is "all" or "executor")
{
    var stopped = new ConcurrentQueue<Activity>();
    using var source = new ActivitySource("Splat.CourseLab.Contract");
    using var listener = new ActivityListener
    {
        ShouldListenTo = candidate => ReferenceEquals(candidate, source),
        Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
        ActivityStopped = stopped.Enqueue
    };
    ActivitySource.AddActivityListener(listener);

    var lease = MakeLease();
    string[] argv = ["LAB_PRIVATE_ARGUMENT", "", "two words"];
    var output = new List<string>();
    var errors = new List<string>();
    var events = new List<LeaseViolationEvent>();
    var stdout = new InlineProgress<string>(output.Add);
    var stderr = new InlineProgress<string>(errors.Add);
    var violations = new InlineProgress<LeaseViolationEvent>(events.Add);
    var violation = new LeaseViolationEvent(1, 2, KernelViolationHook.Open, 3,
        "LAB_PRIVATE_DETAIL", "fixture", DateTime.UnixEpoch);
    var expected = new ProcessExecutionResult(0, "LAB_PRIVATE_OUTPUT", "",
        false, JobResourceMetrics.Unavailable);
    using var callCancellation = new CancellationTokenSource();

    var success = new ScriptedExecutor((actualLease, command, actualArgv, actualOut, actualErr,
        actualEvents, token) =>
    {
        Check(ReferenceEquals(lease, actualLease), "Lease ownership must remain unchanged.");
        Check(command == "fixture-only", "Command must pass through unchanged.");
        Check(ReferenceEquals(argv, actualArgv), "The wrapper must not quote or re-split argv.");
        Check(ReferenceEquals(stdout, actualOut) && ReferenceEquals(stderr, actualErr) &&
            ReferenceEquals(violations, actualEvents), "Progress sinks must pass through.");
        Check(token == callCancellation.Token, "Caller cancellation must reach the executor.");
        actualOut?.Report("LAB_PRIVATE_OUTPUT");
        actualErr?.Report("LAB_PRIVATE_ERROR");
        actualEvents?.Report(violation);
        return Task.FromResult(expected);
    });
    var result = await new MeasuredLeasedExecutor(success, source).ExecuteLeasedAsync(
        lease, "fixture-only", argv, stdout, stderr, violations, callCancellation.Token);
    Check(ReferenceEquals(expected, result), "Return the original result and resource metrics.");
    Check(output.SequenceEqual(["LAB_PRIVATE_OUTPUT"]) && errors.SequenceEqual(["LAB_PRIVATE_ERROR"]) &&
        events.SequenceEqual([violation]), "Streaming callbacks must remain observable.");
    Check(success.Calls == 1, "Observability must not retry a side effect.");

    foreach (var outcome in new[] { (Exit: 7, Timeout: false), (Exit: 0, Timeout: true) })
    {
        var terminal = expected with { ExitCode = outcome.Exit, TimedOut = outcome.Timeout };
        var inner = new ScriptedExecutor((_, _, _, _, _, _, _) => Task.FromResult(terminal));
        var actual = await new MeasuredLeasedExecutor(inner, source)
            .ExecuteLeasedAsync(lease, "fixture-only", argv);
        Check(ReferenceEquals(terminal, actual), "Failure and timeout must not be rewritten.");
    }

    using var cancelled = new CancellationTokenSource();
    cancelled.Cancel();
    var cancellation = new OperationCanceledException(cancelled.Token);
    var cancelledInner = new ScriptedExecutor((_, _, _, _, _, _, _) =>
        Task.FromException<ProcessExecutionResult>(cancellation));
    try
    {
        await new MeasuredLeasedExecutor(cancelledInner, source)
            .ExecuteLeasedAsync(lease, "fixture-only", argv, ct: cancelled.Token);
        Check(false, "Cancellation must propagate.");
    }
    catch (OperationCanceledException error)
    {
        Check(ReferenceEquals(cancellation, error), "Keep the original cancellation.");
    }

    var failure = new IOException("LAB_PRIVATE_EXCEPTION");
    var throwingInner = new ScriptedExecutor((_, _, _, _, _, _, _) =>
        Task.FromException<ProcessExecutionResult>(failure));
    try
    {
        await new MeasuredLeasedExecutor(throwingInner, source)
            .ExecuteLeasedAsync(lease, "fixture-only", argv);
        Check(false, "Transport exceptions must propagate.");
    }
    catch (IOException error)
    {
        Check(ReferenceEquals(failure, error), "Keep the original exception.");
    }

    // A barrier forces overlap without depending on thread scheduling or arbitrary sleeps.
    int arrivals = 0;
    var barrier = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
    var concurrentInner = new ScriptedExecutor(async (_, _, _, _, _, _, _) =>
    {
        if (Interlocked.Increment(ref arrivals) == 2) barrier.TrySetResult();
        await barrier.Task.WaitAsync(TimeSpan.FromSeconds(10));
        return expected;
    });
    var concurrent = new MeasuredLeasedExecutor(concurrentInner, source);
    var otherLease = MakeLease();
    await Task.WhenAll(
        concurrent.ExecuteLeasedAsync(lease, "fixture-only", argv),
        concurrent.ExecuteLeasedAsync(otherLease, "fixture-only", argv));
    Check(concurrentInner.Calls == 2, "Concurrent missions must each execute once.");

    var spans = stopped.ToArray();
    Check(spans.Length == 7, "Each observed invocation needs one completed span.");
    var outcomes = spans.Select(span => span.GetTagItem("splat.outcome")).ToArray();
    Check(outcomes.Count(value => Equals(value, "success")) == 3 &&
        outcomes.Contains("failure") && outcomes.Contains("timeout") &&
        outcomes.Contains("cancelled") && outcomes.Contains("exception"),
        "Outcome categories must distinguish failure, timeout, cancellation and exceptions.");
    Check(spans.Count(span => Equals(span.GetTagItem("splat.mission_id"),
        otherLease.MissionId.ToString("D"))) == 1, "Concurrent mission identity must not bleed.");
    Check(spans.All(span => span.GetTagItem("splat.wall_ms") is double elapsed && elapsed >= 0),
        "Completed spans must record elapsed wall time.");
    string[] allowedTags = ["splat.mission_id", "splat.exit_code", "splat.timed_out",
        "splat.outcome", "splat.wall_ms"];
    Check(spans.SelectMany(span => span.TagObjects).All(tag => allowedTags.Contains(tag.Key)),
        "Only the explicit metadata allow-list may enter tracing.");
    Check(!string.Join("|", spans.SelectMany(span => span.TagObjects).Select(tag => tag.Value))
        .Contains("LAB_PRIVATE", StringComparison.Ordinal), "Private payloads must not enter tracing.");

    using var unobservedSource = new ActivitySource("Splat.CourseLab.NoListener");
    var unobserved = new ScriptedExecutor((_, _, _, _, _, _, _) => Task.FromResult(expected));
    Check(ReferenceEquals(expected, await new MeasuredLeasedExecutor(unobserved, unobservedSource)
        .ExecuteLeasedAsync(lease, "fixture-only", argv)), "No listener must still allow execution.");
    Check(stopped.Count == 7, "No listener must not fabricate a completed trace.");
}

Console.WriteLine($"PASS {checks} checks ({mode}); fixture execution only, no kernel containment measured.");
return 0;

static LeaseSpec MakeLease() => new(
    Guid.NewGuid(), "/course-fixture", false, Array.Empty<string>(), Array.Empty<uint>(),
    false, Array.Empty<InodeIdentifierModel>(), Array.Empty<InodeIdentifierModel>(),
    5, new LeaseResourceLimits());

[StructLayout(LayoutKind.Sequential)]
internal struct LeaseIpv4Layout
{
    public ulong CgroupId;
    public uint Address;
    public ushort Port;
    public ushort Padding;
}

internal sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
{
    public void Report(T value) => report(value);
}

internal sealed class ScriptedExecutor(
    Func<LeaseSpec, string, IReadOnlyList<string>, IProgress<string>?, IProgress<string>?,
        IProgress<LeaseViolationEvent>?, CancellationToken, Task<ProcessExecutionResult>> execute)
    : ILeasedExecutor
{
    private int _calls;
    public int Calls => Volatile.Read(ref _calls);

    public Task<ProcessExecutionResult> ExecuteLeasedAsync(
        LeaseSpec lease, string command, IReadOnlyList<string> argv,
        IProgress<string>? stdout = null, IProgress<string>? stderr = null,
        IProgress<LeaseViolationEvent>? violations = null, CancellationToken ct = default)
    {
        Interlocked.Increment(ref _calls);
        return execute(lease, command, argv, stdout, stderr, violations, ct);
    }
}
