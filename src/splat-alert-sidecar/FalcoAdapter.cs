using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Splat.AlertSidecar;

// Falco's own JSON alert (json_output: true), as http_output posts it or Falcosidekick's webhook
// forwards it. Attribution is the lease cgroup in output_fields["thread.cgroups"], never proc.pid: a
// PID names one process until the kernel recycles it, where the lease cgroup names the whole tree by a
// GUID. The rule bound to a lease must therefore print %thread.cgroups.
internal sealed class FalcoAdapter
{
    // Falco's two reports about itself, both with source "internal" (falco_outputs.cpp handle_msg): a
    // drop alert, rate-limited and raised only above syscall_event_drops.threshold (event_drops.cpp),
    // and the periodic metrics snapshot, whose loss counters only grow for the life of one Falco.
    internal const string DropRule = "Falco internal: syscall event drop";
    internal const string MetricsRule = "Falco internal: metrics snapshot";
    // Kernel ring-buffer drops, then alerts Falco built but could not queue for output.
    private static readonly string[] Losses = ["scap.n_drops", "falco.outputs_queue_num_drops"];
    private readonly Binding _binding;
    private readonly FalcoScope _scope;
    private readonly Func<long> _clock;
    private readonly Lock _gate = new();
    private readonly ulong?[] _losses = new ulong?[Losses.Length];
    private ulong? _sensorStart;
    private long _heard;

    internal FalcoAdapter(Binding binding, Func<long>? clock = null)
    {
        if (binding.Falco is not { Valid: true } scope || binding.Source != "falco")
            throw new InvalidDataException("Falco mode requires a resolved lease scope.");
        _binding = binding; _scope = scope;
        // Silence is measured on a monotonic clock, so a wall-clock step can neither fake nor hide it.
        _clock = clock ?? (() => Environment.TickCount64);
        _heard = _clock();
    }

    internal bool FailClosed => _scope.OnDrop == "revoke";

    // The id to admit, or null for an authentic event that changes nothing for this task. Most of a
    // node-wide sensor's traffic concerns other processes and other leases; that is not an error.
    internal (string? Id, long Observed) Classify(JsonElement root, long now)
    {
        string rule = Required(root, "rule").GetString()!, source = Required(root, "source").GetString()!;
        long observed = Time(Required(root, "time").GetString()!);
        if (!Required(root, "hostname").ValueEquals(_binding.Node)) return (null, observed);
        Interlocked.Exchange(ref _heard, _clock());
        bool revoke = FailClosed && now < _binding.ExpiresUnixMs;
        if (source == "internal" && rule == DropRule) return (revoke ? "falco-drop:" + EventId(root) : null, observed);
        if (source == "internal" && rule == MetricsRule)
            return Continuity(root) is { } gap && revoke ? (gap + ":" + EventId(root), observed) : (null, observed);
        if (rule != _binding.Rule) return (null, observed);
        // A bound rule that cannot be attributed is a misconfiguration to surface, not traffic to drop.
        if (source != "syscall" || !root.TryGetProperty("output_fields", out var fields)
            || fields.ValueKind != JsonValueKind.Object || !fields.TryGetProperty("thread.cgroups", out var cgroups))
            throw new InvalidDataException("The bound rule must be a syscall rule whose output prints %thread.cgroups.");
        // Printed but unavailable belongs to no lease.
        string? lease = cgroups.ValueKind switch
        {
            JsonValueKind.String => LeaseOf(cgroups.GetString()!),
            JsonValueKind.Null => null,
            _ => throw new JsonException("thread.cgroups must be a string.")
        };
        if (lease != _scope.LeaseCgroup) return (null, observed);
        if (now >= _binding.ExpiresUnixMs) throw new InvalidDataException("The binding has expired.");
        return ("falco:" + EventId(root), observed);
    }

    // libsinsp prints thread.cgroups as subsys=path entries joined by single spaces. Under cgroup v2 a
    // controller the lease cgroup does not enable reports the nearest ancestor that does, so only some
    // entries reach the lease (the daemon enables memory, cpu and pids on it). Every entry that names a
    // lease must name the same one; a deeper path is a descendant, and still that lease.
    internal static string? LeaseOf(string cgroups)
    {
        string? lease = null;
        foreach (string entry in cgroups.Split(' '))
        {
            int start = entry.IndexOf('=') + 1;
            if (!entry.AsSpan(start).StartsWith(FalcoScope.Prefix, StringComparison.Ordinal)) continue;
            int end = entry.IndexOf('/', start + FalcoScope.Prefix.Length);
            string found = end < 0 ? entry[start..] : entry[start..end];
            if (lease != null && lease != found) throw new InvalidDataException("One thread cannot sit in two leases.");
            lease = found;
        }
        return lease;
    }

    // A loss counter that moved, or a different Falco process, between two snapshots means events went
    // unseen in between. The first snapshot only sets the baseline: it cannot speak for what came before.
    private string? Continuity(JsonElement root)
    {
        if (!root.TryGetProperty("output_fields", out var fields) || fields.ValueKind != JsonValueKind.Object
            || Counter(fields, "falco.start_ts") is not { } start) return null;
        var counts = Losses.Select(name => Counter(fields, name)).ToArray();
        lock (_gate)
        {
            string? gap = null;
            if (_sensorStart is { } previous)
            {
                if (start != previous) gap = "falco-restart";
                else for (int i = 0; i < counts.Length; i++)
                    if (counts[i] is { } current && _losses[i] is { } before && current != before)
                        gap ??= current > before ? "falco-drop" : "falco-restart";
            }
            _sensorStart = start;
            counts.CopyTo(_losses, 0);
            return gap;
        }
    }

    internal string? Silent() =>
        _scope.MaxSilenceMs is { } limit && _clock() - Interlocked.Read(ref _heard) > limit ? "falco-silence" : null;

    // A sensor that has not spoken for MaxSilenceMs has not been watching. One admission is all the
    // latch holds, so the watch ends with it. The sidecar's own death is outside this: then nothing
    // revokes, and the lease's in-kernel deadline is what still bounds it.
    internal async Task WatchAsync(Latch latch, CancellationToken ct)
    {
        try
        {
            while (_scope.MaxSilenceMs is not null)
            {
                await Task.Delay(1000, ct);
                long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                if (now < _binding.ExpiresUnixMs && Silent() is { } id) { latch.Admit(id, now, now); break; }
            }
            await Task.Delay(Timeout.Infinite, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
    }

    // Falco writes UTC with nine fractional digits; Falcosidekick re-encodes Go's RFC3339Nano, which
    // trims trailing zeros. Both end in 'Z'. An offset or a local time is refused, not guessed at.
    internal static long Time(string value)
    {
        int dot = value.IndexOf('.');
        string fraction = dot == 19 && value.Length > 21 && value[^1] == 'Z' ? value[20..^1] : "";
        if (value.Length < 20 || value[10] != 'T' || value[^1] != 'Z' || (dot == -1 ? value.Length != 20
                : dot != 19 || fraction.Length is 0 or > 9 || !fraction.All(char.IsAsciiDigit))
            || !DateTime.TryParseExact(value[..19], "yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var whole))
            throw new JsonException("Falco time must be RFC 3339 UTC.");
        // The latch keeps milliseconds; finer digits are dropped, never rounded into the next one.
        int millis = fraction.Length == 0 ? 0 : int.Parse(fraction.PadRight(3, '0')[..3], CultureInfo.InvariantCulture);
        return new DateTimeOffset(whole, TimeSpan.Zero).ToUnixTimeMilliseconds() + millis;
    }

    // Falcosidekick's uuid when it sent one; otherwise a digest of the event as received, so a resend
    // of one alert is the same alert.
    private static string EventId(JsonElement root)
    {
        if (!root.TryGetProperty("uuid", out var uuid))
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(root.GetRawText())));
        return uuid.ValueKind == JsonValueKind.String && uuid.GetString() is { Length: <= 100 } id && Binding.ValidIdentifier(id)
            ? id : throw new JsonException("uuid must be a short identifier.");
    }

    private static JsonElement Required(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value : throw new JsonException("Falco alert lacks the string field " + name + ".");

    // Falco emits metrics as JSON numbers; Falcosidekick may hand them on as decimal strings. A sign,
    // fraction or exponent is not a counter.
    private static ulong? Counter(JsonElement fields, string name)
    {
        if (!fields.TryGetProperty(name, out var value)) return null;
        string? raw = value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            _ => null
        };
        return ulong.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out ulong count)
            ? count : throw new JsonException(name + " is not an unsigned counter.");
    }

    // Offline: does a captured alert attribute to this binding? Run it against one real alert from the
    // node before trusting a binding; it is the check for the cgroup rendering this code assumes.
    internal static int? TryRun(string[] args)
    {
        if (args is not ["--check-falco-event", var bindingPath, var eventPath]) return null;
        try
        {
            using var document = StrictJson.Parse(ConfigurationFiles.Read(bindingPath));
            var binding = document.RootElement.Deserialize<Binding>(Binding.Json) ?? throw new JsonException("Missing binding");
            long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            binding.Check(now);
            using var input = StrictJson.Parse(ConfigurationFiles.Read(eventPath));
            var (id, observed) = new FalcoAdapter(binding).Classify(input.RootElement, now);
            Console.WriteLine(JsonSerializer.Serialize(new { binding.TaskId, admit = id != null, id, observed, dispatched = false }));
            return 0;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or JsonException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine("Falco offline check refused: " + ex.GetType().Name + ": " + ex.Message);
            return 2;
        }
    }
}
