using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Splat.AlertSidecar;

// The admission owner supplies this immutable binding, outside the monitored workload.
// A task UUID never comes from the alert. PID alone, human process names and guest wall time
// are deliberately insufficient. Identity is for THIS process, not arbitrary descendants.
// A Falco binding replaces the process tuple with the lease cgroup SPLAT reports for the task, which
// does cover descendants: Boot/Cgroup/Pid/StartTicks are then absent and must stay zero.
internal sealed record Binding(string TaskId, string Node, Guid Boot, ulong Cgroup, int Pid,
    ulong StartTicks, string Source, string Rule, long ExpiresUnixMs, int ListenPort, int A2aPort,
    FalconIdentity? Falcon = null, FalcoScope? Falco = null)
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, PropertyNameCaseInsensitive = false,
        NumberHandling = JsonNumberHandling.Strict, MaxDepth = 8
    };
    internal void Check(long now)
    {
        // Exactly one identity. A tuple left beside a lease scope would be dead configuration that
        // reads as if it were checked.
        bool tuple = Boot != Guid.Empty || Cgroup != 0 || Pid != 0 || StartTicks != 0;
        if (!Guid.TryParseExact(TaskId, "N", out var id) || id == Guid.Empty || Node is not { Length: > 0 and <= 128 }
            || (Falco is { } scope ? tuple || Source != "falco" || Falcon != null || !scope.Valid
                : Boot == Guid.Empty || Cgroup == 0 || Pid <= 0 || StartTicks == 0)
            || Source is not ("falco" or "falcon") || Rule is not { Length: > 0 and <= 256 }
            || ExpiresUnixMs <= now || ListenPort is < 1 or > 65535 || A2aPort is < 1 or > 65535 || ListenPort == A2aPort)
            throw new InvalidDataException("Invalid or expired admission binding.");
        if (Falcon is { } identity)
        {
            if (Source != "falcon" || identity.NotBeforeUnixMs <= 0 || identity.NotBeforeUnixMs > now
                || identity.NotBeforeUnixMs >= ExpiresUnixMs || !ValidIdentifier(identity.TenantId)
                || !ValidIdentifier(identity.AgentId) || !ValidIdentifier(identity.ProcessInstanceId)
                || identity.ProfileSha256 is not { Length: 64 } || !identity.ProfileSha256.All(Uri.IsHexDigit))
                throw new InvalidDataException("Invalid Falcon admission identity.");
        }
    }
    internal static bool ValidIdentifier(string? value)
    {
        if (value is not { Length: > 0 and <= 128 }) return false;
        // String indexing avoids IEnumerable<char>'s enumerator allocation in registrar lookup.
        for (int i = 0; i < value.Length; i++) if (char.IsControl(value[i])) return false;
        return true;
    }
    internal string Fingerprint
    {
        get
        {
            object[] legacy = { TaskId, Node, Boot, Cgroup, Pid, StartTicks, Source, Rule, ExpiresUnixMs, ListenPort, A2aPort };
            // Preserve the exact original fingerprint for normalized-input installations. Vendor
            // identity is opt-in and binds both the process generation and approved schema bytes.
            object[] fields = Falcon is not null ? [..legacy, Falcon] : Falco is not null ? [..legacy, Falco] : legacy;
            return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(fields)));
        }
    }
    internal bool Matches(Alert a, long now) => now < ExpiresUnixMs && a.Version == 1
        && a.ObservedUnixMs >= now - 30_000 && a.ObservedUnixMs <= now + 2_000
        && a.Node == Node && a.Boot == Boot && a.Cgroup == Cgroup && a.Pid == Pid
        && a.StartTicks == StartTicks && a.Source == Source && a.Rule == Rule
        && a.AlertId is { Length: > 0 and <= 128 } && !a.AlertId.Any(char.IsControl);
}

// ProcessInstanceId is the vendor's opaque process-generation identifier, NEVER a recycled OS PID.
// A trusted admission registrar/operator must bind it to the native tuple; this parser cannot infer
// that relationship from a hostname. ProfileSha256 pins a reviewed mapping for the tenant's schema.
internal sealed record FalconIdentity(string TenantId, string AgentId, string ProcessInstanceId,
    long NotBeforeUnixMs, string ProfileSha256);

// LeaseCgroup is what SPLAT's GetTask reports for the task (metadata leaseCgroup); the operator's file
// may pin it, never supply it alone. OnDrop and MaxSilenceMs are the two places a sensor goes blind -
// a saturated ring buffer and a dead pipeline - and each is an explicit fail-open or fail-closed choice:
// "revoke" cancels the task on any evidence the sensor missed events, "tolerate" keeps it running;
// a null MaxSilenceMs tolerates silence, a value cancels after that long without a word from the node.
internal sealed record FalcoScope(string? LeaseCgroup, string OnDrop, long? MaxSilenceMs)
{
    internal const string Prefix = "/splat_leases/mission_";
    internal bool Valid => OnDrop is "revoke" or "tolerate" && MaxSilenceMs is null or (>= 10_000 and <= 86_400_000)
        && LeaseCgroup is { Length: 58 } path && path.StartsWith(Prefix, StringComparison.Ordinal)
        && Guid.TryParseExact(path[Prefix.Length..], "D", out var mission) && mission != Guid.Empty
        && path[Prefix.Length..] == mission.ToString("D");
}

// A trusted collector enriches the sensor event AT observation. Resolving a delayed bare PID
// by inspecting whichever process owns it now is a different observation and must be rejected.
internal sealed record Alert(int Version, string Source, string AlertId, string Rule, string Node,
    Guid Boot, ulong Cgroup, int Pid, ulong StartTicks, long ObservedUnixMs);

internal static class Credentials
{
    internal static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value : throw new InvalidOperationException("Missing " + name);
    internal static byte[] Digest(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));
}
