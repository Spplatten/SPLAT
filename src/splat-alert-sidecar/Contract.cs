using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Splat.AlertSidecar;

// The admission owner supplies this immutable binding, outside the monitored workload.
// A task UUID never comes from the alert. PID alone, human process names and guest wall time
// are deliberately insufficient. Identity is for THIS process, not arbitrary descendants.
internal sealed record Binding(string TaskId, string Node, Guid Boot, ulong Cgroup, int Pid,
    ulong StartTicks, string Source, string Rule, long ExpiresUnixMs, int ListenPort, int A2aPort,
    FalconIdentity? Falcon = null)
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow, PropertyNameCaseInsensitive = false,
        NumberHandling = JsonNumberHandling.Strict, MaxDepth = 8
    };
    internal void Check(long now)
    {
        if (!Guid.TryParseExact(TaskId, "N", out var id) || id == Guid.Empty || Node is not { Length: > 0 and <= 128 }
            || Boot == Guid.Empty || Cgroup == 0 || Pid <= 0 || StartTicks == 0
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
    internal static bool ValidIdentifier(string? value) => value is { Length: > 0 and <= 128 } && !value.Any(char.IsControl);
    internal string Fingerprint
    {
        get
        {
            object[] legacy = { TaskId, Node, Boot, Cgroup, Pid, StartTicks, Source, Rule, ExpiresUnixMs, ListenPort, A2aPort };
            // Preserve the exact original fingerprint for normalized-input installations. Vendor
            // identity is opt-in and binds both the process generation and approved schema bytes.
            object[] fields = Falcon is null ? legacy : [..legacy, Falcon];
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
