using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Linux;

internal static class BoundLeaseReceipt
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    internal static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    internal static LeaseOutcome Verify(LeaseSpec lease, LeaseOutcome outcome, int exitCode, JsonElement frame, string context)
    {
        string Read(string name) => frame.GetProperty(name).GetString() ?? throw new InvalidOperationException("Incomplete bound receipt.");
        string text = Read("outcomeCanonical");
        var fields = Parse(text);
        string policy = lease.ExecutionPolicy is null ? "none" : Hash(JsonSerializer.Serialize(lease.ExecutionPolicy, Json));
        bool Equal(string key, string expected) => fields.TryGetValue(key, out var value) && value == expected;
        if (!Equal("mission", lease.MissionId.ToString()) || !Equal("cgroup", outcome.CgroupId.ToString(CultureInfo.InvariantCulture))
            || !Equal("exit", exitCode.ToString(CultureInfo.InvariantCulture)) || !Equal("enforcing", "true")
            || !Equal("uid", outcome.WorkloadUid?.ToString(CultureInfo.InvariantCulture) ?? "unknown")
            || !Equal("counted", outcome.ViolationsCounted?.ToString(CultureInfo.InvariantCulture) ?? "unknown")
            || !Equal("reported", outcome.ViolationsReported?.ToString(CultureInfo.InvariantCulture) ?? "unknown")
            || !Equal("dropped", outcome.ViolationsDropped.ToString(CultureInfo.InvariantCulture))
            || !Equal("workspace", outcome.Workspace ?? "")
            || !Equal("workspaceRemoved", outcome.WorkspaceRemoved?.ToString().ToLowerInvariant() ?? "n/a")
            || !Equal("executionContext", context) || !Equal("executionPolicySha256", policy)
            || !Equal("workloadDrained", "true") || !Equal("effectivePolicySha256", Read("effectivePolicySha256"))
            // A daemon that stated its installed policy at admission must sign that same policy.
            || outcome.EffectivePolicySha256 is { } admitted && admitted != Read("effectivePolicySha256")
            || !IsHash(Read("effectivePolicySha256")) || Read("executionContext") != context
            || Read("executionPolicySha256") != policy || !frame.GetProperty("workloadDrained").GetBoolean()
            || !Equal("cancellationAccepted", frame.GetProperty("cancellationAccepted").GetBoolean() ? "true" : "false")
            // A lease that named hosts must come back with the proxy's signed account of them, and a
            // lease that named none must not carry one. The readable copies have to be the signed ones.
            || fields.ContainsKey("egressHosts") != (lease.AllowedEgressHosts is { Count: > 0 })
            || fields.TryGetValue("egressHosts", out string? signedHosts)
                && (!frame.TryGetProperty("egressHosts", out var shownHosts) || shownHosts.ValueKind != JsonValueKind.Array
                    || signedHosts != string.Join(",", shownHosts.EnumerateArray().Select(host => host.GetString()))
                    || !frame.TryGetProperty("egressRefused", out var shownRefused) || shownRefused.ValueKind != JsonValueKind.Number
                    || !Equal("egressRefused", shownRefused.GetRawText())))
            throw new InvalidOperationException("Signed lease receipt does not match this invocation or its drained workload.");
        byte[] keyBytes = Convert.FromBase64String(Read("outcomePublicKey"));
        if (Convert.ToHexStringLower(SHA256.HashData(keyBytes)) != Read("outcomeKeyId"))
            throw new InvalidOperationException("Guest outcome key digest mismatch.");
        using var key = RSA.Create();
        key.ImportRSAPublicKey(keyBytes, out int consumed);
        if (consumed != keyBytes.Length || key.KeySize < 2048 || !key.VerifyData(Encoding.UTF8.GetBytes(text),
            Convert.FromBase64String(Read("outcomeSignature")), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            throw new InvalidOperationException("Guest outcome signature refused.");
        return outcome with { WorkloadDrained = true, ExecutionPolicySha256 = policy == "none" ? null : policy,
            ExecutionContextSha256 = Hash(context), EffectivePolicySha256 = Read("effectivePolicySha256"),
            // From the signed text, so a receipt recovered after a lost connection carries them too.
            EgressHosts = fields.TryGetValue("egressHosts", out string? carried)
                ? carried.Split(',', StringSplitOptions.RemoveEmptyEntries) : outcome.EgressHosts,
            EgressRefused = fields.TryGetValue("egressRefused", out string? refused)
                ? ulong.Parse(refused, NumberStyles.None, CultureInfo.InvariantCulture) : outcome.EgressRefused };
    }

    private static bool IsHash(string value) => value.Length == 64 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static Dictionary<string, string> Parse(string text)
    {
        if (!text.StartsWith("splat-lease-outcome/2|", StringComparison.Ordinal))
            throw new InvalidOperationException("Bound invocations require outcome version 2.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string field in text.Split('|').Skip(1))
        {
            int separator = field.IndexOf('=');
            if (separator <= 0) throw new InvalidOperationException("Invalid receipt field.");
            var value = new StringBuilder();
            for (int i = separator + 1; i < field.Length; i++)
            {
                char c = field[i];
                if (c == '\\')
                {
                    if (++i == field.Length) throw new InvalidOperationException("Invalid receipt escape.");
                    c = field[i] switch { '\\' => '\\', 'p' => '|', 'n' => '\n', _ => throw new InvalidOperationException("Invalid receipt escape.") };
                }
                value.Append(c);
            }
            if (!fields.TryAdd(field[..separator], value.ToString())) throw new InvalidOperationException("Duplicate receipt field.");
        }
        // Fifteen fields, or seventeen when the lease had an egress proxy: both of its fields or neither.
        bool proxied = fields.ContainsKey("egressHosts") && fields.ContainsKey("egressRefused");
        if (fields.Count != (proxied ? 17 : 15)) throw new InvalidOperationException("Incomplete bound receipt.");
        return fields;
    }
}
