using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Splat.AlertSidecar;

// These expectations must come from the admission owner BEFORE delivery. Never build them
// from the receipt being checked: a self-signed attacker receipt is internally consistent too.
internal sealed record ReceiptExpectation(string TaskId, string MissionId, ulong Cgroup,
    string DaemonKeySha256, string ExecutionContext, string ExecutionPolicySha256,
    string EffectivePolicySha256)
{
    internal void Check()
    {
        if (!Guid.TryParseExact(TaskId, "N", out var task) || task == Guid.Empty
            || !Guid.TryParseExact(MissionId, "D", out var mission) || mission != task || Cgroup == 0
            || !CancellationReceiptProof.IsHash(DaemonKeySha256)
            || !(ExecutionPolicySha256 == "none" || CancellationReceiptProof.IsHash(ExecutionPolicySha256))
            || !CancellationReceiptProof.IsHash(EffectivePolicySha256) || ExecutionContext is not { Length: > 0 and <= 4096 })
            throw new InvalidDataException("Invalid pre-admission receipt expectations.");
        using var context = StrictJson.Parse(Encoding.UTF8.GetBytes(ExecutionContext));
        _ = CancellationReceiptProof.ContextIdentityHash(context.RootElement);
        if (context.RootElement.GetProperty("taskId").GetString() != TaskId)
            throw new InvalidDataException("Context does not name the admitted task.");
    }
}

internal sealed record VerifiedCancellation(string TaskId, ulong Cgroup, string DaemonKeySha256,
    string SignedOutcomeSha256, bool SignatureVerified, bool DaemonAttestsDrain,
    bool DaemonAttestsCancellation);

internal static class CancellationReceiptProof
{
    private static readonly string[] Fields = ["mission", "cgroup", "enforcing", "uid", "exit",
        "counted", "reported", "dropped", "workspace", "workspaceRemoved", "executionPolicySha256",
        "executionContext", "effectivePolicySha256", "workloadDrained", "cancellationAccepted"];
    internal static bool IsHash(string? text) => text is { Length: 64 }
        && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static string ContextIdentityHash(JsonElement context)
    {
        // A2A metadata omits null optional fields; native signing retains them. Compare the
        // metadata's typed identity semantically, while STILL verifying receipt bytes exactly.
        // Sorting, dropping only null optionals, and restricting the schema avoids accidental
        // dependence on JSON presentation/order without equating different authority values.
        string[] required = ["agentId", "contractSha256", "tenantId", "callerId", "taskId"];
        string[] optional = ["parentTaskId", "delegationSha256", "requestingAgentId", "requestingContractSha256"];
        var fields = new SortedDictionary<string, string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in context.EnumerateObject())
        {
            if (!seen.Add(property.Name) || !required.Contains(property.Name) && !optional.Contains(property.Name))
                throw new InvalidDataException("Unknown or duplicate execution-context identity field.");
            if (property.Value.ValueKind == JsonValueKind.Null && optional.Contains(property.Name)) continue;
            string value = property.Value.GetString() ?? throw new InvalidDataException("Required context identity absent.");
            if (value.Length is < 1 or > 128 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('_' or '.' or '-'))
                || property.Name.EndsWith("Sha256", StringComparison.Ordinal) && !IsHash(value))
                throw new InvalidDataException("Invalid context identity value.");
            fields.Add(property.Name, value);
        }
        if (required.Any(key => !fields.ContainsKey(key))) throw new InvalidDataException("Incomplete execution identity.");
        return Hash(JsonSerializer.SerializeToUtf8Bytes(fields));
    }

    internal static VerifiedCancellation VerifyTask(JsonElement task, ReceiptExpectation expected)
    {
        expected.Check();
        if (task.GetProperty("id").GetString() != expected.TaskId
            || task.GetProperty("status").GetProperty("state").GetString() != "TASK_STATE_CANCELED")
            throw new InvalidDataException("Expected the canceled target task.");
        var metadata = task.GetProperty("metadata").GetProperty(Control.Extension);
        if (!metadata.GetProperty("cancellationRequested").GetBoolean()
            || !metadata.GetProperty("dispatched").GetBoolean())
            throw new InvalidDataException("Cancellation must concern a dispatched workload.");

        // The shipping A2A snapshot embeds MCP text artifacts. Extract every exact agentLease
        // line, then require one. Workload text may contain JSON too; only a pinned signature
        // over the expected invocation can authorize this proof. Multiple candidates fail closed.
        JsonElement? receipt = null;
        foreach (var artifact in task.GetProperty("artifacts").EnumerateArray())
        foreach (var part in artifact.GetProperty("parts").EnumerateArray())
        {
            string text = part.GetProperty("text").GetString() ?? "";
            if (text.Length > 1_048_576) throw new InvalidDataException("Artifact exceeds proof budget.");
            foreach (string line in text.Split('\n'))
            {
                string candidate = line.Trim();
                if (!candidate.StartsWith("{\"agentLease\":", StringComparison.Ordinal)) continue;
                using var parsed = StrictJson.Parse(Encoding.UTF8.GetBytes(candidate));
                if (receipt != null) throw new InvalidDataException("Ambiguous native receipt artifacts.");
                receipt = parsed.RootElement.GetProperty("agentLease").Clone();
            }
        }
        if (receipt is null) throw new InvalidDataException("No signed native receipt retained.");
        return VerifyReceipt(receipt.Value, expected);
    }

    internal static VerifiedCancellation VerifyReceipt(JsonElement receipt, ReceiptExpectation expected)
    {
        expected.Check();
        string Read(string key) => receipt.GetProperty(key).GetString()
            ?? throw new InvalidDataException("Missing native receipt field.");
        // Preserve exact signed bytes. Do not reserialize the execution context or normalize
        // whitespace/escapes. Receipt v2 is the format emitted by native outcome::bound_outcome.
        string canonical = Read("SignedOutcome");
        if (Encoding.UTF8.GetByteCount(canonical) > 32768) throw new InvalidDataException("Oversized receipt.");
        byte[] publicKey = Convert.FromBase64String(Read("OutcomePublicKey"));
        if (publicKey.Length > 4096 || Hash(publicKey) != expected.DaemonKeySha256
            || Read("OutcomeKeyId") != expected.DaemonKeySha256)
            throw new InvalidDataException("Receipt signer differs from the independently pinned daemon key.");
        using var rsa = RSA.Create();
        rsa.ImportRSAPublicKey(publicKey, out int consumed);
        if (consumed != publicKey.Length || rsa.KeySize is < 2048 or > 8192
            || !rsa.VerifyData(Encoding.UTF8.GetBytes(canonical), Convert.FromBase64String(Read("OutcomeSignature")),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            throw new InvalidDataException("Native signature refused.");
        var fields = Parse(canonical);
        bool Equal(string key, string value) => fields[key] == value;
        if (!Equal("mission", expected.MissionId) || !Equal("cgroup", expected.Cgroup.ToString(CultureInfo.InvariantCulture))
            || !Equal("executionContext", expected.ExecutionContext)
            || !Equal("executionPolicySha256", expected.ExecutionPolicySha256)
            || !Equal("effectivePolicySha256", expected.EffectivePolicySha256)
            || !Equal("enforcing", "true") || !Equal("workloadDrained", "true") || !Equal("cancellationAccepted", "true"))
            throw new InvalidDataException("Receipt does not attest cancellation/drain of the expected enforced invocation.");
        return new(expected.TaskId, expected.Cgroup, expected.DaemonKeySha256,
            Hash(Encoding.UTF8.GetBytes(canonical)), true, true, true);
    }

    private static Dictionary<string, string> Parse(string text)
    {
        string[] parts = text.Split('|');
        if (parts.Length != 16 || parts[0] != "splat-lease-outcome/2")
            throw new InvalidDataException("Expected complete native receipt v2.");
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string part in parts.Skip(1))
        {
            int separator = part.IndexOf('=');
            if (separator <= 0 || !Fields.Contains(part[..separator], StringComparer.Ordinal))
                throw new InvalidDataException("Unknown native receipt field.");
            var value = new StringBuilder();
            for (int i = separator + 1; i < part.Length; i++)
            {
                char c = part[i];
                if (c == '\\')
                {
                    if (++i == part.Length) throw new InvalidDataException("Incomplete native escape.");
                    c = part[i] switch { '\\' => '\\', 'p' => '|', 'n' => '\n',
                        _ => throw new InvalidDataException("Unknown native escape.") };
                }
                value.Append(c);
            }
            if (!fields.TryAdd(part[..separator], value.ToString())) throw new InvalidDataException("Duplicate native field.");
        }
        return fields;
    }
}
