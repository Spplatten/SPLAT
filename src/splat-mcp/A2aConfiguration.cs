using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using MissionController.Core;
using MissionController.Infrastructure.Data.Catalog;

namespace SplatMcp;

internal sealed record A2aCaller(string TenantId, string CallerId, string TokenSha256,
    string[] Skills, DateTimeOffset ExpiresUtc, bool RequireDelegation = false,
    int? MaxConcurrentTasks = null, int? MaxRetainedTasks = null)
{
    internal OperatorIdentity Identity => new(CallerId, $"a2a:{TenantId}:{CallerId}",
        OperatorAuthenticationMethod.ApiKey, "a2a-https");
}

internal sealed record A2aConfiguration(int SchemaVersion, string AgentId, string AgentVersion,
    int Port, string CertificateFile, A2aCaller[] Callers, int MaxConcurrentTasks = 4, int MaxTasks = 512,
    string? DelegationKeyFile = null, A2aDelegationIssuer[]? DelegationIssuers = null)
{
    internal const string Extension = "urn:splat:a2a:template-lease:v1";
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        MaxDepth = 24
    };

    internal static A2aConfiguration Load(string path)
    {
        if (new FileInfo(path).Length > 65536) throw new InvalidOperationException("A2A configuration exceeds 64 KiB.");
        using var document = JsonDocument.Parse(File.ReadAllBytes(path), new JsonDocumentOptions { MaxDepth = 24 });
        A2aJson.Unique(document.RootElement);
        var config = document.RootElement.Deserialize<A2aConfiguration>(Json)
            ?? throw new InvalidOperationException("An A2A configuration is required.");
        config.Validate();
        return config;
    }

    internal void Validate()
    {
        AgentManifestApproval.ValidateSelection(AgentId, AgentVersion);
        if (SchemaVersion != 1 || Port is < 1024 or > 65535 || MaxConcurrentTasks is < 1 or > 16
            || MaxTasks < MaxConcurrentTasks || MaxTasks > 4096 || Callers is null || Callers.Length is < 1 or > 64
            || string.IsNullOrWhiteSpace(CertificateFile) || !Path.IsPathFullyQualified(CertificateFile)
            || !File.Exists(CertificateFile))
            throw new InvalidOperationException("A2A needs a certificate file, bounded capacity and explicit callers.");
        var identities = new HashSet<string>(StringComparer.Ordinal);
        var hashes = new HashSet<string>(StringComparer.Ordinal);
        foreach (var caller in Callers)
        {
            if (caller is null || !A2aJson.Identifier(caller.TenantId) || !A2aJson.Identifier(caller.CallerId)
                || !identities.Add(caller.TenantId + ":" + caller.CallerId)
                || caller.TokenSha256 is null || !Regex.IsMatch(caller.TokenSha256, "\\A[0-9a-f]{64}\\z")
                || !hashes.Add(caller.TokenSha256) || caller.ExpiresUtc == default
                || caller.Skills is null || caller.Skills.Length is < 1 or > 6
                || caller.Skills.Any(s => !A2aJson.Identifier(s))
                || caller.Skills.Distinct(StringComparer.Ordinal).Count() != caller.Skills.Length)
                throw new InvalidOperationException("A2A callers need unique identities, unique token hashes, expiry and explicit skills.");
            if (caller.MaxConcurrentTasks is < 1 || caller.MaxConcurrentTasks > MaxConcurrentTasks
                || caller.MaxRetainedTasks is < 1 || caller.MaxRetainedTasks > MaxTasks)
                throw new InvalidOperationException("Per-caller capacity must fit within host capacity.");
        }
        A2aDelegation.ValidateConfiguration(this);
    }

    internal A2aCaller? Authenticate(string authorization)
    {
        if (!authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var token = authorization[7..];
        if (!Regex.IsMatch(token, "\\A[A-Za-z0-9_-]{43,128}\\z")) return null;
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(token));
        A2aCaller? found = null;
        // A token authorizes one configured principal. Caller IDs in messages are never identity.
        foreach (var caller in Callers)
            if (CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(caller.TokenSha256))
                && caller.ExpiresUtc > DateTimeOffset.UtcNow) found = caller;
        return found;
    }
}

internal static class A2aJson
{
    internal static bool Identifier(string? value) => value is not null
        && Regex.IsMatch(value, "\\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\\z");

    internal static void Unique(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
            {
                if (!seen.Add(property.Name)) throw new A2aException(-32602, "Duplicate JSON property.");
                Unique(property.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) Unique(item);
    }

    internal static void Fields(JsonElement value, params string[] allowed)
    {
        if (value.ValueKind != JsonValueKind.Object
            || value.EnumerateObject().Any(p => !allowed.Contains(p.Name, StringComparer.Ordinal)))
            throw new A2aException(-32602, "Unsupported or invalid fields.");
        Unique(value);
    }

    internal static string Text(JsonElement value, string name) => value.TryGetProperty(name, out var item)
        && item.ValueKind == JsonValueKind.String ? item.GetString()! : throw new A2aException(-32602, $"{name} must be a string.");
}

internal sealed class A2aException(int code, string message, int httpStatus = 200) : Exception(message)
{
    internal int Code { get; } = code;
    internal int HttpStatus { get; } = httpStatus;
}
