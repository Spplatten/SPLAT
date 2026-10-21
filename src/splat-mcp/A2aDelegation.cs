using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MissionController.Core.Models;

namespace SplatMcp;

internal sealed record A2aDelegationIssuer(string AgentId, string ContractSha256, string PublicKey);
internal sealed record A2aDelegationGrant(int Version, string Issuer, string IssuerVersion,
    string Audience, string AudienceVersion, string TenantId, string CallerId, string Skill,
    string ParentTaskId, string Nonce, DateTimeOffset ExpiresUtc, int Depth, LeaseAuthority Authority);

internal sealed class A2aDelegation : IDisposable
{
    private readonly A2aConfiguration _config;
    private readonly ECDsa? _signer;

    internal A2aDelegation(A2aConfiguration config)
    {
        _config = config;
        if (config.DelegationKeyFile is not null)
        {
            _signer = ECDsa.Create();
            try
            {
                _signer.ImportFromPem(File.ReadAllText(config.DelegationKeyFile));
                if (_signer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                    throw new InvalidOperationException("Delegation requires a P-256 key.");
                _signer.ExportECPrivateKey();
            }
            catch { _signer.Dispose(); throw; }
        }
    }

    internal static void ValidateConfiguration(A2aConfiguration config)
    {
        if (config.DelegationKeyFile is { } path && (!Path.IsPathFullyQualified(path) || !File.Exists(path)
            || new FileInfo(path).Length > 8192))
            throw new InvalidOperationException("Delegation signing requires a bounded operator-owned key file.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        if (config.DelegationIssuers?.Length > 64) throw new InvalidOperationException("Too many delegation issuers.");
        foreach (var issuer in config.DelegationIssuers ?? [])
        {
            if (!A2aJson.Identifier(issuer.AgentId) || !Hash(issuer.ContractSha256)
                || !seen.Add(issuer.AgentId + ":" + issuer.ContractSha256))
                throw new InvalidOperationException("Delegation issuers need unique, pinned agent contracts.");
            using var key = PublicKey(issuer.PublicKey);
        }
    }

    internal string Issue(A2aDelegationGrant grant)
    {
        if (_signer is null) throw new A2aException(-32000, "Delegation signing is not configured.", 403);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(grant, A2aConfiguration.Json);
        // Different tasks can delegate concurrently; the shared platform key is not thread-safe.
        lock (_signer)
            return Encode(bytes) + "." + Encode(_signer.SignData(bytes, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    internal A2aDelegationGrant Verify(string token, A2aCaller caller, string skill)
    {
        try
        {
            if (token.Length > 49152) throw new InvalidOperationException();
            var parts = token.Split('.');
            if (parts.Length != 2) throw new InvalidOperationException();
            byte[] bytes = Decode(parts[0]), signature = Decode(parts[1]);
            using var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 24 });
            A2aJson.Unique(doc.RootElement);
            var grant = doc.RootElement.Deserialize<A2aDelegationGrant>(A2aConfiguration.Json)!;
            var issuer = (_config.DelegationIssuers ?? []).SingleOrDefault(i =>
                i.AgentId == grant.Issuer && i.ContractSha256 == grant.IssuerVersion);
            if (issuer is null || signature.Length != 64) throw new InvalidOperationException();
            using var key = PublicKey(issuer.PublicKey);
            if (!key.VerifyData(bytes, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)
                || grant.Version != 1 || grant.Audience != _config.AgentId || grant.AudienceVersion != _config.AgentVersion
                || grant.TenantId != caller.TenantId || grant.CallerId != caller.CallerId || grant.Skill != skill
                || grant.ExpiresUtc > caller.ExpiresUtc || grant.ExpiresUtc <= DateTimeOffset.UtcNow.AddSeconds(5)
                || grant.ExpiresUtc > DateTimeOffset.UtcNow.AddSeconds(300) || grant.Depth is < 1 or > 4
                || !A2aJson.Identifier(grant.ParentTaskId) || !Guid.TryParseExact(grant.Nonce, "N", out _)
                || grant.Authority is null)
                throw new InvalidOperationException();
            return grant;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or CryptographicException
            or InvalidOperationException or ArgumentException or NullReferenceException)
        { throw new A2aException(-32000, "Invalid, expired or out-of-scope delegation.", 403); }
    }

    private static ECDsa PublicKey(string encoded)
    {
        if (encoded is null || encoded.Length > 1024) throw new InvalidOperationException("Invalid delegation key.");
        var key = ECDsa.Create();
        try
        {
            var bytes = Convert.FromBase64String(encoded);
            key.ImportSubjectPublicKeyInfo(bytes, out int read);
            if (read != bytes.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new InvalidOperationException("Delegation requires a P-256 public key.");
            return key;
        }
        catch { key.Dispose(); throw; }
    }

    internal static bool Hash(string? value) => value is { Length: 64 }
        && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Decode(string text)
    {
        if (text.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))) throw new FormatException();
        return Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
    }
    public void Dispose() => _signer?.Dispose();
}
