using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Network.Identity;

public sealed class JwtTokenValidator : ITokenValidator
{
    private readonly string? _expectedIssuer;
    private readonly string? _expectedAudience;
    private readonly TimeSpan _clockSkew;
    private readonly ConcurrentDictionary<string, RSA> _rsaPublicKeys = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte[]> _hmacSecrets = new(StringComparer.Ordinal);

    public JwtTokenValidator(
        string? expectedIssuer = null,
        string? expectedAudience = null,
        TimeSpan? clockSkew = null)
    {
        _expectedIssuer = expectedIssuer;
        _expectedAudience = expectedAudience;
        _clockSkew = clockSkew ?? TimeSpan.FromSeconds(60);
    }

    public void RegisterRsaPublicKey(string keyId, RSA rsaPublicKey)
    {
        _rsaPublicKeys[keyId] = rsaPublicKey;
    }

    public void RegisterRsaPublicKeyPem(string keyId, string pemKey)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(pemKey);
        _rsaPublicKeys[keyId] = rsa;
    }

    public void RegisterHmacSecret(string keyId, byte[] secretKey)
    {
        _hmacSecrets[keyId] = (byte[])secretKey.Clone();
    }

    public void RegisterJwksJson(string jwksJson)
    {
        using var doc = JsonDocument.Parse(jwksJson);
        if (!doc.RootElement.TryGetProperty("keys", out var keysElement))
            return;

        foreach (var keyEl in keysElement.EnumerateArray())
        {
            string? kty = keyEl.TryGetProperty("kty", out var ktyEl) ? ktyEl.GetString() : null;
            if (kty != "RSA") continue;

            string? kid = keyEl.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : "default";
            string? n = keyEl.TryGetProperty("n", out var nEl) ? nEl.GetString() : null;
            string? e = keyEl.TryGetProperty("e", out var eEl) ? eEl.GetString() : null;

            if (kid != null && n != null && e != null)
            {
                var rsaParams = new RSAParameters
                {
                    Modulus = Base64UrlDecode(n),
                    Exponent = Base64UrlDecode(e)
                };
                var rsa = RSA.Create(rsaParams);
                _rsaPublicKeys[kid] = rsa;
            }
        }
    }

    public Task<TokenValidationResult> ValidateTokenAsync(string rawToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return Task.FromResult(TokenValidationResult.Failed("Token is empty.", "TOKEN_EMPTY"));
        }

        // Clean bearer prefix if present
        if (rawToken.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            rawToken = rawToken.Substring(7).Trim();
        }

        string[] parts = rawToken.Split('.');
        if (parts.Length != 3)
        {
            return Task.FromResult(TokenValidationResult.Failed("Malformed JWT token format.", "TOKEN_MALFORMED"));
        }

        try
        {
            byte[] headerBytes = Base64UrlDecode(parts[0]);
            byte[] payloadBytes = Base64UrlDecode(parts[1]);
            byte[] signatureBytes = Base64UrlDecode(parts[2]);

            using var headerDoc = JsonDocument.Parse(headerBytes);
            using var payloadDoc = JsonDocument.Parse(payloadBytes);

            var header = headerDoc.RootElement;
            var payload = payloadDoc.RootElement;

            string? alg = header.TryGetProperty("alg", out var algEl) ? algEl.GetString() : null;
            string? kid = header.TryGetProperty("kid", out var kidEl) ? kidEl.GetString() : null;

            if (string.IsNullOrEmpty(alg) || alg.Equals("none", StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(TokenValidationResult.Failed("Insecure or missing 'alg' algorithm header.", "UNSUPPORTED_ALGORITHM"));
            }

            // 1. Signature Verification
            string signedContent = $"{parts[0]}.{parts[1]}";
            byte[] signedContentBytes = Encoding.UTF8.GetBytes(signedContent);

            bool isSignatureValid = false;
            if (alg == "RS256")
            {
                RSA? rsa = null;
                if (!string.IsNullOrEmpty(kid) && _rsaPublicKeys.TryGetValue(kid, out var specificRsa))
                {
                    rsa = specificRsa;
                }
                else if (_rsaPublicKeys.Count == 1)
                {
                    rsa = _rsaPublicKeys.Values.First();
                }
                else if (_rsaPublicKeys.TryGetValue("default", out var defaultRsa))
                {
                    rsa = defaultRsa;
                }

                if (rsa == null)
                {
                    return Task.FromResult(TokenValidationResult.Failed($"No trusted RSA public key registered for kid '{kid}'.", "KEY_NOT_FOUND"));
                }

                isSignatureValid = rsa.VerifyData(signedContentBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            else if (alg == "HS256")
            {
                byte[]? secret = null;
                if (!string.IsNullOrEmpty(kid) && _hmacSecrets.TryGetValue(kid, out var specificSecret))
                {
                    secret = specificSecret;
                }
                else if (_hmacSecrets.Count == 1)
                {
                    secret = _hmacSecrets.Values.First();
                }
                else if (_hmacSecrets.TryGetValue("default", out var defaultSecret))
                {
                    secret = defaultSecret;
                }

                if (secret == null)
                {
                    return Task.FromResult(TokenValidationResult.Failed($"No trusted HMAC secret registered for kid '{kid}'.", "KEY_NOT_FOUND"));
                }

                using var hmac = new HMACSHA256(secret);
                byte[] expectedSig = hmac.ComputeHash(signedContentBytes);
                isSignatureValid = CryptographicOperations.FixedTimeEquals(expectedSig, signatureBytes);
            }
            else
            {
                return Task.FromResult(TokenValidationResult.Failed($"Unsupported algorithm: '{alg}'.", "UNSUPPORTED_ALGORITHM"));
            }

            if (!isSignatureValid)
            {
                return Task.FromResult(TokenValidationResult.Failed("Cryptographic signature verification failed.", "INVALID_SIGNATURE"));
            }

            // 2. Claims Validation
            var now = DateTimeOffset.UtcNow;

            // exp
            if (payload.TryGetProperty("exp", out var expEl))
            {
                long expSeconds = expEl.GetInt64();
                var expDate = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
                if (now - _clockSkew >= expDate)
                {
                    return Task.FromResult(TokenValidationResult.Failed($"Token expired at {expDate:O} (UTC).", "TOKEN_EXPIRED"));
                }
            }
            else
            {
                return Task.FromResult(TokenValidationResult.Failed("Missing required 'exp' claim.", "MISSING_CLAIM"));
            }

            // nbf
            if (payload.TryGetProperty("nbf", out var nbfEl))
            {
                long nbfSeconds = nbfEl.GetInt64();
                var nbfDate = DateTimeOffset.FromUnixTimeSeconds(nbfSeconds);
                if (now + _clockSkew < nbfDate)
                {
                    return Task.FromResult(TokenValidationResult.Failed($"Token is not yet valid (nbf: {nbfDate:O}).", "TOKEN_NOT_YET_VALID"));
                }
            }

            // iss
            if (_expectedIssuer != null)
            {
                string? iss = payload.TryGetProperty("iss", out var issEl) ? issEl.GetString() : null;
                if (!string.Equals(iss, _expectedIssuer, StringComparison.Ordinal))
                {
                    return Task.FromResult(TokenValidationResult.Failed($"Issuer mismatch. Expected '{_expectedIssuer}', got '{iss}'.", "ISSUER_MISMATCH"));
                }
            }

            // aud
            if (_expectedAudience != null)
            {
                bool audMatched = false;
                if (payload.TryGetProperty("aud", out var audEl))
                {
                    if (audEl.ValueKind == JsonValueKind.Array)
                    {
                        audMatched = audEl.EnumerateArray().Any(a => string.Equals(a.GetString(), _expectedAudience, StringComparison.Ordinal));
                    }
                    else if (audEl.ValueKind == JsonValueKind.String)
                    {
                        audMatched = string.Equals(audEl.GetString(), _expectedAudience, StringComparison.Ordinal);
                    }
                }

                if (!audMatched)
                {
                    return Task.FromResult(TokenValidationResult.Failed($"Audience mismatch. Expected '{_expectedAudience}'.", "AUDIENCE_MISMATCH"));
                }
            }

            // 3. Extract Identity & Claims Context
            string subject = payload.TryGetProperty("sub", out var subEl) ? subEl.GetString() ?? "anonymous" : "anonymous";
            string tenantId = payload.TryGetProperty("tenant_id", out var tidEl) ? tidEl.GetString() ?? "default"
                            : (payload.TryGetProperty("tid", out var tEl) ? tEl.GetString() ?? "default" : "default");

            var scopes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (payload.TryGetProperty("scope", out var scopeEl))
            {
                if (scopeEl.ValueKind == JsonValueKind.String)
                {
                    string? scpStr = scopeEl.GetString();
                    if (!string.IsNullOrWhiteSpace(scpStr))
                    {
                        foreach (var s in scpStr.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                        {
                            scopes.Add(s);
                        }
                    }
                }
                else if (scopeEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var s in scopeEl.EnumerateArray())
                    {
                        var str = s.GetString();
                        if (!string.IsNullOrEmpty(str)) scopes.Add(str);
                    }
                }
            }

            if (payload.TryGetProperty("scp", out var scpArr) && scpArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var s in scpArr.EnumerateArray())
                {
                    var str = s.GetString();
                    if (!string.IsNullOrEmpty(str)) scopes.Add(str);
                }
            }

            if (payload.TryGetProperty("roles", out var rolesArr) && rolesArr.ValueKind == JsonValueKind.Array)
            {
                foreach (var s in rolesArr.EnumerateArray())
                {
                    var str = s.GetString();
                    if (!string.IsNullOrEmpty(str)) scopes.Add($"role:{str}");
                }
            }

            var claims = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var prop in payload.EnumerateObject())
            {
                claims[prop.Name] = prop.Value.ToString();
            }

            long iat = payload.TryGetProperty("iat", out var iatEl) ? iatEl.GetInt64() : now.ToUnixTimeSeconds();
            long exp = payload.GetProperty("exp").GetInt64();

            var identity = new SecurityIdentityContext(
                OperatorIdentity: subject,
                TenantId: tenantId,
                Scopes: scopes,
                Claims: claims,
                IssuedAtUtc: DateTimeOffset.FromUnixTimeSeconds(iat),
                ExpiresAtUtc: DateTimeOffset.FromUnixTimeSeconds(exp),
                AuthMethod: $"JWT/{alg}");

            return Task.FromResult(TokenValidationResult.Success(identity));
        }
        catch (Exception ex)
        {
            return Task.FromResult(TokenValidationResult.Failed($"JWT decoding/validation error: {ex.Message}", "VALIDATION_EXCEPTION"));
        }
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string output = input.Replace('-', '+').Replace('_', '/');
        switch (output.Length % 4)
        {
            case 2: output += "=="; break;
            case 3: output += "="; break;
        }
        return Convert.FromBase64String(output);
    }
}
