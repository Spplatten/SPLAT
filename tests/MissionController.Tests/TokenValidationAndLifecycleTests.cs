using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Network.Identity;
using Xunit;

namespace MissionController.Tests;

public class TokenValidationAndLifecycleTests
{
    private sealed class InMemoryCredentialVault : ICredentialVault
    {
        private readonly Dictionary<string, string> _store = new(StringComparer.Ordinal);

        public Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default)
        {
            _store[key] = Convert.ToBase64String(secretBytes);
            return Task.CompletedTask;
        }

        public Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            if (_store.TryGetValue(key, out var val))
            {
                return Task.FromResult<byte[]?>(Convert.FromBase64String(val));
            }
            return Task.FromResult<byte[]?>(null);
        }

        public Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default)
        {
            _store.TryGetValue(key, out var val);
            return Task.FromResult(val);
        }

        public Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default)
        {
            _store[key] = secretString;
            return Task.CompletedTask;
        }

        public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            _store.Remove(key);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task JwtTokenValidator_ValidRs256Token_PassesWithIdentityContext()
    {
        using var rsa = RSA.Create(2048);
        var validator = new JwtTokenValidator(expectedIssuer: "https://auth.enterprise.local", expectedAudience: "mission-controller-api");
        validator.RegisterRsaPublicKey("key-1", rsa);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string token = CreateRs256Jwt(rsa, "key-1", new
        {
            iss = "https://auth.enterprise.local",
            aud = "mission-controller-api",
            sub = "operator-alice",
            tenant_id = "tenant-secops-01",
            scope = "agent:execute tools:read admin:override",
            iat = now,
            exp = now + 3600
        });

        var result = await validator.ValidateTokenAsync($"Bearer {token}");

        Assert.True(result.IsValid);
        Assert.NotNull(result.IdentityContext);
        Assert.Equal("operator-alice", result.IdentityContext.OperatorIdentity);
        Assert.Equal("tenant-secops-01", result.IdentityContext.TenantId);
        Assert.True(result.IdentityContext.HasScope("agent:execute"));
        Assert.True(result.IdentityContext.HasScope("admin:override"));
        Assert.False(result.IdentityContext.HasScope("super:root"));
    }

    [Fact]
    public async Task JwtTokenValidator_ExpiredToken_ReturnsFailure()
    {
        using var rsa = RSA.Create(2048);
        var validator = new JwtTokenValidator(clockSkew: TimeSpan.Zero);
        validator.RegisterRsaPublicKey("key-1", rsa);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string token = CreateRs256Jwt(rsa, "key-1", new
        {
            iss = "https://auth.enterprise.local",
            sub = "operator-alice",
            exp = now - 100 // Expired
        });

        var result = await validator.ValidateTokenAsync(token);

        Assert.False(result.IsValid);
        Assert.Equal("TOKEN_EXPIRED", result.ErrorCode);
    }

    [Fact]
    public async Task JwtTokenValidator_TamperedPayload_FailsSignature()
    {
        using var rsa = RSA.Create(2048);
        var validator = new JwtTokenValidator();
        validator.RegisterRsaPublicKey("key-1", rsa);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string token = CreateRs256Jwt(rsa, "key-1", new
        {
            sub = "operator-bob",
            exp = now + 3600
        });

        string[] parts = token.Split('.');
        // Tamper payload to escalate privilege
        string tamperedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"sub\":\"operator-root\",\"exp\":" + (now + 3600) + "}"));
        string forgedToken = $"{parts[0]}.{tamperedPayload}.{parts[2]}";

        var result = await validator.ValidateTokenAsync(forgedToken);

        Assert.False(result.IsValid);
        Assert.Equal("INVALID_SIGNATURE", result.ErrorCode);
    }

    [Fact]
    public async Task JwtTokenValidator_RejectsNoneAlgorithm()
    {
        var validator = new JwtTokenValidator();

        string header = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"typ\":\"JWT\"}"));
        string payload = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"sub\":\"hacker\",\"exp\":9999999999}"));
        string noneToken = $"{header}.{payload}.";

        var result = await validator.ValidateTokenAsync(noneToken);

        Assert.False(result.IsValid);
        Assert.Equal("UNSUPPORTED_ALGORITHM", result.ErrorCode);
    }

    [Fact]
    public async Task JwtTokenValidator_ValidHs256Token_PassesSuccessfully()
    {
        byte[] hmacKey = RandomNumberGenerator.GetBytes(32);
        var validator = new JwtTokenValidator();
        validator.RegisterHmacSecret("hs-key-1", hmacKey);

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string header = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"hs-key-1\"}"));
        string payload = Base64UrlEncode(Encoding.UTF8.GetBytes("{\"sub\":\"service-agent-42\",\"exp\":" + (now + 1800) + ",\"scope\":\"tools:execute\"}"));
        
        byte[] toSign = Encoding.UTF8.GetBytes($"{header}.{payload}");
        using var hmac = new HMACSHA256(hmacKey);
        string sig = Base64UrlEncode(hmac.ComputeHash(toSign));
        string token = $"{header}.{payload}.{sig}";

        var result = await validator.ValidateTokenAsync(token);

        Assert.True(result.IsValid);
        Assert.Equal("service-agent-42", result.IdentityContext?.OperatorIdentity);
        Assert.True(result.IdentityContext?.HasScope("tools:execute"));
    }

    [Fact]
    public async Task ApiKeyValidator_ValidAndInvalidKeys_EvaluatesCorrectly()
    {
        var validator = new ApiKeyValidator();
        string validKey = "mc_live_secops_secret_token_1234567890";
        string invalidKey = "mc_live_secops_secret_token_forged_key";

        var identity = new SecurityIdentityContext(
            OperatorIdentity: "pipeline-automation-service",
            TenantId: "corp-infra",
            Scopes: new HashSet<string> { "automation:run", "logs:read" },
            Claims: new Dictionary<string, string> { ["source"] = "ci_cd" },
            IssuedAtUtc: DateTimeOffset.UtcNow,
            ExpiresAtUtc: DateTimeOffset.UtcNow.AddDays(30),
            AuthMethod: "APIKey");

        validator.RegisterApiKey(validKey, identity);

        // Test valid
        var validResult = await validator.ValidateApiKeyAsync($"ApiKey {validKey}");
        Assert.True(validResult.IsValid);
        Assert.Equal("pipeline-automation-service", validResult.IdentityContext?.OperatorIdentity);
        Assert.True(validResult.IdentityContext?.HasScope("automation:run"));

        // Test invalid
        var invalidResult = await validator.ValidateApiKeyAsync(invalidKey);
        Assert.False(invalidResult.IsValid);
        Assert.Equal("INVALID_API_KEY", invalidResult.ErrorCode);
    }

    [Fact]
    public async Task TokenLifecycleManager_NearExpiryToken_TriggersProactiveAutoRefresh()
    {
        var vault = new InMemoryCredentialVault();
        var lifecycleManager = new TokenLifecycleManager(vault);

        int refreshCallCount = 0;
        string secretKey = "GoogleCloud.ServiceAccountToken";

        // Initial token expiring in 30 seconds (within the 120s buffer)
        await vault.StoreSecretStringAsync(secretKey, "initial-token-near-expiry");
        lifecycleManager.TrackTokenExpiry(secretKey, DateTimeOffset.UtcNow.AddSeconds(30));

        lifecycleManager.RegisterRefreshHandler(secretKey, ct =>
        {
            Interlocked.Increment(ref refreshCallCount);
            var freshToken = new TokenDescriptor(
                AccessToken: "freshly-minted-access-token",
                TokenType: "Bearer",
                ExpiresAtUtc: DateTimeOffset.UtcNow.AddHours(1));
            return Task.FromResult<TokenDescriptor?>(freshToken);
        });

        // Request token with 120s buffer threshold
        string? activeToken = await lifecycleManager.GetValidAccessTokenAsync(secretKey, bufferSeconds: 120);

        Assert.Equal("freshly-minted-access-token", activeToken);
        Assert.Equal(1, refreshCallCount);

        // Calling again immediately should NOT trigger another refresh because the new token is valid for 1 hour
        string? cachedToken = await lifecycleManager.GetValidAccessTokenAsync(secretKey, bufferSeconds: 120);
        Assert.Equal("freshly-minted-access-token", cachedToken);
        Assert.Equal(1, refreshCallCount);

        // Vault should also be updated
        string? vaultToken = await vault.RetrieveSecretStringAsync(secretKey);
        Assert.Equal("freshly-minted-access-token", vaultToken);
    }

    private static string CreateRs256Jwt(RSA rsa, string kid, object payloadObj)
    {
        string headerJson = JsonSerializer.Serialize(new { alg = "RS256", typ = "JWT", kid = kid });
        string payloadJson = JsonSerializer.Serialize(payloadObj);

        string header = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        string payload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        byte[] toSign = Encoding.UTF8.GetBytes($"{header}.{payload}");
        byte[] sig = rsa.SignData(toSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return $"{header}.{payload}.{Base64UrlEncode(sig)}";
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
