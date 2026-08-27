using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Network.Identity;

public sealed class TokenLifecycleManager : ITokenLifecycleManager
{
    private readonly ICredentialVault _vault;
    private readonly ConcurrentDictionary<string, Func<CancellationToken, Task<TokenDescriptor?>>> _refreshHandlers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _tokenExpirations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _refreshLocks = new(StringComparer.Ordinal);

    public TokenLifecycleManager(ICredentialVault vault)
    {
        _vault = vault;
    }

    public void RegisterRefreshHandler(string secretKey, Func<CancellationToken, Task<TokenDescriptor?>> refreshHandler)
    {
        _refreshHandlers[secretKey] = refreshHandler;
    }

    public void TrackTokenExpiry(string secretKey, DateTimeOffset expiresAtUtc)
    {
        _tokenExpirations[secretKey] = expiresAtUtc;
    }

    public async Task<string?> GetValidAccessTokenAsync(string secretKey, int bufferSeconds = 120, CancellationToken cancellationToken = default)
    {
        string? currentToken = await _vault.RetrieveSecretStringAsync(secretKey, cancellationToken);

        bool needsRefresh = string.IsNullOrEmpty(currentToken);

        if (!needsRefresh && !string.IsNullOrEmpty(currentToken))
        {
            if (_tokenExpirations.TryGetValue(secretKey, out var expiry))
            {
                if (DateTimeOffset.UtcNow.AddSeconds(bufferSeconds) >= expiry)
                {
                    needsRefresh = true;
                }
            }
            else
            {
                // Try parsing expiration from JWT payload if possible
                var jwtExpiry = TryExtractJwtExpiration(currentToken);
                if (jwtExpiry.HasValue)
                {
                    _tokenExpirations[secretKey] = jwtExpiry.Value;
                    if (DateTimeOffset.UtcNow.AddSeconds(bufferSeconds) >= jwtExpiry.Value)
                    {
                        needsRefresh = true;
                    }
                }
            }
        }

        if (needsRefresh)
        {
            var refreshResult = await RefreshTokenAsync(secretKey, cancellationToken);
            if (refreshResult.Success && refreshResult.Token != null)
            {
                return refreshResult.Token.AccessToken;
            }

            // Fallback to existing token if refresh failed but current token hasn't fully expired yet
            if (!string.IsNullOrEmpty(currentToken))
            {
                if (_tokenExpirations.TryGetValue(secretKey, out var exp) && DateTimeOffset.UtcNow < exp)
                {
                    return currentToken;
                }
            }

            return null;
        }

        return currentToken;
    }

    public async Task<TokenRefreshResult> RefreshTokenAsync(string secretKey, CancellationToken cancellationToken = default)
    {
        if (!_refreshHandlers.TryGetValue(secretKey, out var handler))
        {
            return new TokenRefreshResult(false, null, $"No refresh handler registered for key '{secretKey}'.");
        }

        var sem = _refreshLocks.GetOrAdd(secretKey, _ => new SemaphoreSlim(1, 1));
        await sem.WaitAsync(cancellationToken);

        try
        {
            // Re-check if another thread refreshed it while we were waiting
            if (_tokenExpirations.TryGetValue(secretKey, out var exp) && DateTimeOffset.UtcNow.AddSeconds(60) < exp)
            {
                string? token = await _vault.RetrieveSecretStringAsync(secretKey, cancellationToken);
                if (!string.IsNullOrEmpty(token))
                {
                    return new TokenRefreshResult(true, new TokenDescriptor(token, "Bearer", exp));
                }
            }

            var newTokenDescriptor = await handler(cancellationToken);
            if (newTokenDescriptor == null)
            {
                return new TokenRefreshResult(false, null, "Refresh handler returned null descriptor.");
            }

            await _vault.StoreSecretStringAsync(secretKey, newTokenDescriptor.AccessToken, cancellationToken);
            if (!string.IsNullOrEmpty(newTokenDescriptor.RefreshToken))
            {
                await _vault.StoreSecretStringAsync($"{secretKey}.RefreshToken", newTokenDescriptor.RefreshToken, cancellationToken);
            }

            _tokenExpirations[secretKey] = newTokenDescriptor.ExpiresAtUtc;

            return new TokenRefreshResult(true, newTokenDescriptor);
        }
        catch (Exception ex)
        {
            return new TokenRefreshResult(false, null, $"Token refresh failed: {ex.Message}");
        }
        finally
        {
            sem.Release();
        }
    }

    private static DateTimeOffset? TryExtractJwtExpiration(string token)
    {
        try
        {
            if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                token = token.Substring(7).Trim();

            string[] parts = token.Split('.');
            if (parts.Length != 3) return null;

            string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            using var doc = JsonDocument.Parse(payloadJson);
            if (doc.RootElement.TryGetProperty("exp", out var expEl))
            {
                return DateTimeOffset.FromUnixTimeSeconds(expEl.GetInt64());
            }
        }
        catch
        {
            // Ignore parse failures
        }

        return null;
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
