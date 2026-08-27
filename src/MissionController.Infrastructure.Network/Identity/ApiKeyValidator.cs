using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Network.Identity;

public sealed class ApiKeyValidator : IApiKeyValidator
{
    private readonly ConcurrentDictionary<string, (byte[] KeyHash, SecurityIdentityContext Identity)> _registeredKeys = new(StringComparer.Ordinal);

    public void RegisterApiKey(string apiKey, SecurityIdentityContext identity)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
            throw new ArgumentException("API key cannot be empty.", nameof(apiKey));

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));
        string keyId = Convert.ToHexString(hash);
        _registeredKeys[keyId] = (hash, identity);
    }

    public Task<TokenValidationResult> ValidateApiKeyAsync(string apiKey, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(apiKey))
        {
            return Task.FromResult(TokenValidationResult.Failed("API Key is missing or empty.", "API_KEY_EMPTY"));
        }

        // Clean ApiKey prefix if passed as header
        if (apiKey.StartsWith("ApiKey ", StringComparison.OrdinalIgnoreCase))
        {
            apiKey = apiKey.Substring(7).Trim();
        }

        byte[] incomingHash = SHA256.HashData(Encoding.UTF8.GetBytes(apiKey));

        SecurityIdentityContext? matchedIdentity = null;
        foreach (var entry in _registeredKeys.Values)
        {
            if (CryptographicOperations.FixedTimeEquals(entry.KeyHash, incomingHash))
            {
                matchedIdentity = entry.Identity;
                break;
            }
        }

        if (matchedIdentity == null)
        {
            return Task.FromResult(TokenValidationResult.Failed("Invalid API Key.", "INVALID_API_KEY"));
        }

        if (matchedIdentity.IsExpired())
        {
            return Task.FromResult(TokenValidationResult.Failed("API Key has expired.", "API_KEY_EXPIRED"));
        }

        return Task.FromResult(TokenValidationResult.Success(matchedIdentity));
    }
}
