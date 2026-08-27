using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Network.Identity;

public sealed partial class PromptCredentialSanitizer : ICredentialSanitizer
{
    private readonly ConcurrentBag<string> _knownSecrets = new();

    // Regex patterns for sensitive credentials
    private static readonly Regex JwtRegex = new(
        @"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b",
        RegexOptions.Compiled);

    private static readonly Regex BearerHeaderRegex = new(
        @"Bearer\s+([A-Za-z0-9\-_\.]+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex PemPrivateKeyRegex = new(
        @"-----BEGIN (?:[A-Z\s]+)?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z\s]+)?PRIVATE KEY-----",
        RegexOptions.Compiled);

    private static readonly Regex CommonApiKeyRegex = new(
        @"\b(?:mc_live_[a-zA-Z0-9_]{10,}|sk-[a-zA-Z0-9T3BlbkFJ]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35})\b",
        RegexOptions.Compiled);

    public void RegisterKnownSecret(string secret)
    {
        if (!string.IsNullOrWhiteSpace(secret) && secret.Length >= 8)
        {
            _knownSecrets.Add(secret);
        }
    }

    public SanitizationResult Sanitize(string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return new SanitizationResult(input, 0, new Dictionary<string, string>());
        }

        var opaqueMap = new Dictionary<string, string>(StringComparer.Ordinal);
        int redactions = 0;
        string result = input;

        // 1. Redact PEM Private Keys
        result = PemPrivateKeyRegex.Replace(result, match =>
        {
            redactions++;
            string placeholder = GeneratePlaceholder(match.Value);
            opaqueMap[placeholder] = match.Value;
            return placeholder;
        });

        // 2. Redact Bearer Headers
        result = BearerHeaderRegex.Replace(result, match =>
        {
            string token = match.Groups[1].Value;
            redactions++;
            string placeholder = GeneratePlaceholder(token);
            opaqueMap[placeholder] = token;
            return $"Bearer {placeholder}";
        });

        // 3. Redact Standalone JWTs
        result = JwtRegex.Replace(result, match =>
        {
            if (opaqueMap.Values.Contains(match.Value))
                return match.Value;

            redactions++;
            string placeholder = GeneratePlaceholder(match.Value);
            opaqueMap[placeholder] = match.Value;
            return placeholder;
        });

        // 4. Redact Well-Known API Key formats
        result = CommonApiKeyRegex.Replace(result, match =>
        {
            if (opaqueMap.Values.Contains(match.Value))
                return match.Value;

            redactions++;
            string placeholder = GeneratePlaceholder(match.Value);
            opaqueMap[placeholder] = match.Value;
            return placeholder;
        });

        // 5. Redact explicitly registered secrets
        foreach (var secret in _knownSecrets)
        {
            if (result.Contains(secret))
            {
                redactions++;
                string placeholder = GeneratePlaceholder(secret);
                opaqueMap[placeholder] = secret;
                result = result.Replace(secret, placeholder);
            }
        }

        return new SanitizationResult(result, redactions, opaqueMap);
    }

    public string RestoreCredentials(string sanitizedInput, IReadOnlyDictionary<string, string> opaqueMap)
    {
        if (string.IsNullOrEmpty(sanitizedInput) || opaqueMap == null || opaqueMap.Count == 0)
        {
            return sanitizedInput;
        }

        string result = sanitizedInput;
        foreach (var (placeholder, secret) in opaqueMap)
        {
            result = result.Replace(placeholder, secret);
        }
        return result;
    }

    private static string GeneratePlaceholder(string secret)
    {
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret))).Substring(0, 12).ToLowerInvariant();
        return $"[SECRET_REF:sec_{hash}]";
    }
}
