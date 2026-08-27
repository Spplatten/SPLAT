using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Network.Dlp;

public sealed class RegexDataLossPreventionSanitizer : IDataLossPreventionSanitizer
{
    private record DlpRule(
        string Category,
        Regex Pattern,
        string Replacement);

    private readonly IReadOnlyList<DlpRule> _rules;

    public RegexDataLossPreventionSanitizer()
    {
        _rules = new List<DlpRule>
        {
            // 1. Private Keys (RSA, EC, PKCS8)
            new(
                "PrivateKey",
                new Regex(@"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", RegexOptions.Compiled),
                "[REDACTED_PRIVATE_KEY_BLOCK]"
            ),

            // 2. NTLM Hash Pairs (LM:NTLM or User:RID:LM:NTLM)
            new(
                "NtlmHashPair",
                new Regex(@"\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b", RegexOptions.Compiled),
                "[REDACTED_NTLM_HASH]"
            ),

            // 3. Password & API Key Key-Value Assignments
            new(
                "CredentialAssignment",
                new Regex(@"(?i)(password|passwd|pwd|secret|apikey|api_key|access_token|bearer)\s*([:=])\s*([^\s;,""']+)", RegexOptions.Compiled),
                "$1$2[REDACTED_SECRET]"
            ),

            // 4. CLI Password Arguments (-p <pass>, /p:<pass>, -password <pass>)
            new(
                "CliPasswordArgument",
                new Regex(@"(?i)(\s-(?:p|password|pwd)\s+)([^\s]+)", RegexOptions.Compiled),
                "$1[REDACTED_PASSWORD]"
            ),
            new(
                "CliSlashPasswordArgument",
                new Regex(@"(?i)(\/(?:p|password|pwd):)([^\s]+)", RegexOptions.Compiled),
                "$1[REDACTED_PASSWORD]"
            ),

            // 5. Personal & Corporate Email Addresses
            new(
                "EmailAddress",
                new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled),
                "[REDACTED_EMAIL]"
            ),

            // 6. Credit Card Numbers (13-16 digits with hyphens/spaces)
            new(
                "CreditCard",
                new Regex(@"\b(?:\d{4}[-\s]?){3}\d{4}\b", RegexOptions.Compiled),
                "[REDACTED_CARD_NUMBER]"
            ),

            // 7. US Social Security Numbers (SSN)
            new(
                "SSN",
                new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled),
                "[REDACTED_SSN]"
            )
        };
    }

    public DlpSanitizationResult Sanitize(string input)
    {
        if (string.IsNullOrEmpty(input))
            return new DlpSanitizationResult(input, 0, Array.Empty<string>());

        string result = input;
        int totalRedactions = 0;
        var categoriesFound = new HashSet<string>();

        foreach (var rule in _rules)
        {
            var matches = rule.Pattern.Matches(result);
            if (matches.Count > 0)
            {
                totalRedactions += matches.Count;
                categoriesFound.Add(rule.Category);
                result = rule.Pattern.Replace(result, rule.Replacement);
            }
        }

        return new DlpSanitizationResult(
            result,
            totalRedactions,
            new List<string>(categoriesFound));
    }
}
