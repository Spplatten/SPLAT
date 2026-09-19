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

    /// <summary>
    /// Per-rule ceiling on matching time. These patterns run over sandboxed tool output, which is
    /// attacker-influenceable through file names, registry values and process names, and several use
    /// unbounded classes (<c>[\s\S]*?</c>) that can backtrack catastrophically on a crafted input.
    /// Without this, the default is <see cref="Regex.InfiniteMatchTimeout"/> and a single crafted
    /// filename wedges the mission pipeline.
    /// </summary>
    private static readonly TimeSpan PatternTimeout = TimeSpan.FromMilliseconds(750);

    /// <summary>Category suffix recorded when a rule could not finish scanning within the budget.</summary>
    private const string TimeoutCategorySuffix = ":ScanTimeout";

    public RegexDataLossPreventionSanitizer()
    {
        _rules = new List<DlpRule>
        {
            // 1. Private Keys (RSA, EC, PKCS8)
            new(
                "PrivateKey",
                new Regex(@"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_PRIVATE_KEY_BLOCK]"
            ),

            // 2. NTLM Hash Pairs (LM:NTLM or User:RID:LM:NTLM)
            new(
                "NtlmHashPair",
                new Regex(@"\b([a-fA-F0-9]{32}:[a-fA-F0-9]{32})\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_NTLM_HASH]"
            ),

            // 3. Password & API Key Key-Value Assignments
            new(
                "CredentialAssignment",
                new Regex(@"(?i)(password|passwd|pwd|secret|apikey|api_key|access_token|bearer)\s*([:=])\s*([^\s;,""']+)", RegexOptions.Compiled, PatternTimeout),
                "$1$2[REDACTED_SECRET]"
            ),

            // 4. CLI Password Arguments (-p <pass>, /p:<pass>, -password <pass>)
            new(
                "CliPasswordArgument",
                new Regex(@"(?i)(\s-(?:p|password|pwd)\s+)([^\s]+)", RegexOptions.Compiled, PatternTimeout),
                "$1[REDACTED_PASSWORD]"
            ),
            new(
                "CliSlashPasswordArgument",
                new Regex(@"(?i)(\/(?:p|password|pwd):)([^\s]+)", RegexOptions.Compiled, PatternTimeout),
                "$1[REDACTED_PASSWORD]"
            ),

            // 5. Personal & Corporate Email Addresses
            new(
                "EmailAddress",
                new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_EMAIL]"
            ),

            // 6. Credit Card Numbers (13-16 digits with hyphens/spaces)
            new(
                "CreditCard",
                new Regex(@"\b(?:\d{4}[-\s]?){3}\d{4}\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_CARD_NUMBER]"
            ),

            // 7. US Social Security Numbers (SSN)
            new(
                "SSN",
                new Regex(@"\b\d{3}-\d{2}-\d{4}\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_SSN]"
            ),

            // 8. AWS Access Key IDs (AKIA...)
            new(
                "AwsKey",
                new Regex(@"\b(AKIA[0-9A-Z]{16})\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_AWS_KEY]"
            ),

            // 9. GitHub Personal/OAuth Access Tokens (ghp_, gho_, ghu_, ghs_, ghr_)
            new(
                "GitHubToken",
                new Regex(@"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_GITHUB_TOKEN]"
            ),

            // 10. OpenAI API Keys (sk-... or sk-proj-...)
            new(
                "OpenAiKey",
                new Regex(@"\b(sk-(?:proj-)?[a-zA-Z0-9_\-]{20,})\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_OPENAI_KEY]"
            ),

            // 11. Stripe Secret / Restricted Keys (sk_live_..., sk_test_..., rk_live_...)
            new(
                "StripeKey",
                new Regex(@"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_STRIPE_KEY]"
            ),

            // 12. Bare JSON Web Tokens (JWT)
            new(
                "JwtToken",
                new Regex(@"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_JWT]"
            ),

            // 13. Google API Keys (AIza...)
            new(
                "GoogleApiKey",
                new Regex(@"\b(AIza[0-9A-Za-z\-_]{35})\b", RegexOptions.Compiled, PatternTimeout),
                "[REDACTED_GOOGLE_API_KEY]"
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
            try
            {
                // Counting inside the MatchEvaluator replaces the old Matches()-then-Replace()
                // pair, which ran every pattern over the whole payload twice. One pass now.
                int ruleHits = 0;
                string replaced = rule.Pattern.Replace(result, match =>
                {
                    ruleHits++;
                    return match.Result(rule.Replacement);
                });

                if (ruleHits > 0)
                {
                    totalRedactions += ruleHits;
                    categoriesFound.Add(rule.Category);
                    result = replaced;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // FAIL CLOSED. This rule did not finish, so the payload cannot be described as
                // scanned for this category - and returning it as "sanitized" is exactly the kind of
                // claim-without-basis this pipeline exists to prevent. Discard the content rather
                // than forward text of unknown safety to a model provider. The operator sees the
                // category and knows a scan, not the diagnostic, is what failed.
                categoriesFound.Add(rule.Category + TimeoutCategorySuffix);
                totalRedactions++;
                result =
                    $"[REDACTED — DLP scan for {rule.Category} exceeded {PatternTimeout.TotalMilliseconds:F0}ms " +
                    "and this payload was withheld rather than transmitted unscanned]";
                break;
            }
        }

        return new DlpSanitizationResult(
            result,
            totalRedactions,
            new List<string>(categoriesFound));
    }
}
