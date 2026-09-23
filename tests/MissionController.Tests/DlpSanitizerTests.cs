using MissionController.Infrastructure.Network.Dlp;
using Xunit;

namespace MissionController.Tests;

public class DlpSanitizerTests
{
    [Fact]
    public void Sanitize_MasksPasswordsAndSecretsInText()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = "Executing net use \\\\server /user:admin password=SuperSecretPassword123! with api_key=AIzaSySecretToken";
        
        var result = sanitizer.Sanitize(input);

        Assert.Equal(2, result.RedactedCount);
        Assert.Contains("CredentialAssignment", result.RedactedCategories);
        Assert.DoesNotContain("SuperSecretPassword123!", result.SanitizedContent);
        Assert.DoesNotContain("AIzaSySecretToken", result.SanitizedContent);
        Assert.Contains("[REDACTED_SECRET]", result.SanitizedContent);
    }

    [Fact]
    public void Sanitize_MasksCliPasswordArguments()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = "powershell.exe -p P@ssw0rd999! and cmd.exe /p:SuperPass123";

        var result = sanitizer.Sanitize(input);

        Assert.Equal(2, result.RedactedCount);
        Assert.DoesNotContain("P@ssw0rd999!", result.SanitizedContent);
        Assert.DoesNotContain("SuperPass123", result.SanitizedContent);
        Assert.Contains("[REDACTED_PASSWORD]", result.SanitizedContent);
    }

    /// <summary>
    /// svchost's -p is a process-mitigation flag and the -s after it names the service. On a stock
    /// Windows 11 host that is 55 auto-start services, and on 2026-09-23 every one of them reached
    /// the model as "-p [REDACTED_PASSWORD] DusmSvc" - a password finding the sanitizer invented.
    /// A switch is never a password value.
    /// </summary>
    [Fact]
    public void Sanitize_LeavesSwitchAfterPasswordFlagAlone()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = @"C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s DusmSvc";

        var result = sanitizer.Sanitize(input);

        Assert.Equal(0, result.RedactedCount);
        Assert.Equal(input, result.SanitizedContent);
    }

    /// <summary>
    /// The same flag at the end of a Format-List line: the next line is the next field, never the
    /// password. 53 services on the same host lost their StartName to this.
    /// </summary>
    [Fact]
    public void Sanitize_DoesNotReadTheNextLineAsThePassword()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = "PathName    : C:\\Windows\\system32\\svchost.exe -k wsappx -p\r\nStartName   : LocalSystem";

        var result = sanitizer.Sanitize(input);

        Assert.Equal(0, result.RedactedCount);
        Assert.Contains("StartName   : LocalSystem", result.SanitizedContent);
    }

    [Fact]
    public void Sanitize_MasksNtlmHashes()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = "Dumped hash Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::";

        var result = sanitizer.Sanitize(input);

        Assert.Equal(1, result.RedactedCount);
        Assert.Contains("NtlmHashPair", result.RedactedCategories);
        Assert.DoesNotContain("31d6cfe0d16ae931b73c59d7e0c089c0", result.SanitizedContent);
        Assert.Contains("[REDACTED_NTLM_HASH]", result.SanitizedContent);
    }

    [Fact]
    public void Sanitize_MasksEmailAddresses()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = "Contact administrator at john.doe@enterprise.corp or support@secops.io immediately.";

        var result = sanitizer.Sanitize(input);

        Assert.Equal(2, result.RedactedCount);
        Assert.Contains("EmailAddress", result.RedactedCategories);
        Assert.DoesNotContain("john.doe@enterprise.corp", result.SanitizedContent);
        Assert.DoesNotContain("support@secops.io", result.SanitizedContent);
        Assert.Contains("[REDACTED_EMAIL]", result.SanitizedContent);
    }

    [Fact]
    public void Sanitize_MasksPrivateKeys()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = @"Found key file:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3y1aK4oD...secret_private_key_payload...
-----END RSA PRIVATE KEY-----
in user directory.";

        var result = sanitizer.Sanitize(input);

        Assert.Equal(1, result.RedactedCount);
        Assert.Contains("PrivateKey", result.RedactedCategories);
        Assert.DoesNotContain("secret_private_key_payload", result.SanitizedContent);
        Assert.Contains("[REDACTED_PRIVATE_KEY_BLOCK]", result.SanitizedContent);
    }

    [Fact]
    public void Sanitize_MasksBareCloudTokens_WithoutAssignmentOperators()
    {
        // AG-F06: High-entropy bare tokens appearing without assignment keywords (key=, secret:)
        // must be caught and redacted with their category recorded.
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string input = @"Environment dump from container:
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
Token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234
OpenAI: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456
Stripe: sk_live_1234567890abcdefghijklmnop
Google: AIzaSyD1234567890abcdefghijklmnopqrstuv
Auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        var result = sanitizer.Sanitize(input);

        Assert.True(result.RedactedCount >= 6, $"Expected at least 6 redactions, got {result.RedactedCount}");
        Assert.Contains("AwsKey", result.RedactedCategories);
        Assert.Contains("GitHubToken", result.RedactedCategories);
        Assert.Contains("OpenAiKey", result.RedactedCategories);
        Assert.Contains("StripeKey", result.RedactedCategories);
        Assert.Contains("GoogleApiKey", result.RedactedCategories);
        Assert.Contains("JwtToken", result.RedactedCategories);

        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", result.SanitizedContent);
        Assert.DoesNotContain("ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", result.SanitizedContent);
        Assert.DoesNotContain("sk-proj-1234567890abcdefghijklmnopqrstuvwxyz123456", result.SanitizedContent);
        Assert.DoesNotContain("sk_live_1234567890abcdefghijklmnop", result.SanitizedContent);
        Assert.DoesNotContain("AIzaSyD1234567890abcdefghijklmnopqrstuv", result.SanitizedContent);
        Assert.DoesNotContain("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", result.SanitizedContent);

        Assert.Contains("[REDACTED_AWS_KEY]", result.SanitizedContent);
        Assert.Contains("[REDACTED_GITHUB_TOKEN]", result.SanitizedContent);
        Assert.Contains("[REDACTED_OPENAI_KEY]", result.SanitizedContent);
        Assert.Contains("[REDACTED_STRIPE_KEY]", result.SanitizedContent);
        Assert.Contains("[REDACTED_GOOGLE_API_KEY]", result.SanitizedContent);
        Assert.Contains("[REDACTED_JWT]", result.SanitizedContent);
    }

    [Fact]
    public void Sanitize_MasksStandaloneJwt_InToolStderr()
    {
        var sanitizer = new RegexDataLossPreventionSanitizer();
        string rawJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MDAwMDAwMDB9.signatureBytes1234567890";
        string input = $"Unhandled error processing request with raw token: {rawJwt} at stack trace";

        var result = sanitizer.Sanitize(input);

        Assert.Equal(1, result.RedactedCount);
        Assert.Contains("JwtToken", result.RedactedCategories);
        Assert.DoesNotContain(rawJwt, result.SanitizedContent);
        Assert.Contains("[REDACTED_JWT]", result.SanitizedContent);
    }
}
