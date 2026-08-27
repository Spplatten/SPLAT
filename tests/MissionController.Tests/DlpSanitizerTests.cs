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
}
