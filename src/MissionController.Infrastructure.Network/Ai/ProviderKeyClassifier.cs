using System;

namespace MissionController.Infrastructure.Network.Ai;

/// <summary>
/// Maps a pasted API key to the vault slot its provider client actually reads. This closes the
/// original onboarding bug class permanently: the user pastes ONE box, the key lands in the slot
/// the router will find, and no human ever has to know which vendor uses which vault name.
/// </summary>
public static class ProviderKeyClassifier
{
    /// <summary>
    /// Google API keys are issued with a fixed "AIza" prefix; Anthropic keys with "sk-ant-".
    /// Anything unrecognized is stored in the Anthropic slot (the product's default provider),
    /// where a wrong key surfaces as a loud MODEL REQUEST FAILED on first use - never silently.
    /// </summary>
    public static (string VaultKey, string ProviderName) Classify(string apiKey)
    {
        string key = (apiKey ?? string.Empty).Trim();

        if (key.StartsWith("AIza", StringComparison.Ordinal))
            return (GeminiStreamClient.ApiKeyVaultKey, "Google Gemini");

        return (ClaudeStreamClient.ApiKeyVaultKey, "Anthropic Claude");
    }
}
