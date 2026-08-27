using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Network.Ai;

namespace MissionController.UI.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ICredentialVault _vault;
    private readonly ITokenLifecycleManager _lifecycleManager;

    [ObservableProperty]
    private string _anthropicKeyStatus = "No Anthropic API key stored";

    [ObservableProperty]
    private string _geminiKeyStatus = "No Gemini API key stored";

    [ObservableProperty]
    private string _oAuthStatus = "No active OAuth token stored";

    [ObservableProperty]
    private string _saStatus = "No Service Account loaded";

    [ObservableProperty]
    private string _renewalMessage = "Auto-Renew Active (120s buffer threshold)";

    public SettingsViewModel(ICredentialVault vault, ITokenLifecycleManager lifecycleManager)
    {
        _vault = vault;
        _lifecycleManager = lifecycleManager;
    }

    [RelayCommand]
    public async System.Threading.Tasks.Task CheckVaultStatusAsync()
    {
        // Provider API keys are the credentials the mission AI path actually consumes; the vault
        // key names come from the client constants so Settings can never drift from the readers.
        string? anthropicKey = await _vault.RetrieveSecretStringAsync(ClaudeStreamClient.ApiKeyVaultKey);
        AnthropicKeyStatus = string.IsNullOrEmpty(anthropicKey)
            ? "No Anthropic API key in DPAPI Vault"
            : $"DPAPI Vault: Active Anthropic API key ({MaskKey(anthropicKey)}) — default provider";

        string? geminiKey = await _vault.RetrieveSecretStringAsync(GeminiStreamClient.ApiKeyVaultKey);
        GeminiKeyStatus = string.IsNullOrEmpty(geminiKey)
            ? "No Gemini API key in DPAPI Vault"
            : $"DPAPI Vault: Active Gemini API key ({MaskKey(geminiKey)})";

        string? oauthToken = await _vault.RetrieveSecretStringAsync("GoogleCloud.OAuthToken");
        OAuthStatus = string.IsNullOrEmpty(oauthToken) ? "No OAuth Token in DPAPI Vault" : $"DPAPI Vault: Active OAuth Bearer Token ({oauthToken.Substring(0, Math.Min(12, oauthToken.Length))}...)";

        string? saToken = await _vault.RetrieveSecretStringAsync("GoogleCloud.ServiceAccountToken");
        SaStatus = string.IsNullOrEmpty(saToken) ? "No Service Account Token in DPAPI Vault" : $"DPAPI Vault: Active Service Account Token ({saToken.Substring(0, Math.Min(12, saToken.Length))}...)";
    }

    [RelayCommand]
    public async System.Threading.Tasks.Task ForceTokenRefreshAsync()
    {
        RenewalMessage = "Triggering proactive token refresh...";
        var res = await _lifecycleManager.RefreshTokenAsync("GoogleCloud.OAuthToken");
        if (!res.Success)
        {
            res = await _lifecycleManager.RefreshTokenAsync("GoogleCloud.ServiceAccountToken");
        }

        RenewalMessage = res.Success
            ? $"SUCCESS: Token renewed at {DateTime.UtcNow:T} UTC (Expires {res.Token?.ExpiresAtUtc:t})"
            : $"Notice: {res.ErrorMessage ?? "No refresh handler registered"}";

        await CheckVaultStatusAsync();
    }

    private static string MaskKey(string key) =>
        key.Length <= 8 ? "••••" : $"{key.Substring(0, 8)}…";
}

