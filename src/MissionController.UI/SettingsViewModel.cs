using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;

namespace MissionController.UI.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ICredentialVault _vault;
    private readonly ITokenLifecycleManager _lifecycleManager;

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
}

