using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Network.Ai;

namespace MissionController.UI.ViewModels;

public partial class SettingsViewModel : ObservableObject
{
    private readonly ICredentialVault _vault;
    private readonly ITokenLifecycleManager _lifecycleManager;
    private readonly GeminiStreamClient _geminiClient;
    private readonly ClaudeStreamClient _claudeClient;

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

    [ObservableProperty]
    private string _newApiKeyInput = string.Empty;

    [ObservableProperty]
    private bool _isSavingKey;

    [ObservableProperty]
    private string _keyValidationStatus = string.Empty;

    // Vault key names are surfaced as bindable properties so the Remove buttons pass the SAME
    // identifier the readers use. Hardcoding these strings in XAML would let the delete path drift
    // away from the store path, producing a button that reports success and removes nothing.
    public const string OAuthVaultKeyName = "GoogleCloud.OAuthToken";
    public const string ServiceAccountVaultKeyName = "GoogleCloud.ServiceAccountToken";

    public string AnthropicVaultKey => ClaudeStreamClient.ApiKeyVaultKey;
    public string GeminiVaultKey => GeminiStreamClient.ApiKeyVaultKey;
    public string OAuthVaultKey => OAuthVaultKeyName;
    public string ServiceAccountVaultKey => ServiceAccountVaultKeyName;

    [ObservableProperty]
    private bool _hasAnthropicKey;

    [ObservableProperty]
    private bool _hasGeminiKey;

    [ObservableProperty]
    private bool _hasOAuthToken;

    [ObservableProperty]
    private bool _hasServiceAccountToken;

    public SettingsViewModel(
        ICredentialVault vault,
        ITokenLifecycleManager lifecycleManager,
        GeminiStreamClient geminiClient,
        ClaudeStreamClient claudeClient)
    {
        _vault = vault;
        _lifecycleManager = lifecycleManager;
        _geminiClient = geminiClient;
        _claudeClient = claudeClient;
    }

    private System.Threading.CancellationTokenSource? _autoValidationCts;

    partial void OnNewApiKeyInputChanged(string value)
    {
        _autoValidationCts?.Cancel();
        _autoValidationCts?.Dispose();
        _autoValidationCts = null;

        if (string.IsNullOrWhiteSpace(value))
        {
            KeyValidationStatus = string.Empty;
            return;
        }

        string trimmed = value.Trim();
        if (trimmed.Length < 10)
        {
            KeyValidationStatus = "Enter full API key...";
            return;
        }

        _autoValidationCts = new System.Threading.CancellationTokenSource();
        var token = _autoValidationCts.Token;

        _ = System.Threading.Tasks.Task.Run(async () =>
        {
            try
            {
                bool isFastCandidate = (trimmed.StartsWith("sk-ant-", System.StringComparison.Ordinal) && trimmed.Length >= 40)
                                    || (trimmed.StartsWith("AIza", System.StringComparison.Ordinal) && trimmed.Length >= 30);
                if (!isFastCandidate)
                {
                    await System.Threading.Tasks.Task.Delay(350, token);
                }

                if (token.IsCancellationRequested) return;

                await SaveAndValidateInternalAsync(trimmed, token);
            }
            catch (System.OperationCanceledException)
            {
                // Expected on fast typing
            }
        }, token);
    }

    [RelayCommand]
    public async System.Threading.Tasks.Task SaveAndValidateKeyAsync()
    {
        if (string.IsNullOrWhiteSpace(NewApiKeyInput))
        {
            KeyValidationStatus = "Please enter an API Key to verify and save.";
            return;
        }

        await SaveAndValidateInternalAsync(NewApiKeyInput.Trim(), System.Threading.CancellationToken.None);
    }

    private async System.Threading.Tasks.Task SaveAndValidateInternalAsync(string key, System.Threading.CancellationToken cancellationToken)
    {
        var (vaultKey, providerName) = ProviderKeyClassifier.Classify(key);

        IsSavingKey = true;
        try
        {
            KeyValidationStatus = $"Validating {providerName} API key against live endpoint...";

            Core.Models.AiGatewayValidationResult validation;
            if (vaultKey == GeminiStreamClient.ApiKeyVaultKey)
            {
                validation = await _geminiClient.ValidateApiKeyAsync(key, cancellationToken);
            }
            else
            {
                validation = await _claudeClient.ValidateApiKeyAsync(key, cancellationToken);
            }

            if (cancellationToken.IsCancellationRequested) return;

            if (!validation.IsValid)
            {
                KeyValidationStatus = $"🔴 Key rejected: {validation.Message}";
                return;
            }

            await _vault.StoreSecretStringAsync(vaultKey, key, cancellationToken);
            KeyValidationStatus = $"⚡ {providerName} key verified live and stored in DPAPI vault.";
            await CheckVaultStatusAsync();
        }
        catch (System.OperationCanceledException)
        {
            // Ignored
        }
        catch (System.Exception ex)
        {
            KeyValidationStatus = $"🔴 Error saving key: {ex.Message}";
        }
        finally
        {
            IsSavingKey = false;
        }
    }

    /// <summary>
    /// Deletes one stored secret from the DPAPI vault. The provider clients read the vault on every
    /// request and cache nothing, so removal takes effect on the very next mission with no restart.
    /// </summary>
    [RelayCommand]
    public async System.Threading.Tasks.Task RemoveStoredSecretAsync(string? vaultKey)
    {
        if (string.IsNullOrWhiteSpace(vaultKey))
        {
            return;
        }

        try
        {
            // A debounced auto-validation from earlier typing would happily re-store the key we are
            // about to delete, so cancel it before touching the vault.
            _autoValidationCts?.Cancel();

            await _vault.DeleteSecretAsync(vaultKey);

            // Clear the input FIRST: assigning it fires OnNewApiKeyInputChanged, which blanks
            // KeyValidationStatus. Setting the confirmation afterwards is what makes it survive.
            NewApiKeyInput = string.Empty;
            KeyValidationStatus = $"🗑 Removed {DescribeVaultKey(vaultKey)} from the DPAPI vault.";

            await CheckVaultStatusAsync();
        }
        catch (System.Exception ex)
        {
            KeyValidationStatus = $"🔴 Could not remove credential: {ex.Message}";
        }
    }

    private string DescribeVaultKey(string vaultKey) => vaultKey switch
    {
        _ when vaultKey == ClaudeStreamClient.ApiKeyVaultKey => "the Anthropic Claude API key",
        _ when vaultKey == GeminiStreamClient.ApiKeyVaultKey => "the Google Gemini API key",
        OAuthVaultKeyName => "the OAuth 2.0 token",
        ServiceAccountVaultKeyName => "the Service Account token",
        _ => $"'{vaultKey}'"
    };

    [RelayCommand]
    public async System.Threading.Tasks.Task CheckVaultStatusAsync()
    {
        // Provider API keys are the credentials the mission AI path actually consumes; the vault
        // key names come from the client constants so Settings can never drift from the readers.
        string? anthropicKey = await _vault.RetrieveSecretStringAsync(ClaudeStreamClient.ApiKeyVaultKey);
        HasAnthropicKey = !string.IsNullOrEmpty(anthropicKey);
        AnthropicKeyStatus = HasAnthropicKey
            ? $"Active Anthropic API key ({MaskKey(anthropicKey!)}) — default provider"
            : "No Anthropic API key in DPAPI Vault";

        string? geminiKey = await _vault.RetrieveSecretStringAsync(GeminiStreamClient.ApiKeyVaultKey);
        HasGeminiKey = !string.IsNullOrEmpty(geminiKey);
        GeminiKeyStatus = HasGeminiKey
            ? $"Active Gemini API key ({MaskKey(geminiKey!)})"
            : "No Gemini API key in DPAPI Vault";

        string? oauthToken = await _vault.RetrieveSecretStringAsync(OAuthVaultKeyName);
        HasOAuthToken = !string.IsNullOrEmpty(oauthToken);
        OAuthStatus = HasOAuthToken
            ? $"Active OAuth Bearer Token ({MaskKey(oauthToken!)})"
            : "No OAuth Token in DPAPI Vault";

        string? saToken = await _vault.RetrieveSecretStringAsync(ServiceAccountVaultKeyName);
        HasServiceAccountToken = !string.IsNullOrEmpty(saToken);
        SaStatus = HasServiceAccountToken
            ? $"Active Service Account Token ({MaskKey(saToken!)})"
            : "No Service Account Token in DPAPI Vault";
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

