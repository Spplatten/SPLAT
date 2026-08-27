using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Network.Ai;

namespace MissionController.UI.ViewModels;

public partial class WelcomeOnboardingViewModel : ObservableObject
{
    private readonly ICredentialVault _vault;
    private readonly GeminiStreamClient _geminiClient;

    [ObservableProperty]
    private int _currentStep = 1;

    [ObservableProperty]
    private string _apiKeyInput = string.Empty;

    [ObservableProperty]
    private bool _isTestingKey;

    [ObservableProperty]
    private string _keyStatusMessage = "Enter your Anthropic or Gemini API key to enable live AI analysis (optional — you can run missions without one).";

    [ObservableProperty]
    private bool _isKeyValid;

    [ObservableProperty]
    private bool _kernelSandboxReady = true;

    [ObservableProperty]
    private bool _dpapiVaultReady = true;

    [ObservableProperty]
    private bool _egressFirewallReady = true;

    public WelcomeOnboardingViewModel(ICredentialVault vault, GeminiStreamClient geminiClient)
    {
        _vault = vault;
        _geminiClient = geminiClient;
    }

    [RelayCommand]
    public async Task ValidateKeyAsync()
    {
        if (string.IsNullOrWhiteSpace(ApiKeyInput))
        {
            KeyStatusMessage = "Please enter an API Key before testing.";
            IsKeyValid = false;
            return;
        }

        string key = ApiKeyInput.Trim();
        // Route the key to the vault slot its provider client actually reads (the original
        // shipped bug was a key stored under a name nothing read - the classifier is the fix).
        var (vaultKey, providerName) = ProviderKeyClassifier.Classify(key);

        IsTestingKey = true;
        try
        {
            if (vaultKey == GeminiStreamClient.ApiKeyVaultKey)
            {
                // Gemini exposes a zero-cost authenticated probe, so verify BEFORE persisting -
                // a stored-but-dead key would silently downgrade missions to the simulated path.
                KeyStatusMessage = "Validating Google Gemini key against the live endpoint...";
                var validation = await _geminiClient.ValidateApiKeyAsync(key);
                if (!validation.IsValid)
                {
                    IsKeyValid = false;
                    KeyStatusMessage = $"Key NOT saved — {validation.Message}";
                    return;
                }

                await _vault.StoreSecretStringAsync(vaultKey, key);
                IsKeyValid = true;
                KeyStatusMessage = "⚡ Gemini key verified live and saved. Missions will use Google Gemini (Anthropic key, if added later, takes precedence).";
            }
            else
            {
                await _vault.StoreSecretStringAsync(vaultKey, key);
                IsKeyValid = true;
                KeyStatusMessage = $"{providerName} key saved. Live analysis will use it on your next mission; an invalid key will show a clear error there rather than failing silently.";
            }
        }
        catch (System.Exception ex)
        {
            IsKeyValid = false;
            KeyStatusMessage = $"Could not save key: {ex.Message}";
        }
        finally
        {
            IsTestingKey = false;
        }
    }

    [RelayCommand]
    public void NextStep()
    {
        if (CurrentStep < 3)
        {
            CurrentStep++;
        }
    }

    [RelayCommand]
    public void PreviousStep()
    {
        if (CurrentStep > 1)
        {
            CurrentStep--;
        }
    }
}
