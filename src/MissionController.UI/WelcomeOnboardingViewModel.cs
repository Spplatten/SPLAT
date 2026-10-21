using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Network.Ai;

namespace MissionController.UI.ViewModels;

public partial class WelcomeOnboardingViewModel : ObservableObject
{
    private readonly ICredentialVault _vault;
    private readonly GeminiStreamClient _geminiClient;
    private readonly ClaudeStreamClient _claudeClient;

    [ObservableProperty]
    private int _currentStep = 1;

    [ObservableProperty]
    private string _apiKeyInput = string.Empty;

    [ObservableProperty]
    private bool _isTestingKey;

    [ObservableProperty]
    private string _keyStatusMessage = "Enter your Anthropic (sk-ant-...) or Gemini (AIza...) API key for immediate live verification.";

    [ObservableProperty]
    private bool _isKeyValid;

    [ObservableProperty]
    private bool _kernelSandboxReady = true;

    [ObservableProperty]
    private bool _dpapiVaultReady = true;

    [ObservableProperty]
    private bool _egressFirewallReady = true;

    [ObservableProperty]
    private bool _hasAcceptedLegalTerms;

    [ObservableProperty]
    private bool _isLegalViewerExpanded;

    [ObservableProperty]
    private string _selectedLegalKey = "eula";

    [ObservableProperty]
    private string _activeLegalTitle = SplatLegalTerms.EulaTitle;

    [ObservableProperty]
    private string _activeLegalSummary = SplatLegalTerms.AllDocuments[0].Summary;

    [ObservableProperty]
    private string _activeLegalText = SplatLegalTerms.EulaText;

    [ObservableProperty]
    private string _legalAcceptanceNotice = string.Empty;

    public string LegalShortNotice => SplatLegalTerms.ShortNotice;

    public WelcomeOnboardingViewModel(
        ICredentialVault vault,
        GeminiStreamClient geminiClient,
        ClaudeStreamClient claudeClient)
    {
        _vault = vault;
        _geminiClient = geminiClient;
        _claudeClient = claudeClient;
    }

    partial void OnHasAcceptedLegalTermsChanged(bool value)
    {
        if (value)
        {
            LegalAcceptanceNotice = string.Empty;
        }
    }

    [RelayCommand]
    public void SelectLegalDocument(string? key)
    {
        string normalized = string.IsNullOrWhiteSpace(key) ? "eula" : key.Trim().ToLowerInvariant();
        if (string.Equals(normalized, "all", StringComparison.OrdinalIgnoreCase))
        {
            SelectedLegalKey = "all";
            ActiveLegalTitle = "SPLAT EULA, Terms of Use and Privacy Policy";
            ActiveLegalSummary = "All three documents in full.";
            ActiveLegalText = SplatLegalTerms.FormatAll();
            IsLegalViewerExpanded = true;
            return;
        }

        var doc = SplatLegalTerms.TryGetByKeyOrUri(normalized) ?? SplatLegalTerms.AllDocuments[0];
        SelectedLegalKey = doc.Key;
        ActiveLegalTitle = doc.Title;
        ActiveLegalSummary = doc.Summary;
        ActiveLegalText = doc.FullText;
        IsLegalViewerExpanded = true;
    }

    [RelayCommand]
    public void ToggleLegalViewer()
    {
        IsLegalViewerExpanded = !IsLegalViewerExpanded;
    }

    private System.Threading.CancellationTokenSource? _autoValidationCts;

    partial void OnApiKeyInputChanged(string value)
    {
        _autoValidationCts?.Cancel();
        _autoValidationCts?.Dispose();
        _autoValidationCts = null;

        if (string.IsNullOrWhiteSpace(value))
        {
            KeyStatusMessage = "Enter your Anthropic (sk-ant-...) or Gemini (AIza...) API key for immediate live verification.";
            IsKeyValid = false;
            return;
        }

        string trimmed = value.Trim();
        if (trimmed.Length < 10)
        {
            KeyStatusMessage = "Enter full API key...";
            IsKeyValid = false;
            return;
        }

        _autoValidationCts = new System.Threading.CancellationTokenSource();
        var token = _autoValidationCts.Token;

        _ = Task.Run(async () =>
        {
            try
            {
                // If it starts with standard prefix and is complete length, validate immediately, else debounce 350ms
                bool isFastCandidate = (trimmed.StartsWith("sk-ant-", System.StringComparison.Ordinal) && trimmed.Length >= 40)
                                    || (trimmed.StartsWith("AIza", System.StringComparison.Ordinal) && trimmed.Length >= 30);
                if (!isFastCandidate)
                {
                    await Task.Delay(350, token);
                }

                if (token.IsCancellationRequested) return;

                await ValidateKeyInternalAsync(trimmed, token);
            }
            catch (System.OperationCanceledException)
            {
                // Expected when new characters are typed
            }
        }, token);
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

        await ValidateKeyInternalAsync(ApiKeyInput.Trim(), System.Threading.CancellationToken.None);
    }

    private async Task ValidateKeyInternalAsync(string key, System.Threading.CancellationToken cancellationToken)
    {
        var (vaultKey, providerName) = ProviderKeyClassifier.Classify(key);

        IsTestingKey = true;
        try
        {
            KeyStatusMessage = $"Validating {providerName} API key against live endpoint...";

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
                IsKeyValid = false;
                KeyStatusMessage = $"🔴 Key rejected — {validation.Message}";
                return;
            }

            await _vault.StoreSecretStringAsync(vaultKey, key, cancellationToken);
            IsKeyValid = true;
            KeyStatusMessage = $"⚡ {providerName} key verified live and secured in DPAPI vault.";
        }
        catch (System.OperationCanceledException)
        {
            // Ignored
        }
        catch (System.Exception ex)
        {
            IsKeyValid = false;
            KeyStatusMessage = $"🔴 Could not save key: {ex.Message}";
        }
        finally
        {
            IsTestingKey = false;
        }
    }

    [RelayCommand]
    public void NextStep()
    {
        if (CurrentStep == 1 && !HasAcceptedLegalTerms)
        {
            IsLegalViewerExpanded = true;
            LegalAcceptanceNotice = "Read and accept the SPLAT EULA, Terms of Use and Privacy Policy to continue.";
            return;
        }

        LegalAcceptanceNotice = string.Empty;
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
