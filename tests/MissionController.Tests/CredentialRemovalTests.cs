using System;
using System.IO;
using System.Threading.Tasks;
using MissionController.Infrastructure.Windows.Vault;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Removing a stored credential has to actually remove it. These cover the guarantees the Settings
/// "Remove" buttons rely on: the secret stops resolving, the file stops existing, removing one key
/// leaves the others intact, and removing something absent is not an error.
/// </summary>
public class CredentialRemovalTests : IDisposable
{
    private readonly string _vaultDirectory;
    private readonly DpapiCredentialVault _vault;

    public CredentialRemovalTests()
    {
        _vaultDirectory = Path.Combine(Path.GetTempPath(), "splat-vault-tests", Guid.NewGuid().ToString("N"));
        _vault = new DpapiCredentialVault(_vaultDirectory);
    }

    public void Dispose()
    {
        try { Directory.Delete(_vaultDirectory, recursive: true); } catch { }
    }

    [Fact]
    public async Task DeletedSecret_NoLongerResolves()
    {
        await _vault.StoreSecretStringAsync("Anthropic.ApiKey", "sk-ant-example-key-value");
        Assert.Equal("sk-ant-example-key-value", await _vault.RetrieveSecretStringAsync("Anthropic.ApiKey"));

        await _vault.DeleteSecretAsync("Anthropic.ApiKey");

        // The provider clients read the vault per request, so a null here means the next mission
        // genuinely runs without the key rather than reusing a cached copy.
        Assert.Null(await _vault.RetrieveSecretStringAsync("Anthropic.ApiKey"));
    }

    [Fact]
    public async Task DeletedSecret_LeavesNoFileBehind()
    {
        await _vault.StoreSecretStringAsync("Anthropic.ApiKey", "sk-ant-example-key-value");
        Assert.Single(Directory.GetFiles(_vaultDirectory));

        await _vault.DeleteSecretAsync("Anthropic.ApiKey");

        Assert.Empty(Directory.GetFiles(_vaultDirectory));
    }

    [Fact]
    public async Task RemovingOneCredential_LeavesTheOthersUsable()
    {
        await _vault.StoreSecretStringAsync("Anthropic.ApiKey", "sk-ant-value");
        await _vault.StoreSecretStringAsync("GoogleGeminiApiKey", "AIza-value");
        await _vault.StoreSecretStringAsync("GoogleCloud.OAuthToken", "oauth-value");

        await _vault.DeleteSecretAsync("GoogleGeminiApiKey");

        Assert.Null(await _vault.RetrieveSecretStringAsync("GoogleGeminiApiKey"));
        Assert.Equal("sk-ant-value", await _vault.RetrieveSecretStringAsync("Anthropic.ApiKey"));
        Assert.Equal("oauth-value", await _vault.RetrieveSecretStringAsync("GoogleCloud.OAuthToken"));
    }

    [Fact]
    public async Task DeletingAnAbsentSecret_IsNotAnError()
    {
        // The Remove button is bound to a "has key" flag, but a double-click or a stale UI state
        // must not surface an exception to the operator.
        await _vault.DeleteSecretAsync("Never.Stored");
        Assert.Null(await _vault.RetrieveSecretStringAsync("Never.Stored"));
    }

    [Fact]
    public async Task StoringAgainAfterRemoval_Works()
    {
        await _vault.StoreSecretStringAsync("Anthropic.ApiKey", "first-key");
        await _vault.DeleteSecretAsync("Anthropic.ApiKey");
        await _vault.StoreSecretStringAsync("Anthropic.ApiKey", "second-key");

        Assert.Equal("second-key", await _vault.RetrieveSecretStringAsync("Anthropic.ApiKey"));
    }
}
