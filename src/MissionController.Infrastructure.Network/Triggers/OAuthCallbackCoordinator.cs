using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Network.Triggers;

public sealed class OAuthCallbackCoordinator
{
    private readonly EmbeddedWebhookListener _listener;
    private readonly ICredentialVault _vault;

    public OAuthCallbackCoordinator(
        EmbeddedWebhookListener listener,
        ICredentialVault vault)
    {
        _listener = listener;
        _vault = vault;
    }

    public string BuildAuthorizationUrl(
        string provider,
        string authEndpoint,
        string clientId,
        string[] scopes,
        string state)
    {
        string redirectUri = Uri.EscapeDataString($"{_listener.BaseUrl}oauth/callback/{provider.ToLowerInvariant()}");
        string scopeParam = Uri.EscapeDataString(string.Join(" ", scopes));
        string stateParam = Uri.EscapeDataString(state);

        return $"{authEndpoint}?client_id={Uri.EscapeDataString(clientId)}&redirect_uri={redirectUri}&response_type=code&scope={scopeParam}&state={stateParam}";
    }

    public Task<string> AwaitTokenAsync(
        string provider,
        int timeoutSeconds = 120,
        CancellationToken cancellationToken = default)
    {
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

        _listener.RegisterOAuthHandler(provider, async (code, state) =>
        {
            try
            {
                // Vault the received authorization code & simulated token
                string vaultKey = $"oauth_token_{provider.ToLowerInvariant()}";
                string tokenJson = $"{{\"provider\":\"{provider}\",\"code\":\"{code}\",\"vaulted_at\":\"{DateTime.UtcNow:o}\"}}";
                await _vault.StoreSecretStringAsync(vaultKey, tokenJson, CancellationToken.None);

                tcs.TrySetResult(vaultKey);
                return true;
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
                return false;
            }
        });

        cts.Token.Register(() => tcs.TrySetCanceled());
        return tcs.Task;
    }

    public void LaunchBrowser(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch { }
    }
}
