using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Network.Triggers;

public sealed class OAuthCallbackCoordinator
{
    private readonly EmbeddedWebhookListener _listener;
    private readonly ICredentialVault _vault;

    /// <summary>
    /// The state value SPLAT issued for each provider, and when it stops being valid.
    ///
    /// RFC 6749 s10.12 exists because the callback URL is reachable by anything that can point the
    /// operator's browser at 127.0.0.1. Without this check an attacker could send the operator to
    /// /oauth/callback/tiktok?code=ATTACKER_CODE and SPLAT would vault a credential bound to the
    /// attacker's account, then use it as if it were the operator's.
    /// </summary>
    private readonly ConcurrentDictionary<string, (string Nonce, DateTime ExpiresUtc)> _pendingStates =
        new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(10);

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
        // Recorded here so the callback can be checked against it. A caller-supplied state is used
        // as given - it may already be a nonce from a wider flow - but it is never merely echoed.
        _pendingStates[provider] = (state, DateTime.UtcNow.Add(StateLifetime));

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
            // The state was received and discarded before this check existed, so any callback that
            // named a provider SPLAT was waiting on got its code vaulted - including one an attacker
            // sent. A mismatch is refused and the pending state is NOT consumed, so a guessing
            // attacker cannot burn the operator's legitimate handshake by racing it.
            if (!StateMatchesPendingRequest(provider, state))
            {
                return false;
            }

            try
            {
                // Vault the received authorization code & simulated token
                string vaultKey = $"oauth_token_{provider.ToLowerInvariant()}";
                string tokenJson = $"{{\"provider\":\"{provider}\",\"code\":\"{code}\",\"vaulted_at\":\"{DateTime.UtcNow:o}\"}}";
                await _vault.StoreSecretStringAsync(vaultKey, tokenJson, CancellationToken.None);

                // Single use: a replayed callback carrying the same state finds nothing pending.
                _pendingStates.TryRemove(provider, out _);

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

    /// <summary>
    /// True when the callback's state is the one SPLAT issued for this provider and has not expired.
    /// Compared in fixed time: the state is a secret for exactly as long as the handshake lasts.
    /// </summary>
    private bool StateMatchesPendingRequest(string provider, string presentedState)
    {
        if (!_pendingStates.TryGetValue(provider, out var pending))
        {
            return false;
        }

        if (DateTime.UtcNow > pending.ExpiresUtc)
        {
            _pendingStates.TryRemove(provider, out _);
            return false;
        }

        if (string.IsNullOrEmpty(presentedState))
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(presentedState),
            Encoding.UTF8.GetBytes(pending.Nonce));
    }

    /// <summary>A state value suitable for <see cref="BuildAuthorizationUrl"/> when the caller has none.</summary>
    public static string NewState() =>
        Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();

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
