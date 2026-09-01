using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Network.Identity;

public sealed class PkceLoopbackAuthService : IDisposable
{
    /// <summary>Google's OAuth token endpoint host - the only destination for a code exchange.</summary>
    private const string GoogleTokenHost = "oauth2.googleapis.com";

    private readonly HttpClient _httpClient;
    private readonly ICredentialVault _vault;
    private readonly Egress.EgressFirewallHandler? _firewallHandler;
    private Timer? _renewalTimer;

    public const string TokenSecretKey = "GoogleCloud.OAuthToken";
    public const string RefreshSecretKey = "GoogleCloud.RefreshToken";

    public PkceLoopbackAuthService(
        HttpClient httpClient,
        ICredentialVault vault,
        Egress.EgressFirewallHandler? firewallHandler = null)
    {
        _httpClient = httpClient;
        _vault = vault;
        _firewallHandler = firewallHandler;
    }

    public async Task<string> PerformInteractiveLoginAsync(
        string clientId,
        string clientSecret,
        string[] scopes,
        CancellationToken cancellationToken = default)
    {
        // 1. Generate PKCE code verifier and code challenge
        string codeVerifier = GenerateCodeVerifier();
        string codeChallenge = GenerateCodeChallenge(codeVerifier);

        // 2. Start HttpListener on 127.0.0.1:0 (ephemeral port)
        using var listener = new HttpListener();
        int port = GetRandomUnusedPort();
        string redirectUri = $"http://127.0.0.1:{port}/";
        listener.Prefixes.Add(redirectUri);
        listener.Start();

        try
        {
            // 3. Construct OAuth URL & launch native default browser
            string scopeParam = Uri.EscapeDataString(string.Join(" ", scopes));
            string authUrl = $"https://accounts.google.com/o/oauth2/v2/auth?" +
                             $"client_id={Uri.EscapeDataString(clientId)}&" +
                             $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                             $"response_type=code&" +
                             $"scope={scopeParam}&" +
                             $"code_challenge={Uri.EscapeDataString(codeChallenge)}&" +
                             $"code_challenge_method=S256&" +
                             $"access_type=offline&" +
                             $"prompt=consent";

            Process.Start(new ProcessStartInfo
            {
                FileName = authUrl,
                UseShellExecute = true
            });

            // 4. Wait for authorization callback
            var contextTask = listener.GetContextAsync();
            using var reg = cancellationToken.Register(() => listener.Stop());
            var context = await contextTask;

            string? authCode = context.Request.QueryString["code"];
            string? error = context.Request.QueryString["error"];

            // 5. Send clean response page to user's browser
            byte[] responseBytes;
            if (!string.IsNullOrEmpty(authCode))
            {
                responseBytes = "<html><body style='font-family:Segoe UI,sans-serif;padding:40px;text-align:center;'><h2>Authentication Successful</h2><p>You can close this tab and return to Mission Controller.</p></body></html>"u8.ToArray();
            }
            else
            {
                responseBytes = Encoding.UTF8.GetBytes($"<html><body style='font-family:Segoe UI,sans-serif;padding:40px;text-align:center;color:red;'><h2>Authentication Failed</h2><p>{WebUtility.HtmlEncode(error ?? "Unknown error")}</p></body></html>");
            }

            context.Response.ContentType = "text/html";
            context.Response.ContentLength64 = responseBytes.Length;
            await context.Response.OutputStream.WriteAsync(responseBytes, cancellationToken);
            context.Response.OutputStream.Close();

            if (string.IsNullOrEmpty(authCode))
            {
                throw new InvalidOperationException($"OAuth authorization failed: {error}");
            }

            // 6. Exchange auth code for tokens
            var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "https://oauth2.googleapis.com/token")
            {
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", clientId),
                    new KeyValuePair<string, string>("client_secret", clientSecret),
                    new KeyValuePair<string, string>("code", authCode),
                    new KeyValuePair<string, string>("code_verifier", codeVerifier),
                    new KeyValuePair<string, string>("grant_type", "authorization_code"),
                    new KeyValuePair<string, string>("redirect_uri", redirectUri)
                })
            };

            using var tokenScope = _firewallHandler?.BeginScope(GoogleTokenHost);

            var tokenResponse = await _httpClient.SendAsync(tokenRequest, cancellationToken);
            tokenResponse.EnsureSuccessStatusCode();

            string json = await tokenResponse.Content.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(json);
            string accessToken = doc.RootElement.GetProperty("access_token").GetString()!;
            int expiresIn = doc.RootElement.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;

            if (doc.RootElement.TryGetProperty("refresh_token", out var refresh))
            {
                string refreshToken = refresh.GetString()!;
                await _vault.StoreSecretStringAsync(RefreshSecretKey, refreshToken, cancellationToken);
            }

            await _vault.StoreSecretStringAsync(TokenSecretKey, accessToken, cancellationToken);

            // Schedule background auto-renewal 5 minutes before expiration
            ScheduleTokenRenewal(clientId, clientSecret, expiresIn);

            return accessToken;
        }
        finally
        {
            listener.Stop();
        }
    }

    private void ScheduleTokenRenewal(string clientId, string clientSecret, int expiresInSeconds)
    {
        _renewalTimer?.Dispose();
        int renewInSeconds = Math.Max(60, expiresInSeconds - 300);
        _renewalTimer = new Timer(async _ =>
        {
            try
            {
                string? refreshToken = await _vault.RetrieveSecretStringAsync(RefreshSecretKey);
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    await RefreshAccessTokenAsync(clientId, clientSecret, refreshToken);
                }
            }
            catch
            {
                // Silently log or retry on failure
            }
        }, null, TimeSpan.FromSeconds(renewInSeconds), Timeout.InfiniteTimeSpan);
    }

    public async Task<string?> RefreshAccessTokenAsync(string clientId, string clientSecret, string refreshToken, CancellationToken cancellationToken = default)
    {
        var tokenRequest = new HttpRequestMessage(HttpMethod.Post, "https://oauth2.googleapis.com/token")
        {
            Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("refresh_token", refreshToken),
                new KeyValuePair<string, string>("grant_type", "refresh_token")
            })
        };

        using var refreshScope = _firewallHandler?.BeginScope(GoogleTokenHost);

        var response = await _httpClient.SendAsync(tokenRequest, cancellationToken);
        if (!response.IsSuccessStatusCode)
            return null;

        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        using var doc = JsonDocument.Parse(json);
        string accessToken = doc.RootElement.GetProperty("access_token").GetString()!;
        int expiresIn = doc.RootElement.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 3600;

        await _vault.StoreSecretStringAsync(TokenSecretKey, accessToken, cancellationToken);
        ScheduleTokenRenewal(clientId, clientSecret, expiresIn);
        return accessToken;
    }

    public static string GenerateCodeVerifier()
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        return Base64UrlEncode(bytes);
    }

    public static string GenerateCodeChallenge(string codeVerifier)
    {
        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Base64UrlEncode(hash);
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static int GetRandomUnusedPort()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public void Dispose()
    {
        _renewalTimer?.Dispose();
    }
}
