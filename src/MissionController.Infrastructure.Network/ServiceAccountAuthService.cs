using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Network.Identity;

public sealed class ServiceAccountAuthService
{
    private readonly HttpClient _httpClient;
    private readonly ICredentialVault _vault;

    public const string SaTokenKey = "GoogleCloud.ServiceAccountToken";

    public ServiceAccountAuthService(HttpClient httpClient, ICredentialVault vault)
    {
        _httpClient = httpClient;
        _vault = vault;
    }

    public async Task<string> AuthenticateWithServiceAccountJsonAsync(string saJsonContent, CancellationToken cancellationToken = default)
    {
        using var doc = JsonDocument.Parse(saJsonContent);
        var root = doc.RootElement;

        string clientEmail = root.GetProperty("client_email").GetString()!;
        string privateKeyPem = root.GetProperty("private_key").GetString()!;
        string tokenUri = root.TryGetProperty("token_uri", out var uri)
            ? uri.GetString()!
            : "https://oauth2.googleapis.com/token";

        // Create JWT Assertion signed with RS256
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var header = new { alg = "RS256", typ = "JWT" };
        var payload = new
        {
            iss = clientEmail,
            scope = "https://www.googleapis.com/auth/cloud-platform",
            aud = tokenUri,
            exp = now + 3600,
            iat = now
        };

        string headerJson = JsonSerializer.Serialize(header);
        string payloadJson = JsonSerializer.Serialize(payload);

        string encodedHeader = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        string encodedPayload = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        string unsignedToken = $"{encodedHeader}.{encodedPayload}";

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        byte[] signature = rsa.SignData(Encoding.UTF8.GetBytes(unsignedToken), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        string jwtAssertion = $"{unsignedToken}.{Base64UrlEncode(signature)}";

        // Exchange JWT for OAuth2 Access Token
        var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenUri)
        {
            Content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                new KeyValuePair<string, string>("assertion", jwtAssertion)
            })
        };

        var response = await _httpClient.SendAsync(tokenRequest, cancellationToken);
        response.EnsureSuccessStatusCode();

        string json = await response.Content.ReadAsStringAsync(cancellationToken);
        using var respDoc = JsonDocument.Parse(json);
        string accessToken = respDoc.RootElement.GetProperty("access_token").GetString()!;

        await _vault.StoreSecretStringAsync(SaTokenKey, accessToken, cancellationToken);
        return accessToken;
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
