using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Windows.Vault;

public sealed class DpapiCredentialVault : ICredentialVault
{
    private readonly string _vaultDirectory;
    private static readonly byte[] Entropy = "MissionController.DPAPI.Entropy.v1"u8.ToArray();

    public DpapiCredentialVault(string? vaultDirectory = null)
    {
        _vaultDirectory = vaultDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "MissionController",
            "Vault");
        Directory.CreateDirectory(_vaultDirectory);
    }

    public async Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default)
    {
        string filePath = GetSecretPath(key);
        byte[] encryptedBytes = ProtectedData.Protect(secretBytes, Entropy, DataProtectionScope.CurrentUser);
        await File.WriteAllBytesAsync(filePath, encryptedBytes, cancellationToken);
    }

    public async Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default)
    {
        string filePath = GetSecretPath(key);
        if (!File.Exists(filePath))
            return null;

        byte[] encryptedBytes = await File.ReadAllBytesAsync(filePath, cancellationToken);
        try
        {
            return ProtectedData.Unprotect(encryptedBytes, Entropy, DataProtectionScope.CurrentUser);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    public async Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(secretString);
        try
        {
            await StoreSecretAsync(key, bytes, cancellationToken);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public async Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default)
    {
        byte[]? bytes = await RetrieveSecretAsync(key, cancellationToken);
        if (bytes == null)
            return null;

        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
    {
        string filePath = GetSecretPath(key);
        if (File.Exists(filePath))
        {
            File.Delete(filePath);
        }
        return Task.CompletedTask;
    }

    private string GetSecretPath(string key)
    {
        string safeKey = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));
        return Path.Combine(_vaultDirectory, $"{safeKey}.dat");
    }
}
