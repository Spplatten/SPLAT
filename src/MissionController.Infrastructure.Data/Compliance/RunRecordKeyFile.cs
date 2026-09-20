using System;
using System.IO;
using System.Security.Cryptography;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Data.Compliance;

/// <summary>
/// The operator's run record signing key: an RSA private key in a PEM file they keep, like the ledger
/// key. SPLAT reads the file and never prints it; every message here names the path, never key
/// material. The public half travels in each bundle, and its fingerprint is what the operator
/// publishes so a verifier can tell their bundles from anyone else's.
/// </summary>
public static class RunRecordKeyFile
{
    /// <summary>How a host is given the key file without a command line option of its own.</summary>
    public const string EnvironmentVariable = "SPLAT_RUN_RECORD_KEY_FILE";

    /// <summary>What <see cref="NewKeyPem"/> makes: 3072 bits holds past 2030 by NIST's reckoning.</summary>
    public const int CreatedKeyBits = 3072;

    public const int MinimumKeyBits = 2048;

    private const int MaximumBytes = 16 * 1024;

    /// <summary>Why this path cannot be the key file, or null when it might be. Looks only at the file.</summary>
    public static string? Problem(string fullPath)
    {
        if (Directory.Exists(fullPath))
        {
            return $"'{fullPath}' is a folder; the run record key is a file.";
        }

        if (!File.Exists(fullPath))
        {
            return $"'{fullPath}' does not exist. Make one with `splat-mcp new-run-record-key <file>`.";
        }

        return new FileInfo(fullPath).Length > MaximumBytes
            ? $"'{fullPath}' is larger than a key file should be ({MaximumBytes} bytes), so it is probably not the key."
            : null;
    }

    /// <summary>Loads the operator's key. Throws, naming the path, when the file is not a usable RSA private key.</summary>
    public static RsaRunRecordSigner Load(string path)
    {
        string fullPath = Path.GetFullPath(path);
        if (Problem(fullPath) is string problem)
        {
            throw new InvalidOperationException(problem);
        }

        string pem = File.ReadAllText(fullPath);
        if (pem.Contains("ENCRYPTED PRIVATE KEY", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"'{fullPath}' holds an encrypted key. SPLAT reads an unencrypted RSA key, kept where only you can read it.");
        }

        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(pem);
            if (rsa.KeySize < MinimumKeyBits)
            {
                throw new InvalidOperationException($"'{fullPath}' holds a {rsa.KeySize}-bit key; a run record key needs at least {MinimumKeyBits}.");
            }

            // ImportFromPem takes a public key as readily as a private one, and only signing tells them apart.
            rsa.SignData(new byte[1], HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return new RsaRunRecordSigner(rsa);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new InvalidOperationException($"'{fullPath}' holds no RSA private key in PEM form.", ex);
        }
        catch
        {
            rsa.Dispose();
            throw;
        }
    }

    /// <summary>A new key as unencrypted PKCS#8 PEM, and its key id. The caller writes it where only the operator can read it.</summary>
    public static string NewKeyPem(out string keyId)
    {
        using var rsa = RSA.Create(CreatedKeyBits);
        keyId = RsaRunRecordSigner.KeyIdOf(rsa.ExportRSAPublicKey());
        return rsa.ExportPkcs8PrivateKeyPem();
    }
}

/// <summary>RSASSA-PKCS1-v1_5 over SHA-256: verifiable with nothing but Python's standard library or .NET.</summary>
public sealed class RsaRunRecordSigner : IRunRecordSigner, IDisposable
{
    private readonly RSA _rsa;

    internal RsaRunRecordSigner(RSA rsa)
    {
        _rsa = rsa;
        PublicKeyDer = rsa.ExportRSAPublicKey();
        KeyId = KeyIdOf(PublicKeyDer);
    }

    public string KeyId { get; }

    public string Algorithm => "RSASSA-PKCS1-v1_5-SHA256";

    public byte[] PublicKeyDer { get; }

    public byte[] Sign(byte[] data) => _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    /// <summary>The fingerprint a verifier recomputes from the key the bundle carries.</summary>
    public static string KeyIdOf(byte[] publicKeyDer) =>
        "sha256:" + Convert.ToHexString(SHA256.HashData(publicKeyDer)).ToLowerInvariant();

    public void Dispose() => _rsa.Dispose();
}
