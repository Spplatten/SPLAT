using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Linux;

/// <summary>
/// Bridges the Windows DPAPI credential vault to the daemon's root-only secret broker.
///
/// The sequence: retrieve the secret from the vault → write the binding JSON (nonces + approved
/// request, never the secret) to a temp file → pipe the raw secret bytes into
/// <c>splat-agent --issue-secret</c> on stdin → read the grant from stdout → zero the host copy.
///
/// The daemon's SECRETS.md contract guarantees the secret reaches the child's stdin as a sealed
/// memfd and never touches argv, env, the ledger or the run record.
/// </summary>
public sealed class SecretIssuanceService : ISecretIssuance
{
    private readonly ICredentialVault _vault;
    private readonly string _wslDistro;
    private readonly string _secretSocketPath;

    // The binding file is written under a guest-visible path. /run/splat/secrets/ is root-owned
    // mode 0700, matching the daemon's socket directory.
    private const string GuestBindingDir = "/run/splat/secrets";

    private static readonly TimeSpan IssuanceBudget = TimeSpan.FromSeconds(10);

    public SecretIssuanceService(
        ICredentialVault vault,
        string wslDistro = "Ubuntu",
        string secretSocketPath = "/run/splat/secrets/input.sock")
    {
        _vault = vault ?? throw new ArgumentNullException(nameof(vault));
        ArgumentException.ThrowIfNullOrWhiteSpace(wslDistro);
        ArgumentException.ThrowIfNullOrWhiteSpace(secretSocketPath);
        if (wslDistro.AsSpan().IndexOfAny([' ', '\t', '\r', '\n', '"', '\'']) >= 0)
            throw new ArgumentException("WSL distribution name must not contain whitespace or quotes.", nameof(wslDistro));
        if (!secretSocketPath.StartsWith('/') || secretSocketPath.AsSpan().IndexOfAny([' ', '\t', '\r', '\n', '"', '\'']) >= 0)
            throw new ArgumentException("Secret socket path must be an absolute POSIX path without whitespace or quotes.", nameof(secretSocketPath));
        _wslDistro = wslDistro;
        _secretSocketPath = secretSocketPath;
    }

    public async Task<SecretGrant> IssueAsync(
        string vaultKey,
        string clientNonce,
        string serverNonce,
        string approvedRequest,
        int ttlSeconds = 30,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(vaultKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientNonce);
        ArgumentException.ThrowIfNullOrWhiteSpace(serverNonce);
        ArgumentException.ThrowIfNullOrWhiteSpace(approvedRequest);

        if (ttlSeconds is < 1 or > 60)
            throw new ArgumentOutOfRangeException(nameof(ttlSeconds), "TTL must be 1–60 seconds.");

        // Step 1: retrieve the secret from the DPAPI vault
        byte[]? secretBytes = await _vault.RetrieveSecretAsync(vaultKey, ct)
            ?? throw new InvalidOperationException($"No secret found in the vault for key '{vaultKey}'.");

        try
        {
            if (secretBytes.Length is 0 or > 4096)
                throw new InvalidOperationException(
                    $"Secret for '{vaultKey}' is {secretBytes.Length} bytes; the daemon accepts 1–4096.");

            // Step 2: build the binding JSON (no secret content)
            var binding = new
            {
                clientNonce,
                serverNonce,
                request = JsonDocument.Parse(approvedRequest).RootElement,
                ttlSeconds,
                secretLength = secretBytes.Length
            };

            string bindingJson = JsonSerializer.Serialize(binding, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false
            });

            // Step 3: write binding to a temp file in the guest, pipe the secret, read the grant
            string bindingFileName = $"binding-{Guid.NewGuid():N}.json";
            string guestBindingPath = $"{GuestBindingDir}/{bindingFileName}";

            return await IssueViaCliAsync(secretBytes, bindingJson, guestBindingPath, ct);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    private async Task<SecretGrant> IssueViaCliAsync(
        byte[] secretBytes,
        string bindingJson,
        string guestBindingPath,
        CancellationToken ct)
    {
        // Write the binding file atomically at mode 0600 into the guest with one binary and no shell.
        var writeBindingPsi = new ProcessStartInfo
        {
            FileName = "wsl.exe",
            Arguments = $"-d {_wslDistro} -u root -e /usr/bin/install -m 0600 /dev/stdin {guestBindingPath}",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (var writeProc = Process.Start(writeBindingPsi)!)
        {
            await writeProc.StandardInput.WriteAsync(bindingJson);
            writeProc.StandardInput.Close();
            await writeProc.WaitForExitAsync(ct);
            if (writeProc.ExitCode != 0)
            {
                string err = await writeProc.StandardError.ReadToEndAsync(ct);
                throw new InvalidOperationException(
                    $"Failed to write binding file to guest: exit {writeProc.ExitCode}: {err}");
            }
        }

        try
        {
            // Pipe the secret into --issue-secret on the provisioned root-owned daemon binary and read the grant.
            var issuePsi = new ProcessStartInfo
            {
                FileName = "wsl.exe",
                Arguments = $"-d {_wslDistro} -u root -e /opt/splat/splat-agent --secret-socket {_secretSocketPath} --issue-secret {guestBindingPath}",
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(IssuanceBudget);

            using var issueProc = Process.Start(issuePsi)!;

            // Pipe the raw secret bytes, then close stdin
            await issueProc.StandardInput.BaseStream.WriteAsync(secretBytes, cts.Token);
            issueProc.StandardInput.Close();

            string stdout = await issueProc.StandardOutput.ReadToEndAsync(cts.Token);
            await issueProc.WaitForExitAsync(cts.Token);

            if (issueProc.ExitCode != 0)
            {
                string stderr = await issueProc.StandardError.ReadToEndAsync(ct);
                throw new InvalidOperationException(
                    $"Secret issuance failed: exit {issueProc.ExitCode}: {stderr}");
            }

            // Parse the grant from stdout: {"secretGrant":"<64 hex>"}
            using var doc = JsonDocument.Parse(stdout);
            string grant = doc.RootElement.GetProperty("secretGrant").GetString()
                ?? throw new InvalidOperationException("Daemon returned null secretGrant.");

            if (grant.Length != 64 || !IsHex(grant))
                throw new InvalidOperationException(
                    $"Daemon returned an invalid grant (length {grant.Length}).");

            return new SecretGrant(grant, DateTimeOffset.UtcNow, TimeSpan.FromSeconds(30));
        }
        finally
        {
            // Remove the binding file from the guest; redirect stdin so wsl.exe never inherits splat-mcp's JSON-RPC stream.
            try
            {
                var rmPsi = new ProcessStartInfo
                {
                    FileName = "wsl.exe",
                    Arguments = $"-d {_wslDistro} -u root -e /bin/rm -f {guestBindingPath}",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var rmProc = Process.Start(rmPsi)!;
                rmProc.StandardInput.Close();
                await rmProc.WaitForExitAsync(CancellationToken.None);
            }
            catch
            {
                // Best-effort cleanup; the daemon's directory is root-only 0700
            }
        }
    }

    private static bool IsHex(string s)
    {
        foreach (char c in s)
        {
            if (!char.IsAsciiHexDigit(c)) return false;
        }
        return true;
    }
}
