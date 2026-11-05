using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Linux;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Tests for the <see cref="SecretIssuanceService"/> parameter validation and contract.
/// Live integration (vault + daemon) is tested under root by the probe suite, not here.
/// </summary>
public class SecretIssuanceTests
{
    private const string ValidNonce = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
    private const string ValidRequest = """{"type":"EXECUTE_TOOL","command":"/usr/bin/curl","argv":["-s","https://api.github.com"]}""";

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(61)]
    [InlineData(100)]
    public async Task IssueAsync_RejectsTtlOutOfRange(int ttl)
    {
        var vault = new StubVault(new byte[] { 1, 2, 3 });
        var service = new SecretIssuanceService(vault, "TestDistro");

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.IssueAsync("test-key", ValidNonce, ValidNonce, ValidRequest, ttl));
    }

    [Fact]
    public async Task IssueAsync_RejectsEmptyVaultKey()
    {
        var vault = new StubVault(new byte[] { 1, 2, 3 });
        var service = new SecretIssuanceService(vault, "TestDistro");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.IssueAsync("", ValidNonce, ValidNonce, ValidRequest));
    }

    [Fact]
    public async Task IssueAsync_RejectsNullSecret()
    {
        var vault = new StubVault(null);
        var service = new SecretIssuanceService(vault, "TestDistro");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.IssueAsync("missing-key", ValidNonce, ValidNonce, ValidRequest));
    }

    [Fact]
    public async Task IssueAsync_RejectsOversizedSecret()
    {
        var vault = new StubVault(new byte[4097]);
        var service = new SecretIssuanceService(vault, "TestDistro");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.IssueAsync("big-key", ValidNonce, ValidNonce, ValidRequest));
    }

    [Fact]
    public async Task IssueAsync_RejectsEmptySecret()
    {
        var vault = new StubVault(Array.Empty<byte>());
        var service = new SecretIssuanceService(vault, "TestDistro");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.IssueAsync("empty-key", ValidNonce, ValidNonce, ValidRequest));
    }

    [Fact]
    public async Task IssueAsync_RejectsEmptyNonce()
    {
        var vault = new StubVault(new byte[] { 1, 2, 3 });
        var service = new SecretIssuanceService(vault, "TestDistro");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.IssueAsync("test-key", "", ValidNonce, ValidRequest));
    }

    [Fact]
    public async Task IssueAsync_RejectsEmptyRequest()
    {
        var vault = new StubVault(new byte[] { 1, 2, 3 });
        var service = new SecretIssuanceService(vault, "TestDistro");

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.IssueAsync("test-key", ValidNonce, ValidNonce, ""));
    }

    /// <summary>
    /// A vault stub that returns a fixed byte array or null without touching DPAPI.
    /// </summary>
    private sealed class StubVault : ICredentialVault
    {
        private readonly byte[]? _secret;
        public StubVault(byte[]? secret) => _secret = secret;

        public Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken ct = default) =>
            Task.CompletedTask;
        public Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken ct = default) =>
            Task.FromResult(_secret != null ? (byte[]?)_secret.ToArray() : null);
        public Task<string?> RetrieveSecretStringAsync(string key, CancellationToken ct = default) =>
            Task.FromResult<string?>(null);
        public Task StoreSecretStringAsync(string key, string secretString, CancellationToken ct = default) =>
            Task.CompletedTask;
        public Task DeleteSecretAsync(string key, CancellationToken ct = default) =>
            Task.CompletedTask;
    }
}
