using System;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core.Interfaces;

/// <summary>
/// The result of issuing a secret to the daemon's broker. The grant is an opaque 64-hex token
/// that binds to the exact EXECUTE_TOOL request and expires with the session.
/// </summary>
public sealed record SecretGrant(string GrantHex, DateTimeOffset IssuedUtc, TimeSpan Ttl);

/// <summary>
/// Bridges the host credential vault to the daemon's root-only secret broker. Retrieves a
/// scoped credential from DPAPI, pipes it into <c>splat-agent --issue-secret</c>, and returns
/// the opaque grant the caller attaches to the EXECUTE_TOOL frame.
/// </summary>
public interface ISecretIssuance
{
    /// <summary>
    /// Issue a secret for one lease step. The vault key names the DPAPI-protected credential;
    /// the binding JSON carries the nonces and the approved request (never the secret).
    /// </summary>
    /// <param name="vaultKey">The key in <see cref="ICredentialVault"/> to retrieve.</param>
    /// <param name="clientNonce">64-hex nonce from the protocol session.</param>
    /// <param name="serverNonce">64-hex nonce from the protocol session.</param>
    /// <param name="approvedRequest">The complete EXECUTE_TOOL JSON object without secretGrant.</param>
    /// <param name="ttlSeconds">Grant lifetime, 1–60.</param>
    /// <param name="ct">Cancellation token.</param>
    /// <returns>The opaque grant, or throws on failure.</returns>
    Task<SecretGrant> IssueAsync(
        string vaultKey,
        string clientNonce,
        string serverNonce,
        string approvedRequest,
        int ttlSeconds = 30,
        CancellationToken ct = default);
}
