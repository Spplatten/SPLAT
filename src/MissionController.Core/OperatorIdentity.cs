using System;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Models;

namespace MissionController.Core;

/// <summary>
/// How an operator identity was established. This is recorded alongside the identity itself
/// because "who did this" is worthless to an auditor without "and how do you know".
/// </summary>
public enum OperatorAuthenticationMethod
{
    /// <summary>No credential was presented and no OS principal could be read.</summary>
    Unauthenticated = 0,

    /// <summary>The Windows logon session the process is running under. Established by the OS.</summary>
    WindowsAuthenticated = 1,

    /// <summary>A pre-registered API key, validated by <see cref="Interfaces.IApiKeyValidator"/>.</summary>
    ApiKey = 2,

    /// <summary>A signed bearer token, validated by <see cref="Interfaces.ITokenValidator"/>.</summary>
    BearerToken = 3
}

/// <summary>
/// A resolved actor for the audit ledger.
///
/// This type exists because every ledger row in this product used to be attributed to a string
/// literal chosen at the call site - <c>"Operator_AuntMaryTier1"</c>, <c>"Operator_1Click"</c>,
/// <c>"mcp-client"</c> - while the README mapped the ledger to NIST AU.2.041-042
/// non-repudiation. A SHA-256 chain over an actor nobody established proves the ROW has not been
/// edited; it proves nothing whatsoever about who acted.
///
/// The fix is not to invent a login ceremony a local desktop app has no authority to run. It is to
/// record the identity that genuinely exists, and to be explicit when none does - an
/// <see cref="OperatorAuthenticationMethod.Unauthenticated"/> row is honest, where a fabricated
/// name is not.
/// </summary>
public sealed record OperatorIdentity(
    string DisplayName,
    string? PrincipalId,
    OperatorAuthenticationMethod Method,
    string? Transport = null,
    SecurityIdentityContext? Context = null)
{
    /// <summary>
    /// True when this identity was established by something outside the caller's own assertion,
    /// and can therefore carry an attribution claim.
    /// </summary>
    public bool IsAttributable => Method != OperatorAuthenticationMethod.Unauthenticated;

    /// <summary>
    /// The single string written to the ledger's OperatorIdentity column, which the chain hash
    /// commits to. The method prefix is part of the value on purpose: the column is one field and
    /// an auditor reading it needs the provenance, not just a name. The stable principal id is
    /// carried alongside the display name because display names are renameable and SIDs are not.
    /// </summary>
    public string ToLedgerIdentity()
    {
        string prefix = Method switch
        {
            OperatorAuthenticationMethod.WindowsAuthenticated => "windows",
            OperatorAuthenticationMethod.ApiKey => "apikey",
            OperatorAuthenticationMethod.BearerToken => "bearer",
            _ => "unauthenticated"
        };

        string body = string.IsNullOrWhiteSpace(PrincipalId)
            ? DisplayName
            : $"{DisplayName} [{PrincipalId}]";

        return string.IsNullOrWhiteSpace(Transport)
            ? $"{prefix}:{body}"
            : $"{prefix}:{body} via {Transport}";
    }

    /// <summary>
    /// Fallback for a host that can resolve nothing at all. Named rather than blank so it can never
    /// be mistaken for a real principal, and so an auditor can grep for it.
    /// </summary>
    public static OperatorIdentity Unknown(string? transport = null) =>
        new("unresolved-principal", null, OperatorAuthenticationMethod.Unauthenticated, transport);
}

/// <summary>
/// Resolves the actor on whose behalf a mission is about to run. Implementations answer for one
/// host: the WinUI console answers with the Windows logon session, the MCP server answers with a
/// validated client credential or, failing that, the principal its own process runs as.
/// </summary>
public interface IOperatorIdentityProvider
{
    ValueTask<OperatorIdentity> ResolveAsync(CancellationToken cancellationToken = default);
}
