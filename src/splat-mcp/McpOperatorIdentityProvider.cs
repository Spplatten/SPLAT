using System;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Interfaces;

namespace SplatMcp;

/// <summary>
/// Raised when a client presented a credential that did not validate. The call must not proceed:
/// a rejected credential is a refused request, never an anonymous one.
/// </summary>
public sealed class McpAuthenticationException : Exception
{
    public string ErrorCode { get; }

    public McpAuthenticationException(string message, string errorCode)
        : base(message)
    {
        ErrorCode = errorCode;
    }
}

/// <summary>
/// Resolves the actor behind an MCP tool call.
///
/// Every ledger row this server wrote used to be attributed to the literal <c>"mcp-client"</c>.
/// That is not a principal; it is the name of the transport, recorded in the column reserved for
/// who acted.
///
/// The resolution order below is deliberately not "demand a token or refuse". A stdio MCP server
/// is spawned BY its client and runs in that user's own session, so for the shipped configuration
/// there is no second principal to authenticate and a mandatory token would be theatre - the
/// honest identity is the Windows logon session the server runs under, tagged with the transport
/// so an auditor can tell a console action from an agent-driven one.
///
/// A credential is therefore optional, but never ignored: when one IS configured (a remote
/// transport, or several agent clients that must be told apart) it is validated by the
/// <see cref="ITokenValidator"/> / <see cref="IApiKeyValidator"/> that have existed and been
/// tested since the first commit without ever gating anything, and a bad credential fails closed.
/// </summary>
public sealed class McpOperatorIdentityProvider : IOperatorIdentityProvider
{
    /// <summary>Env var carrying a bearer token or API key for the client, when one is in use.</summary>
    public const string CredentialEnvironmentVariable = "SPLAT_MCP_CLIENT_CREDENTIAL";

    private readonly IOperatorIdentityProvider _hostIdentity;
    private readonly ITokenValidator? _tokenValidator;
    private readonly IApiKeyValidator? _apiKeyValidator;
    private readonly string? _presentedCredential;

    private OperatorIdentity? _cached;

    public McpOperatorIdentityProvider(
        IOperatorIdentityProvider hostIdentity,
        ITokenValidator? tokenValidator = null,
        IApiKeyValidator? apiKeyValidator = null,
        string? presentedCredential = null)
    {
        _hostIdentity = hostIdentity ?? throw new ArgumentNullException(nameof(hostIdentity));
        _tokenValidator = tokenValidator;
        _apiKeyValidator = apiKeyValidator;
        _presentedCredential = string.IsNullOrWhiteSpace(presentedCredential)
            ? Environment.GetEnvironmentVariable(CredentialEnvironmentVariable)
            : presentedCredential;
    }

    public async ValueTask<OperatorIdentity> ResolveAsync(CancellationToken cancellationToken = default)
    {
        if (_cached is not null)
        {
            return _cached;
        }

        if (!string.IsNullOrWhiteSpace(_presentedCredential))
        {
            return _cached = await ValidateCredentialAsync(_presentedCredential, cancellationToken);
        }

        // No credential in play: fall back to the principal this process actually runs as, tagged
        // with the transport. Attributable, and true.
        var host = await _hostIdentity.ResolveAsync(cancellationToken);
        return _cached = host with { Transport = "mcp-stdio" };
    }

    private async Task<OperatorIdentity> ValidateCredentialAsync(string credential, CancellationToken cancellationToken)
    {
        // A JWT is three base64url segments separated by dots; anything else is treated as an API
        // key. Probing the shape rather than requiring the caller to declare it keeps the
        // configuration to one env var.
        bool looksLikeJwt = credential.TrimStart().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                            || credential.Split('.').Length == 3;

        if (looksLikeJwt && _tokenValidator is not null)
        {
            var result = await _tokenValidator.ValidateTokenAsync(credential, cancellationToken);
            if (!result.IsValid || result.IdentityContext is null)
            {
                throw new McpAuthenticationException(
                    $"The presented bearer token was rejected: {result.ErrorMessage}",
                    result.ErrorCode ?? "INVALID_TOKEN");
            }

            return FromContext(result.IdentityContext, OperatorAuthenticationMethod.BearerToken);
        }

        if (_apiKeyValidator is not null)
        {
            var result = await _apiKeyValidator.ValidateApiKeyAsync(credential, cancellationToken);
            if (!result.IsValid || result.IdentityContext is null)
            {
                throw new McpAuthenticationException(
                    $"The presented API key was rejected: {result.ErrorMessage}",
                    result.ErrorCode ?? "INVALID_API_KEY");
            }

            return FromContext(result.IdentityContext, OperatorAuthenticationMethod.ApiKey);
        }

        // A credential was configured and there is nothing able to check it. Running anyway would
        // mean recording an identity the caller merely asserted, which is the failure this whole
        // type exists to remove.
        throw new McpAuthenticationException(
            "A client credential was configured but no validator is registered to check it.",
            "NO_VALIDATOR_CONFIGURED");
    }

    private static OperatorIdentity FromContext(
        MissionController.Core.Models.SecurityIdentityContext context,
        OperatorAuthenticationMethod method) =>
        new(
            DisplayName: context.OperatorIdentity,
            PrincipalId: string.IsNullOrWhiteSpace(context.TenantId) ? null : $"tenant={context.TenantId}",
            Method: method,
            Transport: "mcp-stdio",
            Context: context);
}
