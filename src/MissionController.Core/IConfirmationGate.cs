using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core.Interfaces;

/// <summary>
/// A pending confirmation for a state-mutating tool call. The calling agent sees the summary
/// and presents it to the human operator; the operator approves or lets it expire.
/// </summary>
public sealed record PendingConfirmation(
    string Token,
    string ToolName,
    string Summary,
    string MutationVerb,
    string EgressTarget,
    string? SecretScope,
    DateTimeOffset ExpiresUtc,
    string RequestingActor)
{
    /// <summary>Hash of the serialised EXECUTE_TOOL frame this token is bound to.</summary>
    public required string RequestHash { get; init; }
}

public enum ConfirmationOutcome
{
    Granted,
    Expired,
    AlreadyConsumed,
    NotFound,
    RequestMismatch
}

/// <summary>
/// Human-in-the-loop gate for state-mutating leases. A RequiresConfirmation template cannot
/// dispatch until an operator has approved the exact request through this gate.
/// </summary>
public interface IConfirmationGate
{
    /// <summary>
    /// Create a pending confirmation for a tool call. Returns the token the caller must present
    /// to <see cref="ConsumeAsync"/> after human approval.
    /// </summary>
    Task<PendingConfirmation> RequestAsync(
        string toolName,
        string summary,
        string mutationVerb,
        string egressTarget,
        string? secretScope,
        string requestHash,
        string actor,
        TimeSpan? ttl = null,
        CancellationToken ct = default);

    /// <summary>
    /// Consume a confirmation token. Single-use: a second call returns <see cref="ConfirmationOutcome.AlreadyConsumed"/>.
    /// The requestHash must match the one the token was created with.
    /// </summary>
    Task<ConfirmationOutcome> ConsumeAsync(string token, string requestHash, CancellationToken ct = default);

    /// <summary>All pending (unconsumed, unexpired) confirmations for the given actor.</summary>
    Task<IReadOnlyList<PendingConfirmation>> ListPendingAsync(string actor, CancellationToken ct = default);
}
