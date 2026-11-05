using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace SplatMcp;

public partial class McpServerHandler
{
    private IConfirmationGate? _confirmationGate;

    // Called from the constructor or composition root to wire the gate.
    internal void SetConfirmationGate(IConfirmationGate gate) => _confirmationGate = gate;

    /// <summary>
    /// Before dispatching a template that declares RequiresConfirmation, the handler calls this
    /// to create a pending confirmation. The caller receives a token and summary; the lease does
    /// not start until confirm_tool consumes the token.
    /// </summary>
    internal async Task<PendingConfirmation> RequireConfirmationAsync(
        string toolName,
        string summary,
        string mutationVerb,
        string egressTarget,
        string? secretScope,
        JsonElement approvedRequest,
        CancellationToken ct)
    {
        if (_confirmationGate is null)
            throw new InvalidOperationException(
                "A template requires confirmation but no IConfirmationGate is registered.");

        string requestHash = HashRequest(approvedRequest);
        string actor = await ResolveActorAsync(ct);

        var pending = await _confirmationGate.RequestAsync(
            toolName, summary, mutationVerb, egressTarget, secretScope, requestHash, actor, ct: ct);

        await AppendScrubbedLogAsync(
            Guid.NewGuid(),
            $"mcp-confirmation-{toolName}",
            "CONFIRMATION_REQUESTED",
            $"Token bound to {mutationVerb} {egressTarget}; expires {pending.ExpiresUtc:O}",
            actor,
            ct);

        return pending;
    }

    private async Task<McpToolCallResult> ExecuteConfirmToolAsync(JsonElement args, CancellationToken ct)
    {
        if (_confirmationGate is null)
            return new McpToolCallResult
            {
                Content = { new McpContentItem { Text = "No confirmation gate is registered." } },
                IsError = true
            };

        string token = args.TryGetProperty("confirmationToken", out var tokenProp)
            ? tokenProp.GetString() ?? ""
            : "";

        string requestHash = args.TryGetProperty("requestHash", out var hashProp)
            ? hashProp.GetString() ?? ""
            : "";

        if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(requestHash))
            return new McpToolCallResult
            {
                Content = { new McpContentItem { Text = "confirmationToken and requestHash are required." } },
                IsError = true
            };

        string actor = await ResolveActorAsync(ct);
        var outcome = await _confirmationGate.ConsumeAsync(token, requestHash, ct);

        string status = outcome switch
        {
            ConfirmationOutcome.Granted => "CONFIRMATION_GRANTED",
            ConfirmationOutcome.Expired => "CONFIRMATION_EXPIRED",
            ConfirmationOutcome.AlreadyConsumed => "CONFIRMATION_ALREADY_CONSUMED",
            ConfirmationOutcome.NotFound => "CONFIRMATION_NOT_FOUND",
            ConfirmationOutcome.RequestMismatch => "CONFIRMATION_REQUEST_MISMATCH",
            _ => "CONFIRMATION_UNKNOWN"
        };

        await AppendScrubbedLogAsync(
            Guid.NewGuid(),
            "mcp-confirm-tool",
            status,
            $"Token {token[..Math.Min(8, token.Length)]}... outcome: {status}",
            actor,
            ct);

        bool isError = outcome != ConfirmationOutcome.Granted;

        return new McpToolCallResult
        {
            Content = { new McpContentItem { Text = JsonSerializer.Serialize(new
            {
                status,
                granted = outcome == ConfirmationOutcome.Granted,
                message = outcome switch
                {
                    ConfirmationOutcome.Granted => "Confirmation accepted. The lease will now dispatch.",
                    ConfirmationOutcome.Expired => "The confirmation token has expired. Request a new one.",
                    ConfirmationOutcome.AlreadyConsumed => "This token was already used.",
                    ConfirmationOutcome.NotFound => "No pending confirmation with this token.",
                    ConfirmationOutcome.RequestMismatch => "The request hash does not match. The request may have been modified after approval.",
                    _ => "Unknown outcome."
                }
            }) } },
            IsError = isError
        };
    }

    private async Task<McpToolCallResult> ExecuteListPendingConfirmationsAsync(CancellationToken ct)
    {
        if (_confirmationGate is null)
            return new McpToolCallResult
            {
                Content = { new McpContentItem { Text = "[]" } }
            };

        string actor = await ResolveActorAsync(ct);
        var pending = await _confirmationGate.ListPendingAsync(actor, ct);

        var items = new List<object>();
        foreach (var p in pending)
        {
            items.Add(new
            {
                confirmationToken = p.Token,
                toolName = p.ToolName,
                summary = p.Summary,
                mutation = p.MutationVerb,
                egressTarget = p.EgressTarget,
                secretScope = p.SecretScope,
                expiresUtc = p.ExpiresUtc.ToString("O"),
                requestHash = p.RequestHash
            });
        }

        return new McpToolCallResult
        {
            Content = { new McpContentItem { Text = JsonSerializer.Serialize(items) } }
        };
    }

    /// <summary>
    /// The tool definitions for confirm_tool and list_pending_confirmations, appended to the
    /// tools/list response when a confirmation gate is registered.
    /// </summary>
    internal IEnumerable<object> ConfirmationToolDefinitions()
    {
        if (_confirmationGate is null) yield break;

        yield return new
        {
            name = "confirm_tool",
            description = "Approve a pending human-in-the-loop confirmation for a state-mutating lease. " +
                          "Present the pending confirmation's summary to the human operator and pass the " +
                          "token here once they approve.",
            inputSchema = new
            {
                type = "object",
                properties = new Dictionary<string, object>
                {
                    ["confirmationToken"] = new { type = "string", description = "The 64-hex token from the pending confirmation." },
                    ["requestHash"] = new { type = "string", description = "The request hash from the pending confirmation, proving the request was not modified." }
                },
                required = new[] { "confirmationToken", "requestHash" }
            }
        };

        yield return new
        {
            name = "list_pending_confirmations",
            description = "List all pending human-in-the-loop confirmations for your session. " +
                          "Each entry includes the tool name, a human-readable summary of what " +
                          "the mutation will do, the egress target, and the confirmation token.",
            inputSchema = new
            {
                type = "object",
                properties = new Dictionary<string, object>()
            }
        };
    }

    private static string HashRequest(JsonElement request)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(request.GetRawText());
        byte[] hash = SHA256.HashData(bytes);
        return Convert.ToHexStringLower(hash);
    }
}
