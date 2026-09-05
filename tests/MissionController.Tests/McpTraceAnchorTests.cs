using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Models;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Linux;
using SplatMcp;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// Covers the external-orchestrator interop seam: trace-id correlation into the chained audit
/// ledger and the auditAnchor chain-head commitment appended to every tools/call result.
/// </summary>
public class McpTraceAnchorTests
{
    private static McpJsonRpcMessage BuildToolCall(string tool, object arguments) => new()
    {
        JsonRpc = "2.0",
        Id = JsonSerializer.SerializeToElement(1),
        Method = "tools/call",
        Params = JsonSerializer.SerializeToElement(new { name = tool, arguments })
    };

    private static McpToolCallResult ParseToolResult(McpJsonRpcMessage response)
    {
        Assert.NotNull(response.Result);
        return JsonSerializer.Deserialize<McpToolCallResult>(response.Result!.Value.GetRawText())!;
    }

    private static JsonElement? ParseAnchorItem(McpToolCallResult result)
    {
        // The anchor is defined as an appended metadata item; the primary payload precedes it.
        var last = result.Content.LastOrDefault();
        if (last?.Text is null)
        {
            return null;
        }

        try
        {
            var doc = JsonSerializer.Deserialize<JsonElement>(last.Text);
            return doc.ValueKind == JsonValueKind.Object && doc.TryGetProperty("auditAnchor", out _)
                ? doc
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static McpServerHandler BuildHandler(IAuditLedger ledger) => new(
        new StubLeasedExecutor(),
        new TemplatePolicyCompiler(),
        ledger);

    [Fact]
    public async Task ToolCall_WithTraceId_WritesCorrelationRow_AndAnchorsToChainHead()
    {
        var ledger = new ChainingAuditLedger();
        var handler = BuildHandler(ledger);

        var response = await handler.ProcessMessageAsync(BuildToolCall("run_command", new
        {
            command = "/bin/ls",
            traceId = "langsmith-run-42",
            clientName = "langgraph"
        }));

        var correlation = Assert.Single(ledger.Entries, e => e.Action == "EXTERNAL_TRACE_CORRELATED");
        Assert.Contains("TraceId='langsmith-run-42'", correlation.Details);
        Assert.Contains("Client='langgraph'", correlation.Details);
        Assert.Contains("Tool='run_command'", correlation.Details);

        var result = ParseToolResult(response);
        var anchorDoc = ParseAnchorItem(result);
        Assert.NotNull(anchorDoc);

        var anchor = anchorDoc!.Value.GetProperty("auditAnchor");
        Assert.Equal(ledger.Entries[^1].EntryHash, anchor.GetProperty("anchorHash").GetString());
        Assert.Equal(ledger.Entries[^1].Id, anchor.GetProperty("anchorEntryId").GetInt64());
        Assert.Equal("langsmith-run-42", anchor.GetProperty("traceId").GetString());

        // The chain head at anchor time IS the correlation row, so the anchor an external
        // checkpointer embeds commits to its own trace correlation and everything before it.
        Assert.Equal(correlation.EntryHash, anchor.GetProperty("anchorHash").GetString());
    }

    [Fact]
    public async Task ToolCall_WithoutTraceId_StillAnchors_ButWritesNoCorrelationRow()
    {
        var ledger = new ChainingAuditLedger();
        var handler = BuildHandler(ledger);

        var response = await handler.ProcessMessageAsync(BuildToolCall("run_command", new { command = "/bin/ls" }));

        Assert.DoesNotContain(ledger.Entries, e => e.Action == "EXTERNAL_TRACE_CORRELATED");

        // run_command itself ledgers its execution, so a chain head exists to anchor against.
        var anchorDoc = ParseAnchorItem(ParseToolResult(response));
        Assert.NotNull(anchorDoc);
        var anchor = anchorDoc!.Value.GetProperty("auditAnchor");
        Assert.Equal(ledger.Entries[^1].EntryHash, anchor.GetProperty("anchorHash").GetString());
        Assert.Equal(JsonValueKind.Null, anchor.GetProperty("traceId").ValueKind);
    }

    [Fact]
    public async Task ToolsList_AdvertisesTraceId_OnAgentWorkflowTools()
    {
        var handler = BuildHandler(new ChainingAuditLedger());

        var response = await handler.ProcessMessageAsync(new McpJsonRpcMessage
        {
            JsonRpc = "2.0",
            Id = JsonSerializer.SerializeToElement(1),
            Method = "tools/list"
        });

        Assert.NotNull(response.Result);
        var tools = response.Result!.Value.GetProperty("tools").EnumerateArray().ToList();

        foreach (var toolName in new[] { "run_command", "run_code", "diagnose_system", "investigate_system", "run_agent_brain", "run_governed_crew" })
        {
            var tool = tools.Single(t => t.GetProperty("name").GetString() == toolName);
            Assert.True(
                tool.GetProperty("inputSchema").GetProperty("properties").TryGetProperty("traceId", out _),
                $"Tool '{toolName}' does not advertise traceId.");
        }
    }

    [Fact]
    public async Task AnchorFailure_DegradesToMetadataNote_NotACallFailure()
    {
        var ledger = new ChainingAuditLedger { FailReads = true };
        var handler = BuildHandler(ledger);

        var response = await handler.ProcessMessageAsync(BuildToolCall("run_command", new { command = "/bin/ls" }));

        var result = ParseToolResult(response);
        Assert.False(result.IsError);
        Assert.Contains("Mock execution successful", result.Content[0].Text);

        var note = JsonSerializer.Deserialize<JsonElement>(result.Content[^1].Text!);
        Assert.Equal(JsonValueKind.Null, note.GetProperty("auditAnchor").ValueKind);
        Assert.Contains("ledger read refused", note.GetProperty("anchorError").GetString());
    }

    /// <summary>
    /// Real chain semantics in miniature: monotonic ids, each entry hashing over its predecessor,
    /// newest-first reads like the SQLite implementation.
    /// </summary>
    private sealed class ChainingAuditLedger : IAuditLedger
    {
        public List<AuditLogEntry> Entries { get; } = new();
        public bool FailReads { get; set; }

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            long id = Entries.Count + 1;
            string prevHash = Entries.Count > 0 ? Entries[^1].EntryHash : new string('0', 64);
            string hash = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes($"{prevHash}|{id}|{action}|{details}")));
            Entries.Add(new AuditLogEntry(id, DateTime.UtcNow, missionId, templateId, action, details, operatorIdentity, hash, prevHash));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default)
        {
            if (FailReads)
            {
                throw new InvalidOperationException("ledger read refused");
            }

            IReadOnlyList<AuditLogEntry> page = Entries
                .Where(e => missionId == null || e.MissionId == missionId)
                .OrderByDescending(e => e.Id)
                .Take(limit)
                .ToList();
            return Task.FromResult(page);
        }

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }

    private sealed class StubLeasedExecutor : ILeasedExecutor
    {
        public Task<ProcessExecutionResult> ExecuteLeasedAsync(
            LeaseSpec lease,
            string command,
            IReadOnlyList<string> argv,
            IProgress<string>? stdout = null,
            IProgress<string>? stderr = null,
            IProgress<LeaseViolationEvent>? violations = null,
            CancellationToken ct = default)
        {
            return Task.FromResult(new ProcessExecutionResult(
                ExitCode: 0,
                StandardOutput: "Mock execution successful\n",
                StandardError: "",
                TimedOut: false,
                FinalMetrics: JobResourceMetrics.Unavailable));
        }
    }
}
