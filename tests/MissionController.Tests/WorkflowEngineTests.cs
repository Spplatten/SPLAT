using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.Workflow;
using MissionController.Infrastructure.Data;
using MissionController.Infrastructure.Data.Vector;
using MissionController.Infrastructure.Network.Dlp;
using MissionController.Infrastructure.Network.Triggers;
using Xunit;

namespace MissionController.Tests;

public class WorkflowEngineTests
{
    /// <summary>
    /// Minimal model. AgentReasoning now fails without one rather than emitting "Status: VERIFIED"
    /// over a character count, so a test about ledger rows or DLP has to supply a real analysis leg.
    /// </summary>
    private sealed class StubWorkflowModelClient : IModelStreamClient
    {
        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, "stub-provider", requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel, string systemPrompt, string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return "stub analysis";
        }
    }

    private sealed class InMemoryAuditLedger : IAuditLedger
    {
        public List<(Guid MissionId, string TemplateId, string Action, string Details)> Logs { get; } = new();

        public Task AppendLogAsync(
            Guid missionId,
            string templateId,
            string action,
            string details,
            string operatorIdentity,
            CancellationToken cancellationToken = default)
        {
            Logs.Add((missionId, templateId, action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(
            Guid? missionId = null,
            int limit = 100,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());
        }

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private sealed class InMemoryCredentialVault : ICredentialVault
    {
        public Dictionary<string, string> Vault { get; } = new(StringComparer.OrdinalIgnoreCase);

        public Task StoreSecretAsync(string key, byte[] secretBytes, CancellationToken cancellationToken = default)
        {
            Vault[key] = Encoding.UTF8.GetString(secretBytes);
            return Task.CompletedTask;
        }

        public Task<byte[]?> RetrieveSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Vault.TryGetValue(key, out var val) ? Encoding.UTF8.GetBytes(val) : null);
        }

        public Task<string?> RetrieveSecretStringAsync(string key, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(Vault.TryGetValue(key, out var val) ? val : null);
        }

        public Task StoreSecretStringAsync(string key, string secretString, CancellationToken cancellationToken = default)
        {
            Vault[key] = secretString;
            return Task.CompletedTask;
        }

        public Task DeleteSecretAsync(string key, CancellationToken cancellationToken = default)
        {
            Vault.Remove(key);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public void WorkflowGraph_CycleDetection_ThrowsInvalidOperation()
    {
        var graph = new WorkflowGraph(
            WorkflowId: "cyclic-flow",
            Name: "Cyclic Test Flow",
            Description: "Has a loop",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("node1", "Node 1", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                new("node2", "Node 2", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>()),
                new("node3", "Node 3", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>())
            },
            Edges: new List<WorkflowEdge>
            {
                new("node1", "node2"),
                new("node2", "node3"),
                new("node3", "node2") // Loop!
            });

        Assert.Throws<InvalidOperationException>(() => graph.Validate());
    }

    [Fact]
    public void WorkflowGraph_DuplicateNodeIds_ThrowsInvalidOperation()
    {
        var graph = new WorkflowGraph(
            WorkflowId: "dup-flow",
            Name: "Duplicate ID Flow",
            Description: "Invalid duplicates",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("node1", "First Node", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                new("node1", "Duplicate Node", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>())
            },
            Edges: new List<WorkflowEdge>());

        Assert.Throws<InvalidOperationException>(() => graph.Validate());
    }

    [Fact]
    public void WorkflowGraph_DisconnectedEdgeEndpoint_ThrowsInvalidOperation()
    {
        var graph = new WorkflowGraph(
            WorkflowId: "bad-edge-flow",
            Name: "Bad Edge",
            Description: "Points nowhere",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("node1", "Node 1", WorkflowNodeType.Trigger, new Dictionary<string, string>())
            },
            Edges: new List<WorkflowEdge>
            {
                new("node1", "ghost-node")
            });

        Assert.Throws<InvalidOperationException>(() => graph.Validate());
    }

    [Fact]
    public async Task WorkflowExecutionEngine_ExecutesSequentialGraph_LogsLedger()
    {
        var ledger = new InMemoryAuditLedger();
        var engine = new WorkflowExecutionEngine(auditLedger: ledger, modelClient: new StubWorkflowModelClient(), allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-sequential-test",
            Name: "Sequential Test",
            Description: "Runs trigger then step",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("trigger", "Start Trigger", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                new("step1", "Step 1", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(), ScriptCommand: "echo hello"),
                new("step2", "Step 2", WorkflowNodeType.AgentReasoning, new Dictionary<string, string> { { "Prompt", "Summarize findings" } })
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger", "step1"),
                new("step1", "step2")
            });

        var result = await engine.ExecuteAsync(
            graph,
            new Dictionary<string, string> { { "event", "start" } },
            "test-operator");

        Assert.True(result.Success);
        Assert.Contains(ledger.Logs, l => l.Action == "WORKFLOW_INITIATED");
        Assert.Contains(ledger.Logs, l => l.Action == "NODE_COMPLETED:Trigger");
        Assert.Contains(ledger.Logs, l => l.Action == "NODE_COMPLETED:SandboxedScript");
        Assert.Contains(ledger.Logs, l => l.Action == "NODE_COMPLETED:AgentReasoning");
        Assert.Contains(ledger.Logs, l => l.Action == "WORKFLOW_COMPLETED");
    }

    [Fact]
    public async Task WorkflowExecutionEngine_SanitizesSensitiveSecretsWithDlp()
    {
        var dlp = new RegexDataLossPreventionSanitizer();
        var engine = new WorkflowExecutionEngine(dlpSanitizer: dlp, modelClient: new StubWorkflowModelClient(), allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-dlp-test",
            Name: "DLP Test",
            Description: "Masks password in flow",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("step1", "Leak Password", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "api_key=sk_live_secret_token_abcdef1234567890"),
                new("step2", "Receiver", WorkflowNodeType.AgentReasoning, new Dictionary<string, string>())
            },
            Edges: new List<WorkflowEdge> { new("step1", "step2") });

        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteStreamingAsync(graph, new Dictionary<string, string>(), "test-operator"))
        {
            chunks.Add(chunk);
        }

        Assert.Contains(chunks, c => c.Content.Contains("[DLP] Scrubbed"));
    }

    [Fact]
    public async Task WorkflowExecutionEngine_ConditionalBranching_SkipsInactiveBranch()
    {
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-branch-test",
            Name: "Branch Test",
            Description: "Tests condition evaluation",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("trigger", "Trigger", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                new("condition", "Check Error", WorkflowNodeType.Condition, new Dictionary<string, string>
                {
                    { "Field", "trigger" },
                    { "Matches", "CriticalAlarm" }
                }),
                new("trueNode", "Handle Critical", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(), ScriptCommand: "handle alarm"),
                new("falseNode", "Handle Normal", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(), ScriptCommand: "handle normal")
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger", "condition"),
                new("condition", "trueNode", ConditionBranch: "true"),
                new("condition", "falseNode", ConditionBranch: "false")
            });

        // Trigger with "CriticalAlarm"
        var chunks = new List<MissionChunk>();
        await foreach (var chunk in engine.ExecuteStreamingAsync(graph, new Dictionary<string, string> { { "status", "CriticalAlarm" } }, "operator"))
        {
            chunks.Add(chunk);
        }

        Assert.Contains(chunks, c => c.Content.Contains("Executing node: 'Handle Critical'"));
        Assert.Contains(chunks, c => c.Content.Contains("Skipping node 'Handle Normal'"));
    }

    [Fact]
    public async Task WorkflowSynthesizer_CompilesTikTokOAuthRequest()
    {
        var synthesizer = new WorkflowSynthesizerEngine();
        var graph = await synthesizer.SynthesizeFromNaturalLanguageAsync("Set up a TikTok OAuth callback receiver and analyze ad video campaigns");

        Assert.NotNull(graph);
        Assert.Equal("flow-tiktok-oauth-ads", graph.WorkflowId);
        Assert.Equal(WorkflowTriggerType.OAuthCallback, graph.Trigger.Type);
        Assert.Contains(graph.Nodes, n => n.NodeType == WorkflowNodeType.OAuthExchange);
        Assert.Contains(graph.Nodes, n => n.AllowedEgressFqdn == "business-api.tiktok.com");
    }

    [Fact]
    public async Task WorkflowSynthesizer_CompilesLogScrapingRequest()
    {
        var synthesizer = new WorkflowSynthesizerEngine();
        var graph = await synthesizer.SynthesizeFromNaturalLanguageAsync("Scrape system logs for error spikes and alert SecOps");

        Assert.NotNull(graph);
        Assert.Equal("flow-log-audit-alert", graph.WorkflowId);
        Assert.Equal(WorkflowTriggerType.Schedule, graph.Trigger.Type);
        Assert.Contains(graph.Nodes, n => n.NodeType == WorkflowNodeType.Condition);
        Assert.Contains(graph.Nodes, n => n.Name.Contains("Log Scraper"));
    }

    [Fact]
    public async Task WorkflowSynthesizer_CompilesEmailParserRequest()
    {
        var synthesizer = new WorkflowSynthesizerEngine();
        var graph = await synthesizer.SynthesizeFromNaturalLanguageAsync("Ingest email invoice and parse total amount");

        Assert.NotNull(graph);
        Assert.Equal("flow-email-governed-parser", graph.WorkflowId);
        Assert.Equal(WorkflowTriggerType.Webhook, graph.Trigger.Type);
        Assert.Contains(graph.Nodes, n => n.Name.Contains("Financial Parser"));
    }

    [Fact]
    public async Task OAuthExecutionNode_RefusesToVaultAFabricatedToken()
    {
        // The engine no longer takes an ICredentialVault: it has nothing legitimate to put in one
        // until a real token endpoint exists, and holding the dependency invited the fabrication.
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-oauth-test",
            Name: "OAuth Vault Test",
            Description: "Tests token storage",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.OAuthCallback),
            Nodes: new List<WorkflowNode>
            {
                new("oauthNode", "Exchange Token", WorkflowNodeType.OAuthExchange, new Dictionary<string, string> { { "Provider", "TikTok" } })
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(
            graph,
            new Dictionary<string, string> { { "code", "test_auth_code_123" } },
            "operator");

        // The node used to mint "tok_vaulted_<guid>" and deposit it under the provider's live vault
        // key, so an operator would find a bearer token no authorization server ever issued.
        Assert.False(result.Success);
        Assert.Contains("not implemented", result.FailureReason);
        Assert.DoesNotContain("tok_vaulted_", string.Join(" ", result.ExecutionLogs));
    }

    [Fact]
    public void OAuthCallbackCoordinator_BuildsValidAuthorizationUrl()
    {
        using var listener = new EmbeddedWebhookListener(5699);
        var vault = new InMemoryCredentialVault();
        var coordinator = new OAuthCallbackCoordinator(listener, vault);

        string authUrl = coordinator.BuildAuthorizationUrl(
            provider: "TikTok",
            authEndpoint: "https://business-api.tiktok.com/portal/auth",
            clientId: "app_client_id_456",
            scopes: new[] { "ads.read", "ads.write" },
            state: "sec_state_789");

        Assert.StartsWith("https://business-api.tiktok.com/portal/auth?", authUrl);
        Assert.Contains("client_id=app_client_id_456", authUrl);
        Assert.Contains("oauth%2Fcallback%2Ftiktok", authUrl);
        Assert.Contains("state=sec_state_789", authUrl);
    }

    [Fact]
    public async Task WorkflowExecution_ReActAgentNode_ExecutesBoundedToolLoop()
    {
        var ledger = new InMemoryAuditLedger();
        var dlp = new RegexDataLossPreventionSanitizer();
        var engine = new WorkflowExecutionEngine(dlpSanitizer: dlp, auditLedger: ledger, allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-react-test",
            Name: "ReAct Agent Test",
            Description: "Verifies multi-tool bounded reasoning loop",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("react-node", "Autonomous Diagnostician", WorkflowNodeType.ReActAgent, new Dictionary<string, string>
                {
                    { "Goal", "Diagnose intermittent latency and packet drops" },
                    { "MaxSteps", "3" },
                    { "AllowedTools", "LatencyProbe,DnsAudit,PacketInspection" }
                })
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "SecOpsOperator");

        Assert.True(result.Success);
        Assert.Contains("react-node", result.NodeOutputs.Keys);
        string output = result.NodeOutputs["react-node"];
        Assert.Contains("[ReAct Agent Final Synthesis]", output);
        Assert.Contains("3 tool iteration(s)", output);
        Assert.Contains(result.ExecutionLogs, log => log.Contains("[TOOL_EXECUTION:LatencyProbe]"));
    }

    [Fact]
    public async Task WorkflowExecution_MemoryStoreAndRecall_PersistsAndRetrievesContext()
    {
        string dbPath = Path.Combine(Path.GetTempPath(), $"workflow_vector_{Guid.NewGuid():N}.db");
        try
        {
            var ctx = new SqliteStorageContext(dbPath);
            var memoryIndex = new SqliteSemanticMemoryIndex(ctx);
            var engine = new WorkflowExecutionEngine(semanticMemoryIndex: memoryIndex, allowSimulatedExecution: true);

            var graph = new WorkflowGraph(
                WorkflowId: "flow-memory-test",
                Name: "Memory Correlation Pipeline",
                Description: "Tests storing and recalling vectors",
                Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
                Nodes: new List<WorkflowNode>
                {
                    new("store-node", "Index Prior Incident", WorkflowNodeType.MemoryStore, new Dictionary<string, string>
                    {
                        { "Key", "incident-brute-force" },
                        { "Content", "Event 4625 repeated failed logon attempts targeting domain admin." }
                    }),
                    new("recall-node", "Query Similar Diagnostics", WorkflowNodeType.MemoryRecall, new Dictionary<string, string>
                    {
                        { "Query", "failed logon admin attempts" },
                        { "TopK", "2" },
                        { "MinScore", "0.1" }
                    })
                },
                Edges: new List<WorkflowEdge>
                {
                    new("store-node", "recall-node")
                });

            var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "Operator");

            Assert.True(result.Success);
            Assert.Contains("[MEMORY_STORED]", result.NodeOutputs["store-node"]);
            Assert.Contains("[MEMORY_RECALL_RESULTS]", result.NodeOutputs["recall-node"]);
            Assert.Contains("incident-brute-force", result.NodeOutputs["recall-node"]);
        }
        finally
        {
            if (File.Exists(dbPath))
            {
                try { File.Delete(dbPath); } catch { }
            }
        }
    }

    [Fact]
    public async Task WorkflowExecution_TransactionalScope_SuccessWhenAssertionMatches()
    {
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-tx-success-test",
            Name: "Transactional Success Test",
            Description: "Verifies committed transaction when assertions pass",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("tx-node", "Guarded Change", WorkflowNodeType.TransactionalScope, new Dictionary<string, string>
                {
                    { "Assertion", "OK" },
                    { "RollbackScript", "Write-Output 'REVERTED'" }
                },
                ScriptCommand: "Write-Output 'PRE-CHECK: OK'")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "Operator");

        Assert.True(result.Success);
        Assert.Contains("[TRANSACTION_COMMITTED]", result.NodeOutputs["tx-node"]);
    }

    [Fact]
    public async Task WorkflowExecution_TransactionalScope_RollsBackOnAssertionFailure()
    {
        var ledger = new InMemoryAuditLedger();
        var engine = new WorkflowExecutionEngine(auditLedger: ledger, modelClient: new StubWorkflowModelClient(), allowSimulatedExecution: true);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-tx-rollback-test",
            Name: "Transactional Rollback Test",
            Description: "Verifies automatic rollback execution when assertions fail",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("tx-node", "Failing Mutation", WorkflowNodeType.TransactionalScope, new Dictionary<string, string>
                {
                    { "Assertion", "VERIFIED_GOOD" },
                    { "RollbackScript", "Write-Output 'RESTORE_BASELINE_SNAPSHOT'" }
                },
                ScriptCommand: "Write-Output 'STATUS: FAILED_CHECKS'")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "Operator");

        // A rolled-back scope did not do what it was asked to. The rollback working is not a
        // success; it is a contained failure, and the result says so.
        Assert.False(result.Success);
        Assert.Contains("VERIFIED_GOOD", result.FailureReason);
        string output = result.NodeOutputs["tx-node"];
        Assert.Contains("[TRANSACTION_ROLLED_BACK]", output);
        Assert.Contains("RESTORE_BASELINE_SNAPSHOT", output);
        Assert.Contains(ledger.Logs, l => l.Action == "TRANSACTION_ROLLED_BACK");
    }

    [Fact]
    public async Task EmbeddedWebhookListener_RestApi_ListAndExecuteWorkflow()
    {
        int port = 5698;
        var registry = new InMemoryWorkflowRegistry();
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);
        using var listener = new EmbeddedWebhookListener(port, registry, engine);

        var testWorkflow = new WorkflowGraph(
            WorkflowId: "flow-rest-api-target",
            Name: "REST API Target Flow",
            Description: "Executed remotely via HTTP POST",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("echo-node", "Echo Node", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'API_EXECUTION_ACK: payload={paramA}'")
            },
            Edges: new List<WorkflowEdge>());

        await registry.RegisterWorkflowAsync(testWorkflow);

        listener.Start();
        using var httpClient = new HttpClient();

        // Every route that can read or run something now needs the listener's token; the gate is
        // exercised separately in LoopbackGateTests.
        httpClient.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", listener.AuthToken);

        // 1. GET /api/v1/workflows
        var listResponse = await httpClient.GetAsync($"http://127.0.0.1:{port}/api/v1/workflows");
        Assert.Equal(System.Net.HttpStatusCode.OK, listResponse.StatusCode);
        string listJson = await listResponse.Content.ReadAsStringAsync();
        Assert.Contains("flow-rest-api-target", listJson);
        Assert.Contains("REST API Target Flow", listJson);

        // 2. POST /api/v1/workflows/flow-rest-api-target/execute
        var content = new StringContent(JsonSerializer.Serialize(new { paramA = "SuperSecretInput" }), Encoding.UTF8, "application/json");
        var execResponse = await httpClient.PostAsync($"http://127.0.0.1:{port}/api/v1/workflows/flow-rest-api-target/execute", content);
        Assert.Equal(System.Net.HttpStatusCode.OK, execResponse.StatusCode);
        string execJson = await execResponse.Content.ReadAsStringAsync();
        Assert.Contains("\"success\":true", execJson);
        Assert.Contains("flow-rest-api-target", execJson);
    }

    [Fact]
    public async Task WorkflowSynthesizer_CompilesAdvancedAgentAndMemoryPrompts()
    {
        var synthesizer = new WorkflowSynthesizerEngine();

        // A. Autonomous ReAct Agent prompt
        var reactGraph = await synthesizer.SynthesizeFromNaturalLanguageAsync("Run an autonomous agent to investigate network latency with react tools");
        Assert.Equal("flow-react-autonomous-investigation", reactGraph.WorkflowId);
        Assert.Contains(reactGraph.Nodes, n => n.NodeType == WorkflowNodeType.ReActAgent);

        // B. Memory Correlation prompt
        var memoryGraph = await synthesizer.SynthesizeFromNaturalLanguageAsync("Recall memory of past incidents and store new correlation knowledge");
        Assert.Equal("flow-semantic-memory-correlation", memoryGraph.WorkflowId);
        Assert.Contains(memoryGraph.Nodes, n => n.NodeType == WorkflowNodeType.MemoryRecall);
        Assert.Contains(memoryGraph.Nodes, n => n.NodeType == WorkflowNodeType.MemoryStore);

        // C. Transactional safe update prompt
        var txGraph = await synthesizer.SynthesizeFromNaturalLanguageAsync("Perform safe update with transactional rollback if failed");
        Assert.Equal("flow-transactional-safe-update", txGraph.WorkflowId);
        Assert.Contains(txGraph.Nodes, n => n.NodeType == WorkflowNodeType.TransactionalScope);
    }
}
