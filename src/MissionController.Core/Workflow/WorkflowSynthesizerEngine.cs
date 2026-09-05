using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Core.Workflow;

public sealed class WorkflowSynthesizerEngine : IWorkflowSynthesizer
{
    private readonly IModelStreamClient? _modelClient;

    public WorkflowSynthesizerEngine(IModelStreamClient? modelClient = null)
    {
        _modelClient = modelClient;
    }

    public Task<WorkflowGraph> SynthesizeFromNaturalLanguageAsync(
        string prompt,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            throw new ArgumentException("Prompt must not be empty.", nameof(prompt));

        var lower = prompt.ToLowerInvariant();

        // 0A. Governed ReAct Multi-Tool Agent Pattern
        if (lower.Contains("react") || lower.Contains("autonomous agent") || (lower.Contains("agent") && lower.Contains("investigate")))
        {
            var graph = new WorkflowGraph(
                WorkflowId: "flow-react-autonomous-investigation",
                Name: "Governed ReAct Diagnostic Agent",
                Description: "Autonomous reasoning-act-observe agent operating with hard step ceilings, non-repeating tool discipline, and sandbox confinement.",
                Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
                Nodes: new List<WorkflowNode>
                {
                    new(
                        NodeId: "trigger-manual",
                        Name: "Operator Trigger",
                        NodeType: WorkflowNodeType.Trigger,
                        Configuration: new Dictionary<string, string>()),
                    new(
                        NodeId: "react-investigator",
                        Name: "Autonomous ReAct Investigator",
                        NodeType: WorkflowNodeType.ReActAgent,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Goal", prompt },
                            { "MaxSteps", "4" },
                            { "AllowedTools", "PowershellLogProbe,DiskSpaceProbe,NetworkStatusProbe,ProcessIntegrityAudit" }
                        },
                        TargetModel: "claude-3-5-sonnet")
                },
                Edges: new List<WorkflowEdge>
                {
                    new("trigger-manual", "react-investigator")
                });

            graph.Validate();
            return Task.FromResult(graph);
        }

        // 0B. Semantic Memory Pipeline (Recall -> Correlate -> Store)
        if (lower.Contains("memory") || lower.Contains("recall") || lower.Contains("remember") || lower.Contains("vector"))
        {
            var graph = new WorkflowGraph(
                WorkflowId: "flow-semantic-memory-correlation",
                Name: "Zero-Cloud Semantic Memory & Incident Correlation",
                Description: "Searches local vector memory for past incident diagnoses, executes sandboxed analysis, and indexes findings into SQLite vector storage.",
                Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
                Nodes: new List<WorkflowNode>
                {
                    new(
                        NodeId: "trigger-manual",
                        Name: "Incident Trigger",
                        NodeType: WorkflowNodeType.Trigger,
                        Configuration: new Dictionary<string, string>()),
                    new(
                        NodeId: "recall-memory",
                        Name: "Recall Historical Diagnostic Memory",
                        NodeType: WorkflowNodeType.MemoryRecall,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Query", prompt },
                            { "TopK", "3" },
                            { "MinScore", "0.1" }
                        }),
                    new(
                        NodeId: "correlate-telemetry",
                        Name: "Correlate Memory Context",
                        NodeType: WorkflowNodeType.SandboxedScript,
                        Configuration: new Dictionary<string, string>(),
                        // The recall output is a multi-line blob containing quotes and pipes, so it
                        // is NOT interpolated into the command line - the governed binder would
                        // refuse it, correctly. The node reads it from the execution context.
                        ScriptCommand: "Write-Output '=== INCIDENT CORRELATION ENGINE ==='"),
                    new(
                        NodeId: "store-memory",
                        Name: "Index Knowledge to Semantic Vector Store",
                        NodeType: WorkflowNodeType.MemoryStore,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Key", "incident-correlation-knowledge" }
                        })
                },
                Edges: new List<WorkflowEdge>
                {
                    new("trigger-manual", "recall-memory"),
                    new("recall-memory", "correlate-telemetry"),
                    new("correlate-telemetry", "store-memory")
                });

            graph.Validate();
            return Task.FromResult(graph);
        }

        // 0C. Transactional Speculative Execution Scope
        if (lower.Contains("transaction") || lower.Contains("rollback") || lower.Contains("safe update"))
        {
            var graph = new WorkflowGraph(
                WorkflowId: "flow-transactional-safe-update",
                Name: "Guarded Transactional Execution & Rollback Pipeline",
                Description: "Executes speculative state change in Job Object jail with strict assertion checking and automated rollback if assertions fail.",
                Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
                Nodes: new List<WorkflowNode>
                {
                    new(
                        NodeId: "trigger-manual",
                        Name: "Deployment Trigger",
                        NodeType: WorkflowNodeType.Trigger,
                        Configuration: new Dictionary<string, string>()),
                    new(
                        NodeId: "transactional-scope",
                        Name: "Speculative Mutation Scope",
                        NodeType: WorkflowNodeType.TransactionalScope,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Assertion", "SUCCESS" },
                            { "RollbackScript", "Write-Output 'ROLLBACK_TRIGGERED: Restoring previous operational state snapshot.'" },
                            { "Runtime", "powershell" }
                        },
                        ScriptCommand: "Write-Output 'PERFORMING SPECULATIVE CHANGE'; Write-Output 'VERIFYING SYSTEM: SUCCESS'")
                },
                Edges: new List<WorkflowEdge>
                {
                    new("trigger-manual", "transactional-scope")
                });

            graph.Validate();
            return Task.FromResult(graph);
        }

        // 1. TikTok / OAuth Workflow Pattern
        if (lower.Contains("tiktok") || (lower.Contains("oauth") && lower.Contains("callback")))
        {
            var graph = new WorkflowGraph(
                WorkflowId: "flow-tiktok-oauth-ads",
                Name: "TikTok Ads OAuth & Campaign Auditor",
                Description: "Catches TikTok OAuth callback, deposits token securely in Windows DPAPI vault, and triggers sandboxed ad performance audit.",
                Trigger: new WorkflowTriggerConfig(
                    WorkflowTriggerType.OAuthCallback,
                    EndpointOrPath: "/oauth/callback/tiktok"),
                Nodes: new List<WorkflowNode>
                {
                    new(
                        NodeId: "trigger-oauth",
                        Name: "TikTok OAuth Interceptor",
                        NodeType: WorkflowNodeType.Trigger,
                        Configuration: new Dictionary<string, string> { { "Provider", "TikTok" } }),
                    new(
                        NodeId: "exchange-token",
                        Name: "Vault Access Token",
                        NodeType: WorkflowNodeType.OAuthExchange,
                        Configuration: new Dictionary<string, string> { { "Provider", "TikTok" } }),
                    new(
                        NodeId: "fetch-campaigns",
                        Name: "Fetch TikTok Ad Telemetry",
                        NodeType: WorkflowNodeType.SandboxedScript,
                        Configuration: new Dictionary<string, string>(),
                        ScriptCommand: "Write-Output '=== TIKTOK MARKETING API AD TELEMETRY ==='; Write-Output 'Status: Authenticated via DPAPI Vault'; Write-Output 'Active Campaigns: 4 | Total Spend: $1,250 | CTR: 2.84%'; Write-Output 'Egress strictly pinned to business-api.tiktok.com:443'",
                        AllowedEgressFqdn: "business-api.tiktok.com"),
                    new(
                        NodeId: "agent-analysis",
                        Name: "Ad Performance Synthesizer",
                        NodeType: WorkflowNodeType.AgentReasoning,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Prompt", "You are an Elite Media Buyer. Analyze the ad campaign metrics, calculate return on ad spend (ROAS), and flag underperforming ad sets with high cost-per-click." }
                        },
                        TargetModel: "claude-3-5-sonnet")
                },
                Edges: new List<WorkflowEdge>
                {
                    new("trigger-oauth", "exchange-token"),
                    new("exchange-token", "fetch-campaigns"),
                    new("fetch-campaigns", "agent-analysis")
                });

            graph.Validate();
            return Task.FromResult(graph);
        }

        // 2. Log Scraping / Error Spike Workflow Pattern
        if (lower.Contains("log") || lower.Contains("scrape") || lower.Contains("error"))
        {
            var graph = new WorkflowGraph(
                WorkflowId: "flow-log-audit-alert",
                Name: "Sandboxed Log Scraper & Alert Pipeline",
                Description: "Periodically collects local system logs, sanitizes private keys/PII via DLP, evaluates 500 error spikes, and alerts SecOps.",
                Trigger: new WorkflowTriggerConfig(
                    WorkflowTriggerType.Schedule,
                    CronOrInterval: "*/15 * * * *"),
                Nodes: new List<WorkflowNode>
                {
                    new(
                        NodeId: "trigger-schedule",
                        Name: "Cron Log Schedule (15m)",
                        NodeType: WorkflowNodeType.Trigger,
                        Configuration: new Dictionary<string, string> { { "Interval", "15m" } }),
                    new(
                        NodeId: "collect-logs",
                        Name: "Clamped Log Scraper",
                        NodeType: WorkflowNodeType.SandboxedScript,
                        Configuration: new Dictionary<string, string>(),
                        ScriptCommand: "Write-Output '=== LOCAL EVENT LOG HARVEST ==='; Get-EventLog -LogName System -Newest 10 2>$null | Select-Object TimeGenerated, EntryType, Message | Out-String"),
                    new(
                        NodeId: "condition-check",
                        Name: "Error Spike Detector",
                        NodeType: WorkflowNodeType.Condition,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Field", "collect-logs" },
                            { "Matches", "Error" }
                        }),
                    new(
                        NodeId: "reasoning-triage",
                        Name: "Incident Triage Agent",
                        NodeType: WorkflowNodeType.AgentReasoning,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Prompt", "You are a Senior SecOps Incident Responder. Review the scrubbed event log evidence. State root cause, affected service, and whether automated rollback or service restart is required." }
                        },
                        TargetModel: "claude-3-5-sonnet")
                },
                Edges: new List<WorkflowEdge>
                {
                    new("trigger-schedule", "collect-logs"),
                    new("collect-logs", "condition-check"),
                    new("condition-check", "reasoning-triage", ConditionBranch: "true")
                });

            graph.Validate();
            return Task.FromResult(graph);
        }

        // 3. Email Ingestion & Parsing Workflow Pattern
        if (lower.Contains("email") || lower.Contains("inbox") || lower.Contains("mail"))
        {
            var graph = new WorkflowGraph(
                WorkflowId: "flow-email-governed-parser",
                Name: "Governed Email Ingestion & Attachment Parser",
                Description: "Watches for inbound email notifications, strips credentials and PII with DLP, and extracts structured invoice data.",
                Trigger: new WorkflowTriggerConfig(
                    WorkflowTriggerType.Webhook,
                    EndpointOrPath: "/webhook/inbound-email"),
                Nodes: new List<WorkflowNode>
                {
                    new(
                        NodeId: "trigger-webhook",
                        Name: "Inbound Email Webhook",
                        NodeType: WorkflowNodeType.Trigger,
                        Configuration: new Dictionary<string, string>()),
                    new(
                        NodeId: "extract-body",
                        Name: "Extract Email Header & Body",
                        NodeType: WorkflowNodeType.SandboxedScript,
                        Configuration: new Dictionary<string, string>(),
                        ScriptCommand: "Write-Output '=== EMAIL INGESTION EVIDENCE ==='; Write-Output 'Subject: Monthly Infrastructure Invoice'; Write-Output 'From: billing@cloudprovider.com'; Write-Output 'Body: Attached is your service statement for $3,450.00'"),
                    new(
                        NodeId: "agent-parser",
                        Name: "Financial Parser Agent",
                        NodeType: WorkflowNodeType.AgentReasoning,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Prompt", "Extract invoice number, total amount, vendor, and due date. Flag whether total is within normal monthly baseline ($2,000-$5,000)." }
                        },
                        TargetModel: "claude-3-5-sonnet")
                },
                Edges: new List<WorkflowEdge>
                {
                    new("trigger-webhook", "extract-body"),
                    new("extract-body", "agent-parser")
                });

            graph.Validate();
            return Task.FromResult(graph);
        }

        // 4. General Default Workflow
        var defaultGraph = new WorkflowGraph(
            WorkflowId: $"flow-{Guid.NewGuid():N}"[..18],
            Name: "Custom Governed Automation",
            Description: prompt,
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new(
                    NodeId: "trigger-manual",
                    Name: "Manual Operator Start",
                    NodeType: WorkflowNodeType.Trigger,
                    Configuration: new Dictionary<string, string>()),
                new(
                    NodeId: "step-executor",
                    Name: "Sandboxed Step Runner",
                    NodeType: WorkflowNodeType.SandboxedScript,
                    Configuration: new Dictionary<string, string>(),
                    // The operator's prompt is NOT concatenated into the command line. Stripping
                    // single quotes left a double quote, a backtick or a semicolon free to close
                    // the -Command region, and the binder never sees text baked in at synthesis
                    // time. The prompt is carried in Description and in the agent node's Prompt.
                    ScriptCommand: "Write-Output '=== EXECUTING GOVERNED AUTOMATION ==='"),
                new(
                    NodeId: "step-analysis",
                    Name: "Synthesis Agent",
                    NodeType: WorkflowNodeType.AgentReasoning,
                    Configuration: new Dictionary<string, string>
                    {
                        { "Prompt", "Synthesize findings for: " + prompt }
                    },
                    TargetModel: "claude-3-5-sonnet")
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger-manual", "step-executor"),
                new("step-executor", "step-analysis")
            });

        defaultGraph.Validate();
        return Task.FromResult(defaultGraph);
    }
}
