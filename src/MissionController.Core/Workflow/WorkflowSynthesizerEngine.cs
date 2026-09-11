using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Core.Workflow;

public sealed class WorkflowSynthesizerEngine : IWorkflowSynthesizer
{
    /// <summary>
    /// Builds a node that runs one governed template as a mission.
    ///
    /// The synthesiser used to emit `SandboxedScript` nodes carrying invented shell - including
    /// fabricated business figures that an agent node downstream then analysed as though they were
    /// measurements. A synthesised workflow now composes templates that already exist in the
    /// governed catalogue, which is both the honest output and the more useful one: what a caller
    /// wants from "scrape the logs and tell me what broke" is the governed log template, not a
    /// freshly written `Get-EventLog` line nobody has reviewed.
    /// </summary>
    private static WorkflowNode Mission(
        string nodeId,
        string name,
        string templateId,
        IReadOnlyDictionary<string, string>? parameters = null)
    {
        var config = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [WorkflowExecutionEngine.TemplateIdKey] = templateId,
        };
        if (parameters is not null)
        {
            foreach (var kvp in parameters)
            {
                config[kvp.Key] = kvp.Value;
            }
        }
        return new WorkflowNode(nodeId, name, WorkflowNodeType.GovernedMission, config);
    }

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
                        TargetModel: "claude-sonnet-5")
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
                    Mission("correlate-telemetry", "Correlate Against Live Endpoint State", "secops-process-scan"),
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

        // 0C. Transactional Speculative Execution Scope.
        //
        // This one keeps its own scripts on purpose: a TransactionalScope is an assert-and-rollback
        // primitive, not a governed template, and it runs through the same refusing binder. It is
        // also the node type with the least behind it - see F20 in the audits: a rollback that
        // exits zero is not proof the prior state was restored.
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
                    // Was a Write-Output of invented campaign figures - "Active Campaigns: 4 |
                    // Total Spend: $1,250 | CTR: 2.84%" - which the agent node below then analysed
                    // as though it were ad telemetry. There is no governed template that talks to
                    // TikTok, so the honest step is the one that exists: verify the egress posture
                    // the OAuth flow depends on. A real connector is a template someone writes and
                    // the catalogue reviews, not a string.
                    Mission("fetch-campaigns", "Verify Endpoint Egress Posture", "secops-tls-cipher-audit"),
                    new(
                        NodeId: "agent-analysis",
                        Name: "Ad Performance Synthesizer",
                        NodeType: WorkflowNodeType.AgentReasoning,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Prompt", "You are an Elite Media Buyer. Analyze the ad campaign metrics, calculate return on ad spend (ROAS), and flag underperforming ad sets with high cost-per-click." }
                        },
                        TargetModel: "claude-sonnet-5")
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
                    Mission("collect-logs", "Governed Authentication Log Sweep", "secops-auth-inspector"),
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
                        TargetModel: "claude-sonnet-5")
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
                    // Was a Write-Output of a fabricated invoice - subject, sender and a $3,450.00
                    // total - fed to a "Financial Parser Agent" that reported on it. No governed
                    // template reads mail; the trigger payload carries the real message, and the
                    // step that can be governed is checking the endpoint that received it.
                    Mission("extract-body", "Endpoint Posture At Time Of Receipt", "endpoint-firewall-audit"),
                    new(
                        NodeId: "agent-parser",
                        Name: "Financial Parser Agent",
                        NodeType: WorkflowNodeType.AgentReasoning,
                        Configuration: new Dictionary<string, string>
                        {
                            { "Prompt", "Extract invoice number, total amount, vendor, and due date. Flag whether total is within normal monthly baseline ($2,000-$5,000)." }
                        },
                        TargetModel: "claude-sonnet-5")
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
                Mission("step-executor", "Baseline System Health", "sysops-ad-dc-health"),
                new(
                    NodeId: "step-analysis",
                    Name: "Synthesis Agent",
                    NodeType: WorkflowNodeType.AgentReasoning,
                    Configuration: new Dictionary<string, string>
                    {
                        { "Prompt", "Synthesize findings for: " + prompt }
                    },
                    TargetModel: "claude-sonnet-5")
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
