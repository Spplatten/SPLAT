using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.Workflow;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The workflow engine is the layer an unauthenticated webhook reaches first, and the layer whose
/// result an operator reads instead of the ledger. These cover the two properties that makes
/// depend on: a run reports what actually happened, and untrusted text never becomes a command.
/// </summary>
public class WorkflowGovernanceTests
{
    private sealed class RecordingAuditLedger : IAuditLedger
    {
        public readonly List<(Guid MissionId, string Action, string Details)> Entries = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details,
            string operatorIdentity, CancellationToken cancellationToken = default)
        {
            lock (Entries) Entries.Add((missionId, action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private sealed class FakeJobSandbox : IJobSandbox
    {
        public string JobName => "workflow-fake-job";
        public void ConfigureExtendedLimits(long maxMemoryBytes, int maxCpuPercent) { }
        public void AssignProcess(IntPtr processHandle) { }
        public JobResourceMetrics GetResourceMetrics() => new(0, 0, 0, 0, 0);
        public void TerminateAllProcesses(uint exitCode = 1) { }
        public void Dispose() { }
    }

    /// <summary>Returns a fixed exit code, and records every command line it was handed.</summary>
    private sealed class ScriptedProcessLauncher : IProcessLauncher
    {
        private readonly int _exitCode;
        private readonly bool _timedOut;

        public readonly List<string> Arguments = new();

        public ScriptedProcessLauncher(int exitCode = 0, bool timedOut = false)
        {
            _exitCode = exitCode;
            _timedOut = timedOut;
        }

        public Task<ProcessExecutionResult> LaunchSuspendedInJobAsync(
            string executable, string arguments, string workingDirectory, IJobSandbox jobSandbox,
            bool dropAdminPrivileges, int timeoutSeconds,
            IProgress<string>? stdoutProgress = null, IProgress<string>? stderrProgress = null,
            CancellationToken cancellationToken = default, bool denyNetworkAccess = false)
        {
            lock (Arguments) Arguments.Add(arguments);
            return Task.FromResult(new ProcessExecutionResult(
                _exitCode,
                _exitCode == 0 ? "ok" : string.Empty,
                _exitCode == 0 ? string.Empty : "the tool refused to run",
                _timedOut,
                new JobResourceMetrics(1, 10, 10, 1024, 2048)));
        }
    }

    private static WorkflowGraph SingleScriptGraph(string scriptCommand, string workflowId = "flow-under-test") =>
        new(
            WorkflowId: workflowId,
            Name: "Workflow Under Test",
            Description: "Single sandboxed script node.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Webhook),
            Nodes: new List<WorkflowNode>
            {
                new("trigger", "Inbound", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                new("script", "Script", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: scriptCommand)
            },
            Edges: new List<WorkflowEdge> { new("trigger", "script") });

    [Fact]
    public async Task TheExecutionIdOnTheResult_IsTheIdWrittenToTheLedger()
    {
        var ledger = new RecordingAuditLedger();
        var engine = new WorkflowExecutionEngine(auditLedger: ledger);

        var result = await engine.ExecuteAsync(
            SingleScriptGraph("Write-Output 'hello'"),
            new Dictionary<string, string>(),
            "operator");

        Assert.True(result.Success, result.FailureReason);

        // A result that cannot be joined to its own audit records is not evidence of anything.
        Assert.NotEmpty(ledger.Entries);
        Assert.All(ledger.Entries, e => Assert.Equal(result.ExecutionId, e.MissionId));
    }

    [Fact]
    public async Task AScriptNodeThatExitsNonZero_FailsTheWorkflow()
    {
        var ledger = new RecordingAuditLedger();
        var engine = new WorkflowExecutionEngine(
            processLauncher: new ScriptedProcessLauncher(exitCode: 3),
            sandboxFactory: () => new FakeJobSandbox(),
            auditLedger: ledger);

        var result = await engine.ExecuteAsync(
            SingleScriptGraph("Write-Output 'hello'"),
            new Dictionary<string, string>(),
            "operator");

        Assert.False(result.Success);
        Assert.Contains("exited 3", result.FailureReason);
        Assert.Contains(ledger.Entries, e => e.Action == "WORKFLOW_FAILED");
    }

    [Fact]
    public async Task AScriptNodeThatTimesOut_FailsTheWorkflow()
    {
        var engine = new WorkflowExecutionEngine(
            processLauncher: new ScriptedProcessLauncher(exitCode: 0, timedOut: true),
            sandboxFactory: () => new FakeJobSandbox());

        var result = await engine.ExecuteAsync(
            SingleScriptGraph("Write-Output 'hello'"),
            new Dictionary<string, string>(),
            "operator");

        Assert.False(result.Success);
        Assert.Contains("budget", result.FailureReason);
    }

    [Fact]
    public async Task ARolledBackTransaction_IsReportedAsAFailedRun()
    {
        var engine = new WorkflowExecutionEngine();

        var graph = new WorkflowGraph(
            WorkflowId: "flow-tx-honesty",
            Name: "Rollback Honesty",
            Description: "A scope whose assertion cannot hold.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("tx", "Speculative Change", WorkflowNodeType.TransactionalScope,
                    new Dictionary<string, string>
                    {
                        { "Assertion", "VERIFIED" },
                        { "RollbackScript", "Write-Output 'RESTORED'" }
                    },
                    ScriptCommand: "Write-Output 'STATUS: FAILED_CHECKS'")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.False(result.Success);
        Assert.Contains("VERIFIED", result.FailureReason);

        // The failing node's evidence survives the abort, because that is what gets diagnosed.
        Assert.Contains("[TRANSACTION_ROLLED_BACK]", result.NodeOutputs["tx"]);
    }

    [Fact]
    public async Task AWebhookPayloadCarryingShellMetacharacters_IsRefusedNotExecuted()
    {
        var launcher = new ScriptedProcessLauncher();
        var engine = new WorkflowExecutionEngine(
            processLauncher: launcher,
            sandboxFactory: () => new FakeJobSandbox());

        // The trigger node turns the payload into "field=value" lines, and the script node used to
        // splice those straight into powershell.exe -Command.
        var result = await engine.ExecuteAsync(
            SingleScriptGraph("Write-Output 'received: {trigger}'"),
            new Dictionary<string, string> { { "field", "x'; Start-Process calc.exe; '" } },
            "anonymous-webhook");

        Assert.False(result.Success);
        Assert.Contains("refused by the governed argument binder", result.FailureReason);
        Assert.DoesNotContain(launcher.Arguments, a => a.Contains("calc.exe"));
    }

    [Fact]
    public async Task ASecondOrderPlaceholderInsideAValue_IsNotReExpanded()
    {
        var launcher = new ScriptedProcessLauncher();
        var engine = new WorkflowExecutionEngine(
            processLauncher: launcher,
            sandboxFactory: () => new FakeJobSandbox());

        var graph = new WorkflowGraph(
            WorkflowId: "flow-second-order",
            Name: "Second Order",
            Description: "A configuration value that itself names another placeholder.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("script", "Script", WorkflowNodeType.SandboxedScript,
                    new Dictionary<string, string> { { "Outer", "{Inner}" }, { "Inner", "payload" } },
                    ScriptCommand: "Write-Output '{Outer}'")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(result.Success, result.FailureReason);

        // One pass over the author's template: {Outer} resolves to the literal "{Inner}" and stops.
        string commandLine = Assert.Single(launcher.Arguments);
        Assert.Contains("{Inner}", commandLine);
        Assert.DoesNotContain("payload", commandLine);
    }

    [Fact]
    public async Task AnAlphanumericPayloadInAQuotedLiteral_StillBinds()
    {
        var launcher = new ScriptedProcessLauncher();
        var engine = new WorkflowExecutionEngine(
            processLauncher: launcher,
            sandboxFactory: () => new FakeJobSandbox());

        var graph = new WorkflowGraph(
            WorkflowId: "flow-legitimate-binding",
            Name: "Legitimate Binding",
            Description: "The guard must not cost the product its ordinary case.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("script", "Script", WorkflowNodeType.SandboxedScript,
                    new Dictionary<string, string> { { "Host", "api.internal.example.com" } },
                    ScriptCommand: "Test-Connection -TargetName '{Host}'")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(result.Success, result.FailureReason);
        Assert.Contains(launcher.Arguments, a => a.Contains("api.internal.example.com"));
    }

    [Fact]
    public async Task AConditionScopedToAField_IgnoresEveryOtherNodesOutput()
    {
        var engine = new WorkflowExecutionEngine();

        // 'probe' is the field under test and reports healthy. The trigger payload - which an
        // unauthenticated caller controls - carries the alarm text the gate looks for.
        var graph = new WorkflowGraph(
            WorkflowId: "flow-scoped-condition",
            Name: "Scoped Condition",
            Description: "Only the named field may satisfy the gate.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Webhook),
            Nodes: new List<WorkflowNode>
            {
                new("trigger", "Inbound", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                new("probe", "Probe", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'all clear'"),
                new("gate", "Escalation Gate", WorkflowNodeType.Condition,
                    new Dictionary<string, string> { { "Field", "probe" }, { "Matches", "CriticalAlarm" } }),
                new("escalate", "Escalate", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'paging secops'")
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger", "probe"),
                new("probe", "gate"),
                new("gate", "escalate", ConditionBranch: "true")
            });

        var result = await engine.ExecuteAsync(
            graph,
            new Dictionary<string, string> { { "status", "CriticalAlarm" } },
            "anonymous-webhook");

        Assert.True(result.Success, result.FailureReason);
        Assert.Equal("false", result.NodeOutputs["gate"]);
        Assert.DoesNotContain("escalate", result.NodeOutputs.Keys);
    }

    [Fact]
    public async Task AConditionWithNoMatchPattern_IsRefused()
    {
        var engine = new WorkflowExecutionEngine();

        var graph = new WorkflowGraph(
            WorkflowId: "flow-empty-condition",
            Name: "Empty Condition",
            Description: "A gate with nothing to test.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("gate", "Gate", WorkflowNodeType.Condition, new Dictionary<string, string>())
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.False(result.Success);
        Assert.Contains("no 'Matches' pattern", result.FailureReason);
    }

    [Fact]
    public async Task ADescendantOfASkippedNode_IsSkippedToo()
    {
        var engine = new WorkflowExecutionEngine();

        var graph = new WorkflowGraph(
            WorkflowId: "flow-transitive-skip",
            Name: "Transitive Skip",
            Description: "The whole inactive branch must stay dark, not just its first node.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("probe", "Probe", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'all clear'"),
                new("gate", "Gate", WorkflowNodeType.Condition,
                    new Dictionary<string, string> { { "Field", "probe" }, { "Matches", "CriticalAlarm" } }),
                new("page", "Page SecOps", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'paging'"),
                new("remediate", "Restart Service", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'restarting'")
            },
            Edges: new List<WorkflowEdge>
            {
                new("probe", "gate"),
                new("gate", "page", ConditionBranch: "true"),
                new("page", "remediate")   // unconditional edge off a conditionally-skipped node
            });

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(result.Success, result.FailureReason);
        Assert.DoesNotContain("page", result.NodeOutputs.Keys);
        Assert.DoesNotContain("remediate", result.NodeOutputs.Keys);
    }

    [Fact]
    public async Task TheOAuthNode_RefusesRatherThanVaultingAFabricatedToken()
    {
        var engine = new WorkflowExecutionEngine();

        var graph = new WorkflowGraph(
            WorkflowId: "flow-oauth-honesty",
            Name: "OAuth Honesty",
            Description: "No token endpoint is wired, so no token may be produced.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.OAuthCallback),
            Nodes: new List<WorkflowNode>
            {
                new("exchange", "Exchange", WorkflowNodeType.OAuthExchange,
                    new Dictionary<string, string> { { "Provider", "TikTok" } })
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(
            graph,
            new Dictionary<string, string> { { "code", "auth_code_123" } },
            "operator");

        Assert.False(result.Success);
        Assert.Contains("not implemented", result.FailureReason);
    }

    [Fact]
    public async Task TheGovernedHttpNode_SaysItSentNothing()
    {
        var engine = new WorkflowExecutionEngine();

        var graph = new WorkflowGraph(
            WorkflowId: "flow-http-honesty",
            Name: "HTTP Honesty",
            Description: "No pinned client is wired, so the node must not claim a send.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("post", "Post Event", WorkflowNodeType.GovernedHttp, new Dictionary<string, string>(),
                    AllowedEgressFqdn: "api.example.com")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(result.Success, result.FailureReason);
        Assert.Contains("NOT_IMPLEMENTED", result.NodeOutputs["post"]);
        Assert.DoesNotContain("sent successfully", result.NodeOutputs["post"]);
    }

    [Fact]
    public async Task EverySynthesizedTemplate_BindsWithoutRefusal()
    {
        // The shipped templates are the first thing an operator runs. A template that the governed
        // binder refuses is a template that cannot execute, and that must fail here, not in the UI.
        var synthesizer = new WorkflowSynthesizerEngine();
        string[] prompts =
        {
            "Run an autonomous agent to investigate network latency with react tools",
            "Recall memory of past incidents and store new correlation knowledge",
            "Perform safe update with transactional rollback if failed",
            "Scrape system logs for error spikes and alert SecOps",
            "Ingest email invoice and parse total amount",
            "Reconcile the ledger; drop \"quotes\" and `backticks` into the prompt"
        };

        foreach (var prompt in prompts)
        {
            var graph = await synthesizer.SynthesizeFromNaturalLanguageAsync(prompt);

            foreach (var node in graph.Nodes.Where(n => n.ScriptCommand is not null))
            {
                var values = new Dictionary<string, string>(node.Configuration, StringComparer.OrdinalIgnoreCase);
                var bound = MissionController.Core.GovernedArgumentBinder.BindWorkflowCommand(node.ScriptCommand, values);
                Assert.NotNull(bound);
            }
        }
    }
}
