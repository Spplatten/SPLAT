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

    private const string ProbeTemplate = "test-probe";

    /// <summary>A webhook trigger feeding one governed mission - the smallest real workflow.</summary>
    private static WorkflowGraph SingleMissionGraph(
        string workflowId = "flow-under-test",
        params (string Key, string Value)[] parameters) =>
        new(
            WorkflowId: workflowId,
            Name: "Workflow Under Test",
            Description: "Single governed mission node.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Webhook),
            Nodes: new List<WorkflowNode>
            {
                new("trigger", "Inbound", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
                WorkflowMissionDoubles.MissionNode("probe", "Probe", ProbeTemplate, parameters)
            },
            Edges: new List<WorkflowEdge> { new("trigger", "probe") });

    private static WorkflowExecutionEngine Engine(
        RecordingMissionEngine missions,
        IAuditLedger? ledger = null,
        params string[] templateIds) =>
        new(
            auditLedger: ledger,
            missionEngine: missions,
            templateRegistry: new StubTemplateRegistry(
                templateIds.Length > 0 ? templateIds : new[] { ProbeTemplate }));

    [Fact]
    public async Task TheExecutionIdOnTheResult_IsTheIdWrittenToTheLedger()
    {
        var ledger = new RecordingAuditLedger();
        var engine = Engine(new RecordingMissionEngine(), ledger);

        var result = await engine.ExecuteAsync(
            SingleMissionGraph(),
            new Dictionary<string, string>(),
            "operator");

        Assert.True(result.Success, result.FailureReason);

        // A result that cannot be joined to its own audit records is not evidence of anything.
        Assert.NotEmpty(ledger.Entries);
        Assert.All(ledger.Entries, e => Assert.Equal(result.ExecutionId, e.MissionId));
    }

    [Fact]
    public async Task AMissionNode_RunsThroughTheMissionEngine_NotTheWorkflowsOwnLauncher()
    {
        // The load-bearing assertion of the whole rewrite. A workflow step that reports success
        // without reaching the mission engine has skipped the jail, the argument binder, the DLP
        // pass and the ledger row - which is what the old SandboxedScript node did while sitting in
        // a graph the operator was told was governed. So the test reads the delegation directly
        // rather than believing the run's report of itself.
        var missions = new RecordingMissionEngine("PROBE OUTPUT");
        var launcher = new ScriptedProcessLauncher();
        var engine = new WorkflowExecutionEngine(
            processLauncher: launcher,
            sandboxFactory: () => new FakeJobSandbox(),
            missionEngine: missions,
            templateRegistry: new StubTemplateRegistry(ProbeTemplate));

        var result = await engine.ExecuteAsync(
            SingleMissionGraph(),
            new Dictionary<string, string>(),
            "operator");

        Assert.True(result.Success, result.FailureReason);
        var invocation = Assert.Single(missions.Invocations);
        Assert.Equal(ProbeTemplate, invocation.TemplateId);
        Assert.Equal("operator", invocation.OperatorIdentity);
        Assert.Contains("PROBE OUTPUT", result.NodeOutputs["probe"]);

        // A launcher was wired and must have stayed idle: no second execution tier.
        Assert.Empty(launcher.Arguments);
    }

    [Fact]
    public async Task AMissionThatNeverCompletes_FailsTheWorkflow()
    {
        // The mission engine reports a failed exit contract, a timeout or a rejected analysis by
        // ending its stream without a Completed chunk. Treating that as success would hand the
        // partial output downstream as though it were a finished measurement.
        var ledger = new RecordingAuditLedger();
        var engine = Engine(RecordingMissionEngine.NeverCompletes("PARTIAL"), ledger);

        var result = await engine.ExecuteAsync(
            SingleMissionGraph(),
            new Dictionary<string, string>(),
            "operator");

        Assert.False(result.Success);
        Assert.Contains("did not complete", result.FailureReason);
        Assert.Contains(ledger.Entries, e => e.Action == "WORKFLOW_FAILED");
    }

    [Fact]
    public async Task AMissionNamingATemplateTheCatalogueDoesNotHave_IsRefused()
    {
        // Not synthesised, not defaulted. A template absent from the catalogue has no reviewed
        // policy behind it, so there is nothing for the mission engine to enforce.
        var missions = new RecordingMissionEngine();
        var engine = new WorkflowExecutionEngine(
            missionEngine: missions,
            templateRegistry: new StubTemplateRegistry(ProbeTemplate));

        var graph = new WorkflowGraph(
            WorkflowId: "flow-unknown-template",
            Name: "Unknown Template",
            Description: "Names something the catalogue never reviewed.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                WorkflowMissionDoubles.MissionNode("probe", "Probe", "not-in-the-catalogue")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.False(result.Success);
        Assert.Contains("not in the governed catalogue", result.FailureReason);
        Assert.Empty(missions.Invocations);
    }

    [Fact]
    public async Task ASandboxedScriptNode_IsRefusedRatherThanRun()
    {
        // The old node type is kept in the enum so a stored graph deserialises and says why it
        // stopped, rather than throwing an enum error the operator cannot act on. What it must
        // never do again is launch anything - including under allowSimulatedExecution, which is
        // wired here precisely so the refusal cannot be an artefact of a missing launcher.
        var launcher = new ScriptedProcessLauncher();
        var engine = new WorkflowExecutionEngine(
            processLauncher: launcher,
            sandboxFactory: () => new FakeJobSandbox(),
            allowSimulatedExecution: true,
            missionEngine: new RecordingMissionEngine(),
            templateRegistry: new StubTemplateRegistry(ProbeTemplate));

        var graph = new WorkflowGraph(
            WorkflowId: "flow-legacy-script",
            Name: "Legacy Script",
            Description: "A graph saved before the mission rewrite.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                new("script", "Script", WorkflowNodeType.SandboxedScript, new Dictionary<string, string>(),
                    ScriptCommand: "Write-Output 'hello'")
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.False(result.Success);
        Assert.Contains("no longer run", result.FailureReason);
        Assert.Empty(launcher.Arguments);
    }

    [Fact]
    public async Task ARolledBackTransaction_IsReportedAsAFailedRun()
    {
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

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

    /// <summary>
    /// Runs the real binder over whatever the workflow handed down, exactly as a mission does, so
    /// the refusal under test is the shipped policy rather than a restatement of it.
    /// </summary>
    private static RecordingMissionEngine BindingMissionEngine() =>
        new((templateId, parameters) =>
        {
            var baseTemplate = WorkflowMissionDoubles.Template(templateId);
            var template = baseTemplate with
            {
                Tool = baseTemplate.Tool with
                {
                    ArgumentsTemplate = "-Command \"Write-Output 'received: {payload}'\""
                }
            };
            MissionController.Core.GovernedArgumentBinder.Bind(template, parameters);
            return RecordingMissionEngine.Emit("bound", complete: true);
        });

    [Fact]
    public async Task AWebhookPayloadCarryingShellMetacharacters_IsRefusedNotExecuted()
    {
        var launcher = new ScriptedProcessLauncher();
        var engine = new WorkflowExecutionEngine(
            processLauncher: launcher,
            sandboxFactory: () => new FakeJobSandbox(),
            missionEngine: BindingMissionEngine(),
            templateRegistry: new StubTemplateRegistry(ProbeTemplate));

        // The workflow passes the payload field down as a mission PARAMETER and never builds a
        // command from it; the refusal comes from the binder inside the mission, which is where
        // the boundary now lives.
        var result = await engine.ExecuteAsync(
            SingleMissionGraph(parameters: ("payload", "{trigger.field}")),
            new Dictionary<string, string> { { "field", "x'; Start-Process calc.exe; '" } },
            "anonymous-webhook");

        Assert.False(result.Success);
        Assert.Contains("refused by the governed argument binder", result.FailureReason);

        // The refusal names the parameter and not its value on purpose: echoing attacker text into
        // an audit trail an operator reads is its own injection surface.
        Assert.DoesNotContain("calc.exe", result.FailureReason);
        Assert.Empty(launcher.Arguments);
    }

    [Fact]
    public async Task ASecondOrderPlaceholderInsideAValue_IsNotReExpanded()
    {
        var missions = new RecordingMissionEngine();
        var engine = Engine(missions);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-second-order",
            Name: "Second Order",
            Description: "A configuration value that itself names another placeholder.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                WorkflowMissionDoubles.MissionNode("probe", "Probe", ProbeTemplate,
                    ("Outer", "{Inner}"), ("Inner", "payload"))
            },
            Edges: new List<WorkflowEdge>());

        var result = await engine.ExecuteAsync(graph, new Dictionary<string, string>(), "operator");

        Assert.True(result.Success, result.FailureReason);

        // One pass over the author's value: {Outer} resolves to the literal "{Inner}" and stops.
        // A second pass would let a node output name a placeholder and have it expanded, which is
        // the second-order injection the single-pass substitution exists to prevent.
        Assert.Equal("{Inner}", Assert.Single(missions.Invocations).Parameters["Outer"]);
    }

    [Fact]
    public async Task AnAlphanumericPayloadInAQuotedLiteral_StillBinds()
    {
        // The control for the refusal above, through the identical path. Without it a binder that
        // refused everything would pass that test - and a refusal that cannot succeed is a broken
        // feature, not a guarantee.
        var missions = BindingMissionEngine();
        var engine = new WorkflowExecutionEngine(
            missionEngine: missions,
            templateRegistry: new StubTemplateRegistry(ProbeTemplate));

        var result = await engine.ExecuteAsync(
            SingleMissionGraph(parameters: ("payload", "{trigger.field}")),
            new Dictionary<string, string> { { "field", "api.internal.example.com" } },
            "anonymous-webhook");

        Assert.True(result.Success, result.FailureReason);
        Assert.Contains("api.internal.example.com", Assert.Single(missions.Invocations).Parameters["payload"]);
    }

    [Fact]
    public async Task AConditionScopedToAField_IgnoresEveryOtherNodesOutput()
    {
        var engine = Engine(new RecordingMissionEngine("all clear"));

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
                WorkflowMissionDoubles.MissionNode("probe", "Probe", ProbeTemplate),
                new("gate", "Escalation Gate", WorkflowNodeType.Condition,
                    new Dictionary<string, string> { { "Field", "probe" }, { "Matches", "CriticalAlarm" } }),
                WorkflowMissionDoubles.MissionNode("escalate", "Escalate", ProbeTemplate)
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
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

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
        var missions = new RecordingMissionEngine("all clear");
        var engine = Engine(missions);

        var graph = new WorkflowGraph(
            WorkflowId: "flow-transitive-skip",
            Name: "Transitive Skip",
            Description: "The whole inactive branch must stay dark, not just its first node.",
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: new List<WorkflowNode>
            {
                WorkflowMissionDoubles.MissionNode("probe", "Probe", ProbeTemplate),
                new("gate", "Gate", WorkflowNodeType.Condition,
                    new Dictionary<string, string> { { "Field", "probe" }, { "Matches", "CriticalAlarm" } }),
                WorkflowMissionDoubles.MissionNode("page", "Page SecOps", ProbeTemplate),
                WorkflowMissionDoubles.MissionNode("remediate", "Restart Service", ProbeTemplate)
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

        // A skipped node must not have reached the substrate either. Asserting only the absence of
        // an OUTPUT would pass even if the mission ran and its result was discarded.
        Assert.Equal(new[] { ProbeTemplate }, missions.Invocations.Select(i => i.TemplateId));
    }

    [Fact]
    public async Task TheOAuthNode_RefusesRatherThanVaultingAFabricatedToken()
    {
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

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
        var engine = new WorkflowExecutionEngine(allowSimulatedExecution: true);

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
    public async Task EverySynthesizedMissionNode_NamesATemplateTheCatalogueActuallyHas()
    {
        // The synthesiser composes catalogue templates by id, and a mistyped id is a workflow that
        // synthesises cleanly, saves cleanly, and refuses the moment an operator runs it. The
        // shipped catalogue is the authority, so it is what the ids are checked against.
        var catalogue = new HashSet<string>(
            MissionController.Infrastructure.Data.Catalog.GovernedTemplateCatalog.All.Select(t => t.TemplateId),
            StringComparer.OrdinalIgnoreCase);

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

            foreach (var node in graph.Nodes.Where(n => n.NodeType == WorkflowNodeType.GovernedMission))
            {
                Assert.True(
                    node.Configuration.TryGetValue(WorkflowExecutionEngine.TemplateIdKey, out var templateId),
                    $"'{node.NodeId}' in '{graph.WorkflowId}' is a mission node with no template id");
                Assert.True(
                    catalogue.Contains(templateId!),
                    $"'{node.NodeId}' in '{graph.WorkflowId}' names '{templateId}', absent from the catalogue");
            }

            // A synthesised script node is one the rewrite missed: it would be refused at run time,
            // so it fails here instead, where the author can see it.
            Assert.DoesNotContain(graph.Nodes, n => n.NodeType == WorkflowNodeType.SandboxedScript);

            foreach (var node in graph.Nodes.Where(n => n.ScriptCommand is not null))
            {
                Assert.Equal(WorkflowNodeType.TransactionalScope, node.NodeType);
                var values = new Dictionary<string, string>(node.Configuration, StringComparer.OrdinalIgnoreCase);
                var bound = MissionController.Core.GovernedArgumentBinder.BindWorkflowCommand(node.ScriptCommand, values);
                Assert.NotNull(bound);
            }
        }
    }
}
