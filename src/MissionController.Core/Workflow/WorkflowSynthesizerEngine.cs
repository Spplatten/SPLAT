using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core.Workflow;

/// <summary>
/// Compiles an operator's sentence into a governed plan, using a model, grounded in the catalogue
/// that ships, and refusing anything it cannot resolve.
///
/// What this replaced was an illusion, and worth naming because it is the failure mode this whole
/// class now guards: it took an <see cref="IModelStreamClient"/> in its constructor and never called
/// it. Synthesis was <c>prompt.ToLowerInvariant().Contains("tiktok")</c> over five hardcoded graphs,
/// and anything that matched none of the five - which is nearly every real sentence - fell through to
/// a "General Default Workflow" that ran an Active Directory health check and told the operator it
/// had understood them. "Run the disk audit, and keep going if it fails" produced the same plan as
/// "reconcile the ledger". The page said synthesised; nothing had been read.
///
/// The contract now:
///
///   1. The model is asked, always. There is no keyword path.
///   2. It is grounded: the system prompt carries the governed catalogue and the named recipes, and
///      the model may only choose from what is in front of it.
///   3. Its answer is untrusted input. Every template id is checked against the catalogue before any
///      of it becomes a graph, and an id the catalogue does not have throws here rather than
///      reaching <see cref="ProjectExecutionEngine"/> and failing in front of the operator.
///   4. With no model configured, synthesis refuses. A plan nobody read is worse than no plan: the
///      operator would have to notice by themselves that the stages had nothing to do with what they
///      asked for.
/// </summary>
public sealed class WorkflowSynthesizerEngine : IWorkflowSynthesizer
{
    /// <summary>
    /// The most stages a synthesised plan may have. Project Studio's own rule - a finite ordered
    /// playbook, not a swarm - and the model is told it, but a model that ignores it is exactly the
    /// case this constant exists for.
    /// </summary>
    public const int MaxStages = 6;

    private const string DefaultModelId = "claude-sonnet-5";

    private static readonly Regex JsonFencedBlock = new(
        @"```(?:json)?\s*([\s\S]*?)```",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly IModelStreamClient? _modelClient;
    private readonly IReadOnlyList<SingleToolTemplate> _catalog;
    private readonly string _modelId;

    public WorkflowSynthesizerEngine(
        IModelStreamClient? modelClient = null,
        IReadOnlyList<SingleToolTemplate>? catalog = null,
        string modelId = DefaultModelId)
    {
        _modelClient = modelClient;
        _catalog = catalog ?? Array.Empty<SingleToolTemplate>();
        _modelId = string.IsNullOrWhiteSpace(modelId) ? DefaultModelId : modelId;
    }

    /// <summary>
    /// The workflow rendering: a trigger and the compiled stages as governed mission nodes, or one of
    /// the named recipes when the model chose one.
    /// </summary>
    public async Task<WorkflowGraph> SynthesizeFromNaturalLanguageAsync(
        string prompt,
        CancellationToken cancellationToken = default)
    {
        var plan = await CompileAsync(prompt, cancellationToken);
        if (plan.RecipeId is not null)
        {
            return Recipes[plan.RecipeId].Build(prompt);
        }

        var nodes = new List<WorkflowNode>
        {
            new("trigger-manual", "Manual Operator Start", WorkflowNodeType.Trigger, new Dictionary<string, string>()),
        };
        var edges = new List<WorkflowEdge>();
        string previous = "trigger-manual";

        foreach (var stage in plan.Stages)
        {
            var configuration = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [WorkflowExecutionEngine.TemplateIdKey] = stage.TemplateId,
                [WorkflowExecutionEngine.DirectiveKey] = stage.Directive,
            };

            // Written only when true. The key is reserved either way, but a graph that carries the
            // flag on every node says nothing about which stage the operator actually asked to
            // survive a failure.
            if (stage.ContinueOnFailure)
            {
                configuration[WorkflowExecutionEngine.ContinueOnFailureKey] = "true";
            }

            nodes.Add(new WorkflowNode(stage.StageId, stage.Name, WorkflowNodeType.GovernedMission, configuration));
            edges.Add(new WorkflowEdge(previous, stage.StageId));
            previous = stage.StageId;
        }

        var graph = new WorkflowGraph(
            WorkflowId: plan.WorkflowId,
            Name: plan.Name,
            Description: plan.Description,
            Trigger: new WorkflowTriggerConfig(WorkflowTriggerType.Manual),
            Nodes: nodes,
            Edges: edges);

        graph.Validate();
        return graph;
    }

    /// <summary>
    /// The Project Studio rendering. The stencil the model fills in is <see cref="ProjectStage"/>
    /// itself - stage id, the template that runs it, the directive, and whether the project carries
    /// on when it fails - so "keep going if the disk check fails" lands on the boolean the execution
    /// engine already reads, rather than on a checkbox the operator has to find and tick.
    /// </summary>
    public async Task<ProjectTemplate> SynthesizeProjectAsync(
        string prompt,
        CancellationToken cancellationToken = default)
    {
        var plan = await CompileAsync(prompt, cancellationToken);
        var stages = plan.RecipeId is null
            ? plan.Stages.Select(s => new ProjectStage(s.StageId, s.Name, s.TemplateId, s.Directive, s.ContinueOnFailure)).ToList()
            : StagesOfRecipe(Recipes[plan.RecipeId].Build(prompt));

        var project = new ProjectTemplate(
            ProjectId: plan.WorkflowId.StartsWith("flow-", StringComparison.Ordinal)
                ? "project-" + plan.WorkflowId[5..]
                : "project-" + plan.WorkflowId,
            Name: plan.Name,
            Description: plan.Description,
            Category: "Synthesized Workflows",
            Stages: stages,
            Deliverables: new[]
            {
                "Complete sandboxed execution of " + plan.Name,
                "Notarized execution in the SHA-256 chained audit ledger",
            });

        project.Validate();
        return project;
    }

    /// <summary>
    /// A recipe's mission nodes as project stages. Its other node types - OAuth exchange, memory
    /// recall, a ReAct agent - have no <see cref="ProjectStage"/> to become, so they are dropped
    /// rather than flattened into stages that would run something else entirely. A recipe whose
    /// missions are all dropped leaves no project, which <see cref="ProjectTemplate.Validate"/>
    /// refuses; that refusal is correct and is the reason a recipe is offered to the workflow page
    /// rather than to this one.
    /// </summary>
    private static List<ProjectStage> StagesOfRecipe(WorkflowGraph graph) =>
        graph.Nodes
            .Where(n => n.NodeType == WorkflowNodeType.GovernedMission)
            .Select((n, index) => new ProjectStage(
                n.NodeId,
                $"Stage {index + 1}: {n.Name}",
                n.Configuration[WorkflowExecutionEngine.TemplateIdKey],
                n.Configuration.TryGetValue(WorkflowExecutionEngine.DirectiveKey, out var directive)
                    ? directive
                    : $"Run {n.Name} and report only what the sensor observed.",
                ContinueOnFailure: false))
            .ToList();

    /// <summary>
    /// One model call, one validation, both renderings. Nothing here trusts the answer: the JSON is
    /// parsed defensively, every id is resolved against the catalogue, and anything unresolvable
    /// throws with the reason an operator can act on.
    /// </summary>
    private async Task<SynthesizedPlan> CompileAsync(string prompt, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(prompt))
        {
            throw new ArgumentException("Prompt must not be empty.", nameof(prompt));
        }

        if (_modelClient is null)
        {
            throw new InvalidOperationException(
                "Workflow synthesis needs a connected model: it compiles your sentence into governed " +
                "stages rather than matching keywords. Connect an API key in Settings, or build the " +
                "project stage by stage.");
        }

        if (_catalog.Count == 0)
        {
            throw new InvalidOperationException(
                "Workflow synthesis has no governed catalogue to compile against. A plan naming " +
                "templates that were never loaded would refuse the moment it ran.");
        }

        var response = new StringBuilder();
        await foreach (var token in _modelClient.StreamAnalysisAsync(
            _modelId, SystemPrompt(_catalog), prompt, cancellationToken))
        {
            response.Append(token);
        }

        var plan = Parse(response.ToString(), prompt);
        if (plan.RecipeId is null)
        {
            ValidateAgainstCatalog(plan.Stages);
        }

        return plan;
    }

    private static string SystemPrompt(IReadOnlyList<SingleToolTemplate> catalog)
    {
        var templates = new StringBuilder();
        foreach (var template in catalog)
        {
            templates.Append("- ").Append(template.TemplateId)
                .Append(" | ").Append(template.Name)
                .Append(" | ").Append(template.Category)
                .Append(" | ").Append(Single(template.Description))
                .Append('\n');
        }

        var recipes = new StringBuilder();
        foreach (var (id, recipe) in Recipes)
        {
            recipes.Append("- ").Append(id).Append(" | ").Append(recipe.Description).Append('\n');
        }

        return $$"""
You compile an operator's request into a governed plan for SPLAT. You do not write scripts, invent
tools, or describe what a tool would find. You choose from what exists and put it in order.

[GOVERNED TEMPLATES - the only things that can run. id | name | category | what it does]
{{templates}}
[PREBUILT RECIPES - whole workflows that already exist, for requests that match one closely]
{{recipes}}
Answer with one JSON object and nothing else.

To use a recipe:
{"recipeId": "flow-log-audit-alert"}

Otherwise compile the request into ordered stages:
{
  "workflowId": "flow-short-kebab-case-name",
  "name": "Short title an operator would recognise",
  "description": "One sentence on what this plan does.",
  "stages": [
    {
      "stageId": "stage-1",
      "name": "Stage 1: what this step is",
      "templateId": "an exact id from the list above",
      "directive": "What this stage must report, in one or two sentences addressed to the agent.",
      "continueOnFailure": false
    }
  ]
}

Rules, all enforced after you answer:
- templateId must be copied exactly from the list. An id that is not on the list is refused and the
  operator sees an error instead of a plan, so never approximate one.
- At most {{MaxStages}} stages, in the order they should run.
- continueOnFailure is true only when the request says the plan should carry on past that stage
  failing - "keep going", "continue even if", "don't stop on". It is false by default.
- directive describes what to report. It never contains a command, a script or a file path.
- Choose a recipe only when the request is plainly one of them; otherwise compile stages.
""";
    }

    private static string Single(string text) =>
        string.Join(" ", text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static SynthesizedPlan Parse(string rawResponse, string prompt)
    {
        var fenced = JsonFencedBlock.Match(rawResponse);
        string json = fenced.Success ? fenced.Groups[1].Value : rawResponse;

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(
                "The model did not answer with the JSON plan this compiler reads, so there is nothing " +
                $"to validate and nothing will be built from it: {ex.Message}");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidOperationException("The model's plan was not a JSON object.");
            }

            if (root.TryGetProperty("recipeId", out var recipeProperty) &&
                recipeProperty.ValueKind == JsonValueKind.String)
            {
                string recipeId = recipeProperty.GetString()!.Trim();
                if (!Recipes.ContainsKey(recipeId))
                {
                    throw new InvalidOperationException(
                        $"The model chose the recipe '{recipeId}', which does not exist. Known recipes: " +
                        string.Join(", ", Recipes.Keys) + ".");
                }

                return new SynthesizedPlan(recipeId, string.Empty, string.Empty, string.Empty, Array.Empty<PlannedStage>());
            }

            if (!root.TryGetProperty("stages", out var stagesProperty) ||
                stagesProperty.ValueKind != JsonValueKind.Array ||
                stagesProperty.GetArrayLength() == 0)
            {
                throw new InvalidOperationException(
                    "The model's plan named no stages and no recipe, so there is nothing to run.");
            }

            if (stagesProperty.GetArrayLength() > MaxStages)
            {
                throw new InvalidOperationException(
                    $"The model's plan has {stagesProperty.GetArrayLength()} stages; a project is a finite " +
                    $"ordered playbook of at most {MaxStages}.");
            }

            var stages = new List<PlannedStage>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int position = 0;
            foreach (var element in stagesProperty.EnumerateArray())
            {
                position++;
                stages.Add(ReadStage(element, position, seen));
            }

            return new SynthesizedPlan(
                RecipeId: null,
                WorkflowId: Identifier(root, "workflowId", "flow-synthesized-" + Guid.NewGuid().ToString("N")[..8]),
                Name: Text(root, "name", "Synthesized Governed Plan"),
                Description: Text(root, "description", Single(prompt)),
                Stages: stages);
        }
    }

    private static PlannedStage ReadStage(JsonElement element, int position, HashSet<string> seen)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException($"Stage {position} in the model's plan is not an object.");
        }

        string templateId = Text(element, "templateId", string.Empty).Trim();
        if (templateId.Length == 0)
        {
            throw new InvalidOperationException($"Stage {position} names no template.");
        }

        string stageId = Identifier(element, "stageId", "stage-" + position.ToString(CultureInfo.InvariantCulture));
        if (!seen.Add(stageId))
        {
            throw new InvalidOperationException(
                $"The model's plan uses the stage id '{stageId}' twice; a graph cannot hold two nodes with one id.");
        }

        string directive = Text(element, "directive", string.Empty).Trim();
        if (directive.Length == 0)
        {
            throw new InvalidOperationException(
                $"Stage {position} ('{stageId}') carries no directive, so the agent running it would be told nothing.");
        }

        bool continueOnFailure =
            element.TryGetProperty("continueOnFailure", out var flag) && flag.ValueKind == JsonValueKind.True;

        return new PlannedStage(
            stageId,
            Text(element, "name", $"Stage {position}"),
            templateId,
            Single(directive),
            continueOnFailure);
    }

    /// <summary>
    /// The boundary the blueprint calls fail-closed, and the reason this class takes the catalogue
    /// rather than a registry it could query later: a plan is either entirely runnable when it is
    /// returned, or it does not exist. A hallucinated id that reached the project registry would
    /// save cleanly, list cleanly, and refuse the first time an operator pressed Run.
    /// </summary>
    private void ValidateAgainstCatalog(IReadOnlyList<PlannedStage> stages)
    {
        var known = new HashSet<string>(_catalog.Select(t => t.TemplateId), StringComparer.OrdinalIgnoreCase);
        var invented = stages.Where(s => !known.Contains(s.TemplateId)).Select(s => s.TemplateId).Distinct().ToList();
        if (invented.Count > 0)
        {
            throw new InvalidOperationException(
                "The model's plan names templates the governed catalogue does not have: " +
                string.Join(", ", invented) +
                ". Nothing was built from it - a plan that names a template nobody wrote refuses the " +
                "moment it runs, and by then the operator is watching it fail.");
        }
    }

    private static string Text(JsonElement element, string property, string fallback) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String &&
        !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!
            : fallback;

    /// <summary>
    /// An id the model supplied, held to what a node id may be. Ids reach graph validation, edge
    /// matching and - through the workflow id - a webhook path, so a model that answered with a
    /// sentence, a path fragment or an empty string gets the positional default instead.
    /// </summary>
    private static string Identifier(JsonElement element, string property, string fallback)
    {
        string value = Text(element, property, string.Empty).Trim();
        return value.Length is > 0 and <= 64 && Regex.IsMatch(value, "^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
            ? value
            : fallback;
    }

    private sealed record PlannedStage(
        string StageId,
        string Name,
        string TemplateId,
        string Directive,
        bool ContinueOnFailure);

    private sealed record SynthesizedPlan(
        string? RecipeId,
        string WorkflowId,
        string Name,
        string Description,
        IReadOnlyList<PlannedStage> Stages);

    private sealed record Recipe(string Description, Func<string, WorkflowGraph> Build);

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

    /// <summary>
    /// The workflows that already exist, offered to the model by name and description.
    ///
    /// These were the keyword branches. They are kept because they carry structure a compiled stage
    /// list cannot express - an OAuth exchange, a conditional branch, semantic memory recall and
    /// store, a ReAct agent under a step ceiling - and because each one encodes a correction that
    /// took a mission to find. What changed is who chooses them: the model, reading the request
    /// against their descriptions, rather than <c>Contains("tiktok")</c>.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, Recipe> Recipes =
        new Dictionary<string, Recipe>(StringComparer.OrdinalIgnoreCase)
        {
            ["flow-react-autonomous-investigation"] = new(
                "An autonomous reason-act-observe agent under a hard step ceiling, for open-ended investigation.",
                ReActRecipe),
            ["flow-semantic-memory-correlation"] = new(
                "Recall past incidents from local semantic memory, correlate against live endpoint state, store what was learned.",
                MemoryRecipe),
            ["flow-transactional-safe-update"] = new(
                "A speculative change in a jail with an assertion and an automated rollback if it fails.",
                TransactionalRecipe),
            ["flow-tiktok-oauth-ads"] = new(
                "Receive an OAuth callback, vault the token with DPAPI, then audit the endpoint's egress posture.",
                OAuthRecipe),
            ["flow-log-audit-alert"] = new(
                "Every 15 minutes, sweep authentication logs, detect an error spike, and triage it with an agent.",
                LogAuditRecipe),
            ["flow-email-governed-parser"] = new(
                "On an inbound-email webhook, check the endpoint posture at time of receipt and parse the message with an agent.",
                EmailRecipe),
        };

    private static WorkflowGraph ReActRecipe(string prompt)
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
                    TargetModel: DefaultModelId)
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger-manual", "react-investigator")
            });

        graph.Validate();
        return graph;
    }

    private static WorkflowGraph MemoryRecipe(string prompt)
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
        return graph;
    }

    /// <summary>
    /// Keeps its own scripts on purpose: a TransactionalScope is an assert-and-rollback primitive,
    /// not a governed template, and it runs through the same refusing binder. It is also the node
    /// type with the least behind it - see F20 in the audits: a rollback that exits zero is not proof
    /// the prior state was restored.
    /// </summary>
    private static WorkflowGraph TransactionalRecipe(string prompt)
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
        return graph;
    }

    private static WorkflowGraph OAuthRecipe(string prompt)
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
                    TargetModel: DefaultModelId)
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger-oauth", "exchange-token"),
                new("exchange-token", "fetch-campaigns"),
                new("fetch-campaigns", "agent-analysis")
            });

        graph.Validate();
        return graph;
    }

    private static WorkflowGraph LogAuditRecipe(string prompt)
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
                    TargetModel: DefaultModelId)
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger-schedule", "collect-logs"),
                new("collect-logs", "condition-check"),
                new("condition-check", "reasoning-triage", ConditionBranch: "true")
            });

        graph.Validate();
        return graph;
    }

    private static WorkflowGraph EmailRecipe(string prompt)
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
                    TargetModel: DefaultModelId)
            },
            Edges: new List<WorkflowEdge>
            {
                new("trigger-webhook", "extract-body"),
                new("extract-body", "agent-parser")
            });

        graph.Validate();
        return graph;
    }
}
