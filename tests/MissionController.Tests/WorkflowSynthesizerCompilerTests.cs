using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.Workflow;
using MissionController.Infrastructure.Data.Catalog;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// The synthesiser compiles a sentence into a governed plan, or it refuses. Everything here is about
/// the difference between those two and the thing it replaced, which did neither: it accepted an
/// <see cref="IModelStreamClient"/> and never called it, matched <c>Contains("tiktok")</c> over five
/// hardcoded graphs, and answered everything else with an Active Directory health check labelled
/// "Successfully synthesized".
/// </summary>
public class WorkflowSynthesizerCompilerTests
{
    private static IReadOnlyList<SingleToolTemplate> Catalog() => GovernedTemplateCatalog.All;

    private static string FirstTemplateId() => Catalog()[0].TemplateId;

    /// <summary>
    /// The sentence this was built for. "Keep going if it fails" is a boolean on a stage, not a
    /// checkbox the operator has to find afterwards - so the compiled plan must carry it on the stage
    /// the operator meant, and only that one.
    /// </summary>
    [Fact]
    public async Task ARequestToCarryOnPastAFailure_FlipsThatStagesBoolean()
    {
        string first = Catalog()[0].TemplateId;
        string second = Catalog()[1].TemplateId;
        var model = new ScriptedPlanner($$"""
        {
          "workflowId": "flow-disk-then-network",
          "name": "Disk sweep, then network",
          "description": "Check the disk, carry on regardless, then check the network.",
          "stages": [
            {"stageId": "stage-1", "name": "Stage 1: Disk", "templateId": "{{first}}",
             "directive": "Report free space per volume.", "continueOnFailure": true},
            {"stageId": "stage-2", "name": "Stage 2: Network", "templateId": "{{second}}",
             "directive": "Report the adapter state.", "continueOnFailure": false}
          ]
        }
        """);

        var project = await new WorkflowSynthesizerEngine(model, Catalog())
            .SynthesizeProjectAsync("Run the disk audit and click continue if this stage reports a failure, then check the network");

        Assert.Equal(2, project.Stages.Count);
        Assert.True(project.Stages[0].ContinueOnFailure);
        Assert.False(project.Stages[1].ContinueOnFailure);
        Assert.Equal(first, project.Stages[0].TemplateId);
        Assert.Equal("Report free space per volume.", project.Stages[0].Directive);

        // The operator's own sentence reached the model rather than a keyword match of it.
        Assert.Contains("click continue", model.LastUserPrompt, StringComparison.Ordinal);
    }

    /// <summary>
    /// The grounding context. A compiler that does not put the catalogue in front of the model is
    /// asking it to guess ids, and a guessed id is a plan that refuses the first time it runs.
    /// </summary>
    [Fact]
    public async Task TheCatalogueIsWhatTheModelIsGivenToChooseFrom()
    {
        var model = new ScriptedPlanner(Plan(FirstTemplateId()));

        await new WorkflowSynthesizerEngine(model, Catalog()).SynthesizeProjectAsync("anything");

        foreach (var template in Catalog().Take(5))
        {
            Assert.Contains(template.TemplateId, model.LastSystemPrompt, StringComparison.Ordinal);
        }

        Assert.Contains("copied exactly", model.LastSystemPrompt, StringComparison.Ordinal);
    }

    /// <summary>
    /// The fail-closed boundary. The model is an untrusted input source: a plan naming a template
    /// nobody wrote must die here, not in front of an operator who pressed Run.
    /// </summary>
    [Fact]
    public async Task ATemplateTheCatalogueDoesNotHave_IsRefusedBeforeAnythingIsBuilt()
    {
        var model = new ScriptedPlanner(Plan("sysops-quantum-defragmenter"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(model, Catalog()).SynthesizeProjectAsync("defragment the qubits"));

        Assert.Contains("sysops-quantum-defragmenter", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithNoModelConnected_SynthesisRefusesRatherThanInventingAPlan()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(modelClient: null, catalog: Catalog())
                .SynthesizeFromNaturalLanguageAsync("scrape the logs"));

        Assert.Contains("Settings", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WithNoCatalogue_SynthesisRefuses()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(new ScriptedPlanner(Plan("anything")), Array.Empty<SingleToolTemplate>())
                .SynthesizeFromNaturalLanguageAsync("scrape the logs"));

        Assert.Contains("catalogue", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("I'd suggest running the disk audit first.")]
    [InlineData("{\"stages\": []}")]
    [InlineData("{\"stages\": [{\"templateId\": \"\", \"directive\": \"x\"}]}")]
    [InlineData("[]")]
    public async Task AnAnswerThatIsNotAPlan_IsRefused(string answer)
    {
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(new ScriptedPlanner(answer), Catalog())
                .SynthesizeProjectAsync("do something"));
    }

    [Fact]
    public async Task AStageWithNoDirective_IsRefused()
    {
        var model = new ScriptedPlanner(
            $"{{\"stages\": [{{\"stageId\": \"stage-1\", \"templateId\": \"{FirstTemplateId()}\", \"directive\": \"  \"}}]}}");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(model, Catalog()).SynthesizeProjectAsync("do something"));

        Assert.Contains("directive", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TwoStagesWithOneId_AreRefused()
    {
        string id = FirstTemplateId();
        var model = new ScriptedPlanner(
            $"{{\"stages\": [" +
            $"{{\"stageId\": \"stage-1\", \"templateId\": \"{id}\", \"directive\": \"a\"}}," +
            $"{{\"stageId\": \"stage-1\", \"templateId\": \"{id}\", \"directive\": \"b\"}}]}}");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(model, Catalog()).SynthesizeProjectAsync("do something twice"));

        Assert.Contains("stage-1", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MoreStagesThanAProjectMayHold_AreRefused()
    {
        string id = FirstTemplateId();
        var stages = string.Join(",", Enumerable.Range(1, WorkflowSynthesizerEngine.MaxStages + 1)
            .Select(n => $"{{\"stageId\": \"stage-{n}\", \"templateId\": \"{id}\", \"directive\": \"step {n}\"}}"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(new ScriptedPlanner($"{{\"stages\": [{stages}]}}"), Catalog())
                .SynthesizeProjectAsync("do seven things"));

        Assert.Contains(WorkflowSynthesizerEngine.MaxStages.ToString(), ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The plan and the tool are different things. A stage's directive and its continue-on-failure
    /// flag travel in the node's configuration, which the workflow engine otherwise hands to the
    /// argument binder as mission parameters - and the binder refuses a parameter no template
    /// declares, so a plan carrying its own description would refuse the moment it ran.
    /// </summary>
    [Fact]
    public async Task TheGraphCarriesTheDirectiveAndTheFlag_WithoutBindingThemAsMissionParameters()
    {
        var model = new ScriptedPlanner(Plan(FirstTemplateId(), continueOnFailure: true));

        var graph = await new WorkflowSynthesizerEngine(model, Catalog())
            .SynthesizeFromNaturalLanguageAsync("check the disk and keep going");

        var mission = Assert.Single(graph.Nodes, n => n.NodeType == WorkflowNodeType.GovernedMission);
        Assert.Equal(FirstTemplateId(), mission.Configuration[WorkflowExecutionEngine.TemplateIdKey]);
        Assert.Equal("Report free space per volume.", mission.Configuration[WorkflowExecutionEngine.DirectiveKey]);
        Assert.Equal("true", mission.Configuration[WorkflowExecutionEngine.ContinueOnFailureKey]);

        Assert.All(
            mission.Configuration.Keys,
            key => Assert.Contains(key, WorkflowExecutionEngine.ReservedConfigurationKeys));
    }

    /// <summary>
    /// The flag is only written when it is true. A graph that carried it on every node would say
    /// nothing about which stage the operator asked to survive a failure.
    /// </summary>
    [Fact]
    public async Task AStageThatMustStopOnFailure_CarriesNoFlagAtAll()
    {
        var graph = await new WorkflowSynthesizerEngine(new ScriptedPlanner(Plan(FirstTemplateId())), Catalog())
            .SynthesizeFromNaturalLanguageAsync("check the disk");

        var mission = Assert.Single(graph.Nodes, n => n.NodeType == WorkflowNodeType.GovernedMission);
        Assert.False(mission.Configuration.ContainsKey(WorkflowExecutionEngine.ContinueOnFailureKey));
    }

    /// <summary>
    /// The prebuilt workflows survive, but the model chooses them by reading their descriptions
    /// against the request. They carry structure a stage list cannot - an OAuth exchange, a
    /// conditional branch, memory recall - and each encodes a correction that took a mission to find.
    /// </summary>
    [Fact]
    public async Task ARecipeTheModelChose_IsCompiledWithItsOwnStructure()
    {
        var graph = await new WorkflowSynthesizerEngine(
                new ScriptedPlanner("{\"recipeId\": \"flow-tiktok-oauth-ads\"}"), Catalog())
            .SynthesizeFromNaturalLanguageAsync("receive the TikTok OAuth callback and audit the account");

        Assert.Equal("flow-tiktok-oauth-ads", graph.WorkflowId);
        Assert.Equal(WorkflowTriggerType.OAuthCallback, graph.Trigger.Type);
        Assert.Contains(graph.Nodes, n => n.NodeType == WorkflowNodeType.OAuthExchange);
    }

    /// <summary>
    /// A project is an ordered list of governed missions, and three of the six recipes have none - a
    /// ReAct agent, a memory pipeline, a transactional scope. Offering them here would have let the
    /// model answer a project request with a workflow that leaves no stages, and the operator would
    /// have read a validation error about stage counts instead of an answer.
    /// </summary>
    [Fact]
    public async Task CompilingAProject_NeitherOffersARecipeNorAcceptsOne()
    {
        var offered = new ScriptedPlanner(Plan(FirstTemplateId()));
        await new WorkflowSynthesizerEngine(offered, Catalog()).SynthesizeProjectAsync("check the disk");
        Assert.DoesNotContain("recipeId", offered.LastSystemPrompt, StringComparison.Ordinal);
        Assert.DoesNotContain("flow-log-audit-alert", offered.LastSystemPrompt, StringComparison.Ordinal);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(ScriptedPlanner.ChoosingRecipe("flow-react-autonomous-investigation"), Catalog())
                .SynthesizeProjectAsync("investigate the network"));
        Assert.Contains("was not offered", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARecipeThatDoesNotExist_IsRefused()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new WorkflowSynthesizerEngine(new ScriptedPlanner("{\"recipeId\": \"flow-do-my-taxes\"}"), Catalog())
                .SynthesizeFromNaturalLanguageAsync("do my taxes"));

        Assert.Contains("flow-do-my-taxes", ex.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// Models fence their JSON whether or not they are asked to. Refusing that would be refusing a
    /// correct answer for its packaging.
    /// </summary>
    [Fact]
    public async Task AFencedAnswer_IsRead()
    {
        var model = new ScriptedPlanner("Here is the plan:\n```json\n" + Plan(FirstTemplateId()) + "\n```\n");

        var project = await new WorkflowSynthesizerEngine(model, Catalog()).SynthesizeProjectAsync("check the disk");

        Assert.Single(project.Stages);
    }

    /// <summary>
    /// Whatever the model answered, the ids in the result are the catalogue's. This is the assertion
    /// that would have caught the old default workflow: it ran sysops-ad-dc-health for every request
    /// it did not recognise, which is a real template, so an id check alone would have passed it -
    /// what makes this meaningful is that the stage came from the answer to this prompt.
    /// </summary>
    [Fact]
    public async Task EveryStageOfACompiledPlan_NamesATemplateTheCatalogueHas()
    {
        var known = new HashSet<string>(Catalog().Select(t => t.TemplateId), StringComparer.OrdinalIgnoreCase);
        string id = Catalog()[3].TemplateId;

        var project = await new WorkflowSynthesizerEngine(new ScriptedPlanner(Plan(id)), Catalog())
            .SynthesizeProjectAsync("whatever this asks for");

        Assert.All(project.Stages, stage => Assert.Contains(stage.TemplateId, known));
        Assert.Equal(id, Assert.Single(project.Stages).TemplateId);
    }

    private static string Plan(string templateId, bool continueOnFailure = false) => $$"""
    {
      "workflowId": "flow-one-step",
      "name": "One step",
      "description": "A single governed stage.",
      "stages": [
        {"stageId": "stage-1", "name": "Stage 1: Disk", "templateId": "{{templateId}}",
         "directive": "Report free space per volume.", "continueOnFailure": {{(continueOnFailure ? "true" : "false")}}}
      ]
    }
    """;
}
