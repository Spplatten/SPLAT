using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Brain;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using Xunit;

namespace MissionController.Tests;

public class AgentBrainTests
{
    private static readonly SingleToolTemplate NetTemplate = new(
        TemplateId: "net-dns-audit",
        Name: "Atlas-Net",
        Description: "Diagnoses network drops and DNS latency",
        Category: "Network",
        TargetModel: "claude-3-5-sonnet",
        Tool: new SingleToolDefinition("tool-ping", "Ping Tool", "ping.exe", "-n 1 1.1.1.1", new[] { 0 }),
        EgressRule: new EgressRule("api.anthropic.com", 443),
        SystemPrompt: "Analyze network status",
        ParameterFields: Array.Empty<TemplateParameterField>(),
        AvailableRemediations: new[]
        {
            new RemediationAction("net-dns-flush", "net-dns-audit", "Flush DNS Resolver Cache", "Flushes DNS cache", RemediationRiskLevel.Safe, true, "ipconfig.exe", "/flushdns", "ipconfig.exe", "/renew")
        });

    private static readonly SingleToolTemplate SecTemplate = new(
        TemplateId: "identity-auth-posture",
        Name: "Sentinel-SecOps",
        Description: "Hunts for brute force logon anomalies",
        Category: "Security",
        TargetModel: "claude-3-5-sonnet",
        Tool: new SingleToolDefinition("tool-wevtutil", "Event Log Tool", "wevtutil.exe", "qe Security", new[] { 0 }),
        EgressRule: new EgressRule("api.anthropic.com", 443),
        SystemPrompt: "Analyze auth security events",
        ParameterFields: Array.Empty<TemplateParameterField>(),
        AvailableRemediations: new[]
        {
            new RemediationAction("sec-lockout", "identity-auth-posture", "Enforce Account Lockout", "Sets lockout threshold", RemediationRiskLevel.Moderate, true, "net.exe", "accounts /lockoutthreshold:5", "net.exe", "accounts /lockoutthreshold:0")
        });

    private static readonly SingleToolTemplate DiskTemplate = new(
        TemplateId: "sysops-disk-space",
        Name: "Titan-SysOps",
        Description: "Analyzes disk space exhaustion",
        Category: "Storage",
        TargetModel: "claude-3-5-sonnet",
        Tool: new SingleToolDefinition("tool-wmic", "WMIC Tool", "wmic.exe", "logicaldisk get freespace", new[] { 0 }),
        EgressRule: new EgressRule("api.anthropic.com", 443),
        SystemPrompt: "Analyze disk headroom",
        ParameterFields: Array.Empty<TemplateParameterField>(),
        AvailableRemediations: new[]
        {
            new RemediationAction("disk-clean", "sysops-disk-space", "Purge Temp Cache", "Cleans temporary files", RemediationRiskLevel.Safe, false, "cleanmgr.exe", "/sagerun:1")
        });

    [Theory]
    [InlineData("Why is my internet dropping and DNS resolving so slowly?", "net-dns-audit")]
    // The goal changed with the template. "Investigate brute force attacks" used to route to a
    // detector that read the Security channel; nothing in the catalog reads it any more, so a goal
    // phrased as event hunting has no honest destination and the heuristic should not be taught to
    // pretend otherwise. What it can route is a question about exposure.
    [InlineData("Check the account lockout policy and which local accounts are enabled", "identity-auth-posture")]
    [InlineData("Our C: drive is completely out of space and needs temp cleanup", "sysops-disk-space")]
    public async Task CognitiveGoalDecomposer_Heuristic_Routes_Accurately(string userGoal, string expectedTemplateId)
    {
        var mockModelClient = new MockBrainModelClient();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient);
        var templates = new List<SingleToolTemplate> { NetTemplate, SecTemplate, DiskTemplate };

        var result = await decomposer.DecomposeGoalAsync(userGoal, templates);

        Assert.NotEmpty(result.RecommendedTemplateIds);
        Assert.Equal(expectedTemplateId, result.RecommendedTemplateIds[0]);
        Assert.True(result.ConfidenceScore > 0.5);
    }

    [Fact]
    public async Task AgentBrainEngine_ExecutesAutonomousMultiStepReasoning_AndSynthesizesRootCause()
    {
        var mockEngine = new MockMissionExecutionEngine(
            toolOutput: "Reply from 1.1.1.1: bytes=32 time=250ms TTL=54\nPackets: Sent = 4, Received = 2, Lost = 2 (50% loss)",
            aiAnalysis: "```json\n{\"status\":\"Critical\",\"headline\":\"Severe 50% Packet Loss Detected on Network Interface\",\"findings\":[\"50% packet loss to 1.1.1.1\",\"Latency elevated at 250ms\"],\"recommendedActions\":[\"Flush DNS cache\"]}\n```");

        var mockRegistry = new MockTemplateRegistry(new[] { NetTemplate, SecTemplate, DiskTemplate });
        var mockLedger = new MockBrainAuditLedger();
        var mockModelClient = new MockBrainModelClient();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient);

        var brain = new AgentBrainEngine(
            missionEngine: mockEngine,
            templateRegistry: mockRegistry,
            decomposer: decomposer,
            auditLedger: mockLedger);

        var progressChunks = new List<MissionChunk>();
        var progress = new Progress<MissionChunk>(chunk => progressChunks.Add(chunk));

        var result = await brain.ProcessGoalAsync(
            userGoal: "Diagnose why our cloud connection is lagging with massive packet loss",
            operatorIdentity: "corp\\alice",
            maxReasoningSteps: 2,
            progress: progress);

        Assert.Equal(DiagnosticHealthStatus.Critical, result.OverallStatus);
        Assert.Contains("Multi-Factor Degradation", result.ExecutiveHeadline);
        Assert.NotEmpty(result.ExecutedSteps);
        Assert.NotEmpty(result.EvaluatedHypotheses);
        Assert.Equal(HypothesisStatus.Confirmed, result.EvaluatedHypotheses[0].Status);
        Assert.NotEmpty(result.AvailableRemediations);
        Assert.Equal("Flush DNS Resolver Cache", result.AvailableRemediations[0].Title);
        Assert.NotEmpty(mockLedger.Entries);
        Assert.Equal("BRAIN_REASONING_COMPLETED", mockLedger.Entries[^1].Action);
        Assert.NotNull(result.AuditLedgerEntryHash);
    }

    [Fact]
    public async Task AgentBrainEngine_HandlesCleanHealth_WithExecutiveAllClear()
    {
        var mockEngine = new MockMissionExecutionEngine(
            toolOutput: "Reply from 1.1.1.1: bytes=32 time=12ms TTL=58\nPackets: Sent = 4, Received = 4, Lost = 0 (0% loss)",
            aiAnalysis: "```json\n{\"status\":\"Healthy\",\"headline\":\"Network Latency Normal and Zero Packet Loss\",\"findings\":[\"0% packet loss\",\"12ms latency\"],\"recommendedActions\":[]}\n```");

        var mockRegistry = new MockTemplateRegistry(new[] { NetTemplate, SecTemplate, DiskTemplate });
        var mockLedger = new MockBrainAuditLedger();
        var mockModelClient = new MockBrainModelClient();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient);

        var brain = new AgentBrainEngine(
            missionEngine: mockEngine,
            templateRegistry: mockRegistry,
            decomposer: decomposer,
            auditLedger: mockLedger);

        var result = await brain.ProcessGoalAsync(
            userGoal: "Check network health status",
            operatorIdentity: "corp\\bob",
            maxReasoningSteps: 1);

        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.Contains("ALL CLEAR", result.ExecutiveHeadline);
        Assert.NotEmpty(result.ExecutedSteps);
        Assert.Equal(HypothesisStatus.Refuted, result.EvaluatedHypotheses[0].Status);
    }

    [Fact]
    public void CognitiveGoalDecomposer_DefaultsTo_ClaudeSonnet5_AndIsConfigurable()
    {
        var mockModelClient = new MockBrainModelClient();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient);

        Assert.Equal("claude-sonnet-5", CognitiveGoalDecomposer.DefaultModelId);
        Assert.Equal("claude-sonnet-5", decomposer.ModelId);

        decomposer.ModelId = "claude-opus-custom";
        Assert.Equal("claude-opus-custom", decomposer.ModelId);

        var customDecomposer = new CognitiveGoalDecomposer(mockModelClient, modelId: "claude-haiku-instant");
        Assert.Equal("claude-haiku-instant", customDecomposer.ModelId);
    }

    [Fact]
    public async Task CognitiveGoalDecomposer_EmptyTemplateRegistry_DoesNotThrow()
    {
        var mockModelClient = new MockBrainModelClient();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient);

        var result = await decomposer.DecomposeGoalAsync("Check network health", Array.Empty<SingleToolTemplate>());

        Assert.Empty(result.RecommendedTemplateIds);
        Assert.Equal(0.0, result.ConfidenceScore);
        Assert.Contains("No governed templates", result.ReasoningRationale);

        var nextResult = await decomposer.DecomposeNextStepAsync(
            "Check network health",
            Array.Empty<SingleToolTemplate>(),
            new BrainWorkingMemory(Guid.NewGuid(), "Check network health"));

        Assert.False(nextResult.ShouldContinue);
        Assert.Null(nextResult.NextTemplateId);
    }

    [Fact]
    public async Task AgentBrainEngine_EmptyTemplateRegistry_DoesNotThrow_ReturnsUnresolved()
    {
        var mockEngine = new MockMissionExecutionEngine("output", "analysis");
        var emptyRegistry = new MockTemplateRegistry(Array.Empty<SingleToolTemplate>());
        var mockLedger = new MockBrainAuditLedger();
        var mockModelClient = new MockBrainModelClient();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient);

        var brain = new AgentBrainEngine(
            missionEngine: mockEngine,
            templateRegistry: emptyRegistry,
            auditLedger: mockLedger,
            decomposer: decomposer);

        var result = await brain.ProcessGoalAsync(
            userGoal: "Diagnose mysterious system slowdown",
            operatorIdentity: "corp\\secops",
            maxReasoningSteps: 3);

        Assert.Equal(DiagnosticHealthStatus.Unknown, result.OverallStatus);
        Assert.Contains("UNRESOLVED", result.ExecutiveHeadline);
        Assert.Empty(result.ExecutedSteps);
        Assert.Empty(result.EvaluatedHypotheses);
        Assert.NotEmpty(mockLedger.Entries);
        Assert.Equal("BRAIN_SESSION_EMPTY_CATALOG", mockLedger.Entries[^1].Action);
    }

    [Fact]
    public async Task AgentBrainEngine_DynamicRePlanning_FeedsGroundedFactsToNextStep()
    {
        // Step 1 (Net): detects high packet loss and latency
        // Step 2 (SecOps): dynamically re-planned as follow-up step
        var mockEngine = new DynamicMockMissionExecutionEngine(template =>
        {
            if (template.TemplateId == "net-dns-audit")
            {
                return (
                    "Reply from 1.1.1.1: 50% packet loss, ping timeout",
                    "```json\n{\"status\":\"Critical\",\"headline\":\"Severe Packet Loss Detected\",\"findings\":[\"50% packet loss\",\"Elevated latency\"],\"recommendedActions\":[\"Flush DNS\"]}\n```"
                );
            }
            return (
                "Event 4625 count: 0",
                "```json\n{\"status\":\"Healthy\",\"headline\":\"No Logon Anomalies Detected\",\"findings\":[\"Zero failed logons\"],\"recommendedActions\":[]}\n```"
            );
        });

        var mockRegistry = new MockTemplateRegistry(new[] { NetTemplate, SecTemplate, DiskTemplate });
        var mockLedger = new MockBrainAuditLedger();
        var mockModelClient = new MockBrainModelClient();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient);

        var brain = new AgentBrainEngine(
            missionEngine: mockEngine,
            templateRegistry: mockRegistry,
            auditLedger: mockLedger,
            decomposer: decomposer);

        var result = await brain.ProcessGoalAsync(
            userGoal: "Diagnose why network is experiencing heavy packet loss",
            operatorIdentity: "corp\\engineer",
            maxReasoningSteps: 2);

        Assert.Equal(DiagnosticHealthStatus.Critical, result.OverallStatus);
        Assert.NotEmpty(result.ExecutedSteps);
        Assert.Equal("net-dns-audit", result.ExecutedSteps[0].TemplateId);
        Assert.Contains(result.GroundedKeyFindings, f => f.Contains("50% packet loss"));
        Assert.Equal(HypothesisStatus.Confirmed, result.EvaluatedHypotheses[0].Status);
    }

    [Fact]
    public async Task AgentBrainEngine_IndexesCompletedSession_IntoSemanticMemory()
    {
        var mockEngine = new MockMissionExecutionEngine(
            toolOutput: "Reply from 1.1.1.1: bytes=32 time=15ms TTL=54",
            aiAnalysis: "```json\n{\"status\":\"Healthy\",\"headline\":\"Network Nominal\",\"findings\":[\"15ms latency\"],\"recommendedActions\":[]}\n```");

        var mockRegistry = new MockTemplateRegistry(new[] { NetTemplate, SecTemplate });
        var mockLedger = new MockBrainAuditLedger();
        var mockModelClient = new MockBrainModelClient();
        var mockMemoryIndex = new MockBrainSemanticMemoryIndex();
        var decomposer = new CognitiveGoalDecomposer(mockModelClient, mockMemoryIndex);

        var brain = new AgentBrainEngine(
            missionEngine: mockEngine,
            templateRegistry: mockRegistry,
            auditLedger: mockLedger,
            decomposer: decomposer,
            semanticMemoryIndex: mockMemoryIndex);

        var result = await brain.ProcessGoalAsync(
            userGoal: "Check network latency and connectivity",
            operatorIdentity: "corp\\dave",
            maxReasoningSteps: 1);

        Assert.Equal(DiagnosticHealthStatus.Healthy, result.OverallStatus);
        Assert.Single(mockMemoryIndex.IndexedDocuments);
        var (missionId, templateId, content) = mockMemoryIndex.IndexedDocuments[0];
        Assert.Equal(result.SessionId, missionId);
        Assert.Equal("agent-brain-session", templateId);
        Assert.Contains("Check network latency and connectivity", content);
        Assert.Contains("ALL CLEAR", content);
    }

    [Fact]
    public void AgentBrainEngine_Constructor_ThrowsOnNullAuditLedger()
    {
        var mockEngine = new MockMissionExecutionEngine("out", "ai");
        var mockRegistry = new MockTemplateRegistry(new[] { NetTemplate });

        Assert.Throws<ArgumentNullException>("auditLedger", () =>
            new AgentBrainEngine(
                missionEngine: mockEngine,
                templateRegistry: mockRegistry,
                auditLedger: null!));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Test Doubles
    // ─────────────────────────────────────────────────────────────────────────────

    private sealed class MockBrainSemanticMemoryIndex : ISemanticMemoryIndex
    {
        public List<(Guid MissionId, string TemplateId, string Content)> IndexedDocuments { get; } = new();
        public List<SemanticSearchResult> SimulatedResults { get; } = new();

        public Task IndexMissionDocumentAsync(Guid missionId, string templateId, string content, CancellationToken cancellationToken = default)
        {
            IndexedDocuments.Add((missionId, templateId, content));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<SemanticSearchResult>> SearchSimilarMissionsAsync(string query, int topK = 5, double minScore = 0.1, CancellationToken cancellationToken = default)
        {
            return Task.FromResult<IReadOnlyList<SemanticSearchResult>>(SimulatedResults);
        }
    }

    private sealed class DynamicMockMissionExecutionEngine : IMissionExecutionEngine
    {
        private readonly Func<SingleToolTemplate, (string ToolOutput, string AiAnalysis)> _handler;

        public DynamicMockMissionExecutionEngine(Func<SingleToolTemplate, (string ToolOutput, string AiAnalysis)> handler)
        {
            _handler = handler;
        }

        public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var id = Guid.NewGuid();
            var (toolOutput, aiAnalysis) = _handler(template);
            yield return new MissionChunk(id, MissionChunkType.StatusChange, $"Starting {template.Name}", DateTime.UtcNow);
            yield return new MissionChunk(id, MissionChunkType.Stdout, toolOutput, DateTime.UtcNow);
            yield return new MissionChunk(id, MissionChunkType.AiToken, aiAnalysis, DateTime.UtcNow);
            yield return new MissionChunk(id, MissionChunkType.Completed, "Done", DateTime.UtcNow);
            await Task.Yield();
        }
    }

    private sealed class MockBrainModelClient : IModelStreamClient
    {
        public Task<ModelAvailability> CheckAvailabilityAsync(string requestedModel, CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(false, "Simulated", requestedModel, "No real key configured"));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel,
            string systemPrompt,
            string userPrompt,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            yield return "```json\n{\"status\":\"Healthy\",\"headline\":\"System Nominal\",\"findings\":[],\"recommendedActions\":[]}\n```";
        }
    }

    private sealed class MockMissionExecutionEngine : IMissionExecutionEngine
    {
        private readonly string _toolOutput;
        private readonly string _aiAnalysis;

        public MockMissionExecutionEngine(string toolOutput, string aiAnalysis)
        {
            _toolOutput = toolOutput;
            _aiAnalysis = aiAnalysis;
        }

        public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
            SingleToolTemplate template,
            IReadOnlyDictionary<string, string> parameters,
            string operatorIdentity,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            var id = Guid.NewGuid();
            yield return new MissionChunk(id, MissionChunkType.StatusChange, $"Starting {template.Name}", DateTime.UtcNow);
            yield return new MissionChunk(id, MissionChunkType.Stdout, _toolOutput, DateTime.UtcNow);
            yield return new MissionChunk(id, MissionChunkType.AiToken, _aiAnalysis, DateTime.UtcNow);
            yield return new MissionChunk(id, MissionChunkType.Completed, "Done", DateTime.UtcNow);
            await Task.Yield();
        }
    }

    private sealed class MockTemplateRegistry : ITemplateRegistry
    {
        private readonly IReadOnlyList<SingleToolTemplate> _templates;
        public MockTemplateRegistry(IReadOnlyList<SingleToolTemplate> templates) => _templates = templates;

        public Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(_templates);

        public Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default) =>
            Task.FromResult(_templates.FirstOrDefault(t => string.Equals(t.TemplateId, templateId, StringComparison.OrdinalIgnoreCase)));

        public Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default) => Task.CompletedTask;
    }

    private sealed class MockBrainAuditLedger : IAuditLedger
    {
        public List<AuditLogEntry> Entries { get; } = new();

        public Task AppendLogAsync(Guid missionId, string templateId, string action, string details, string operatorIdentity, CancellationToken cancellationToken = default)
        {
            long id = Entries.Count + 1;
            string hash = Guid.NewGuid().ToString("N");
            string prevHash = Entries.Count > 0 ? Entries[^1].EntryHash : "0000000000000000000000000000000000000000000000000000000000000000";
            Entries.Add(new AuditLogEntry(id, DateTime.UtcNow, missionId, templateId, action, details, operatorIdentity, hash, prevHash));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(Guid? missionId = null, int limit = 100, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Entries);

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);
    }
}
