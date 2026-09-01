using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland;
using MissionController.Core.QualityIsland.Arbiter;
using MissionController.Core.QualityIsland.Contracts;
using MissionController.Core.QualityIsland.Evaluators;
using MissionController.Core.QualityIsland.Oracles;
using Xunit;

namespace MissionController.Tests;

public class QualityIslandTests
{
    private sealed class InMemoryAuditLedger : IAuditLedger
    {
        public readonly List<(string Action, string Details)> Entries = new();

        public Task AppendLogAsync(
            Guid missionId,
            string templateId,
            string action,
            string details,
            string operatorIdentity,
            CancellationToken cancellationToken = default)
        {
            Entries.Add((action, details));
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AuditLogEntry>> GetAuditLogsAsync(
            Guid? missionId = null,
            int limit = 100,
            CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<AuditLogEntry>>(Array.Empty<AuditLogEntry>());

        public Task<bool> VerifyLedgerIntegrityAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(true);
    }

    private sealed class ConfigurableMockModelClient : IModelStreamClient
    {
        private readonly Queue<string> _responses = new();
        public readonly List<(string ModelId, string SystemPrompt, string UserPrompt)> CapturedCalls = new();

        public ConfigurableMockModelClient(params string[] responses)
        {
            foreach (var r in responses) _responses.Enqueue(r);
        }

        public Task<ModelAvailability> CheckAvailabilityAsync(
            string requestedModel,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(new ModelAvailability(true, "MockProvider", requestedModel, null));

        public async IAsyncEnumerable<string> StreamAnalysisAsync(
            string requestedModel,
            string systemPrompt,
            string userPrompt,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            CapturedCalls.Add((requestedModel, systemPrompt, userPrompt));
            string response = _responses.Count > 0 ? _responses.Dequeue() : "Default mock response.";
            yield return response;
            await Task.Yield();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 1. 2D Decision Matrix & Quadrant I Evaluation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task DecisionMatrix_ValidStructuredJsonAndGroundedTelemetry_LandsInQuadrantI()
    {
        var island = new QualityIslandEngine(
            new ConfigurableMockModelClient(),
            new InMemoryAuditLedger());

        string candidate = """
        System triage complete. Memory usage is nominal.
        ```json
        {
          "status": "Healthy",
          "headline": "Endpoint memory and CPU within operational parameters",
          "findings": [
            "Physical memory at 42% utilization",
            "Available memory: 8192 MB"
          ],
          "recommendedActions": [
            "No remediation required"
          ]
        }
        ```
        """;

        string telemetry = "Physical Memory: 42% utilized. Available: 8192 MB. Status: Normal.";

        var eval = await island.EvaluateArtifactAsync(
            candidate,
            telemetry,
            SchemaContractType.StructuredDiagnosis,
            new QualityIslandOptions(SemanticThreshold: 0.75));

        Assert.True(eval.PassedQuadrantI);
        Assert.Equal(EvaluationQuadrant.QuadrantI_Pass, eval.Quadrant);
        Assert.True(eval.OracleResult.IsProgrammaticallyValid);
        Assert.Equal(1.0, eval.Point.X);
        Assert.True(eval.Point.Y >= 0.75);
    }

    [Fact]
    public async Task DecisionMatrix_MalformedJson_LandsInQuadrantII_SemanticOnly()
    {
        var island = new QualityIslandEngine(
            new ConfigurableMockModelClient(),
            new InMemoryAuditLedger());

        // High semantic content via markdown diagnosis but invalid JSON syntax (unquoted key and missing closing brace)
        string candidate = """
        ### Executive Diagnosis
        - **Status**: Warning
        - **Headline**: High CPU utilization detected on svchost process
        - **Key Findings**:
          * svchost PID 1244 CPU at 98%
        - **Recommended Actions**:
          * Review active services under svchost PID 1244

        ```json
        {
          status: "Warning",
          headline: "High CPU utilization detected on svchost process",
          findings: [ "svchost PID 1244 CPU at 98%" ]
        """;

        string telemetry = "svchost.exe PID 1244 CPU: 98%";

        var eval = await island.EvaluateArtifactAsync(
            candidate,
            telemetry,
            SchemaContractType.StructuredDiagnosis,
            new QualityIslandOptions(SemanticThreshold: 0.70));

        Assert.False(eval.PassedQuadrantI);
        Assert.Equal(EvaluationQuadrant.QuadrantII_SemanticOnly, eval.Quadrant);
        Assert.False(eval.OracleResult.IsProgrammaticallyValid);
        Assert.True(eval.Point.Y >= 0.70);
    }

    [Fact]
    public async Task DecisionMatrix_FabricatedClaims_LandsInQuadrantIV_DeterministicOnly()
    {
        var island = new QualityIslandEngine(
            new ConfigurableMockModelClient(),
            new InMemoryAuditLedger());

        // Syntactically valid JSON, but claims fabricated IPs and critical failure not in telemetry
        string candidate = """
        Active ransomware attack detected.
        ```json
        {
          "status": "Critical",
          "headline": "Active command-and-control connection to 192.168.99.100",
          "findings": [
            "Malicious process lockbit.exe running from C:\\Windows\\Temp\\lockbit.exe",
            "Outbound connection to 192.168.99.100 with 45000 failed attempts"
          ],
          "recommendedActions": [
            "Isolate host immediately"
          ]
        }
        ```
        """;

        string cleanTelemetry = "Network adapter status: UP. IP: 10.0.0.1. No active connections to public hosts.";

        var eval = await island.EvaluateArtifactAsync(
            candidate,
            cleanTelemetry,
            SchemaContractType.StructuredDiagnosis,
            new QualityIslandOptions(SemanticThreshold: 0.75));

        Assert.False(eval.PassedQuadrantI);
        Assert.Equal(EvaluationQuadrant.QuadrantIV_DeterministicOnly, eval.Quadrant);
        Assert.True(eval.OracleResult.IsProgrammaticallyValid);
        Assert.True(eval.Point.Y < 0.75); // Grounding penalty drops Y below threshold
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 2. Deterministic Oracle Unit Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task JsonSchemaOracle_RejectsMissingRequiredProperties()
    {
        var oracle = new JsonSchemaValidationOracle();
        string jsonWithoutHeadline = """
        ```json
        {
          "status": "Healthy",
          "findings": ["Everything OK"]
        }
        ```
        """;

        var res = await oracle.ValidateAsync(
            jsonWithoutHeadline,
            SchemaContractType.StructuredDiagnosis,
            new QualityIslandOptions());

        Assert.False(res.IsProgrammaticallyValid);
        Assert.Contains(res.RejectionReasons, r => r.Contains("headline"));
    }

    [Fact]
    public async Task JsonSchemaOracle_RejectsInvalidReActTemplateId()
    {
        var oracle = new JsonSchemaValidationOracle();
        string reactOutput = """
        ```json
        {
          "action": "continue",
          "templateId": "unauthorized-custom-script",
          "reason": "Investigate further"
        }
        ```
        """;

        var res = await oracle.ValidateAsync(
            reactOutput,
            SchemaContractType.ReActDecision,
            new QualityIslandOptions(AllowedTemplateIds: new[] { "net-ping", "sys-services" }));

        Assert.False(res.IsProgrammaticallyValid);
        Assert.Contains(res.RejectionReasons, r => r.Contains("not present in the offered governed catalog"));
    }

    [Fact]
    public async Task AstCodeOracle_RejectsBannedImportsInGeneratedScripts()
    {
        var oracle = new AstCodeValidationOracle();
        string pythonWithOs = """
        ```python
        import os
        os.system("whoami /priv")
        ```
        """;

        var res = await oracle.ValidateAsync(
            pythonWithOs,
            SchemaContractType.DynamicCodeScript,
            new QualityIslandOptions(DynamicLanguage: "python"));

        Assert.False(res.IsProgrammaticallyValid);
        Assert.Contains(res.DetectedRisks, risk => risk.Contains("os module import"));
    }

    [Fact]
    public async Task AstCodeOracle_RejectsDangerousShellCommands()
    {
        var oracle = new AstCodeValidationOracle();
        string shellScript = """
        #!/bin/bash
        rm -rf /
        """;

        var res = await oracle.ValidateAsync(
            shellScript,
            SchemaContractType.DynamicCodeScript,
            new QualityIslandOptions(DynamicLanguage: "bash"));

        Assert.False(res.IsProgrammaticallyValid);
        Assert.Contains(res.DetectedRisks, risk => risk.Contains("root wipe"));
    }

    [Fact]
    public async Task StructureIntegrityOracle_RejectsUnbalancedFences()
    {
        var oracle = new StructureIntegrityOracle();
        string incomplete = "Here is the analysis ```json { \"status\": \"Healthy\" }";

        var res = await oracle.ValidateAsync(
            incomplete,
            SchemaContractType.StructuredDiagnosis,
            new QualityIslandOptions());

        Assert.False(res.IsProgrammaticallyValid);
        Assert.Contains(res.RejectionReasons, r => r.Contains("Unbalanced markdown code fences"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 3. Semantic & Anti-Hedging Evaluator Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AntiHedgingEvaluator_PenalizesEvasiveAiBoilerplate()
    {
        var evaluator = new AntiHedgingSemanticEvaluator();
        string evasive = "As an AI language model, I am unable to determine if the server is healthy. Please consult a professional.";

        var res = await evaluator.EvaluateAsync(
            evasive,
            "Server status: UP",
            SchemaContractType.FreeFormGroundedText,
            new QualityIslandOptions());

        Assert.True(res.AntiHedgingScore < 0.5);
        Assert.Contains(res.QualityNotes, note => note.Contains("AI refusal / self-identification boilerplate"));
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 4. Lean Fail-Safe & Targeted Frontier Escalation Engine Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task LeanFailSafe_HappyPath_ExecutesSinglePassWithoutEscalation()
    {
        string goodOutput = """
        Host firewall is active.
        ```json
        {
          "status": "Healthy",
          "headline": "Windows Defender Firewall is operational",
          "findings": [ "Domain profile is Active", "Private profile is Active" ],
          "recommendedActions": [ "None" ]
        }
        ```
        """;

        var mockClient = new ConfigurableMockModelClient(goodOutput);
        var auditLedger = new InMemoryAuditLedger();
        var island = new QualityIslandEngine(mockClient, auditLedger);

        var request = new QualityIslandRequest(
            MissionId: Guid.NewGuid(),
            TemplateId: "net-firewall-status",
            TargetModel: "claude-sonnet-5",
            SystemPrompt: "Analyze firewall",
            UserPayload: "DomainProfile: Active. PrivateProfile: Active.",
            OperatorIdentity: "SecOps_Tier1",
            ExpectedTelemetryHaystack: "DomainProfile: Active. PrivateProfile: Active.");

        var result = await island.ExecuteIslandAsync(request);

        Assert.True(result.IsSuccess);
        Assert.Equal(1, result.Telemetry.TotalCandidatesGenerated);
        Assert.False(result.Telemetry.EscalationTriggered);
        Assert.Equal(0, result.Telemetry.EscalationCount);
        Assert.Single(mockClient.CapturedCalls);

        Assert.Contains(auditLedger.Entries, e => e.Action == "CHECK_ESCALATE_QUADRANT_PASSED");
        Assert.DoesNotContain(auditLedger.Entries, e => e.Action == "CHECK_ESCALATE_ESCALATION_TRIGGERED");
    }

    [Fact]
    public async Task LeanFailSafe_OutOfQuadrantPass1_TriggersTargetedFrontierEscalationWithTelemetry()
    {
        // First response: broken JSON (missing closing brace)
        string brokenOutput = """
        Firewall looks OK.
        ```json
        {
          "status": "Healthy",
          "headline": "Firewall running",
          "findings": [ "Domain active" ]
        """;

        // Second response (from escalation): perfectly corrected Quadrant I JSON
        string fixedOutput = """
        Firewall telemetry verified.
        ```json
        {
          "status": "Healthy",
          "headline": "Windows Defender Firewall is active on Domain profile",
          "findings": [
            "Domain profile is active and enforced"
          ],
          "recommendedActions": [
            "No remediation needed"
          ]
        }
        ```
        """;

        var mockClient = new ConfigurableMockModelClient(brokenOutput, fixedOutput);
        var auditLedger = new InMemoryAuditLedger();
        var island = new QualityIslandEngine(mockClient, auditLedger);

        var request = new QualityIslandRequest(
            MissionId: Guid.NewGuid(),
            TemplateId: "net-firewall-check",
            TargetModel: "gemini-2.0-flash",
            SystemPrompt: "Analyze firewall rules.",
            UserPayload: "Domain profile is active and enforced.",
            OperatorIdentity: "SecOps_Tier1",
            ExpectedTelemetryHaystack: "Domain profile is active and enforced.",
            Options: new QualityIslandOptions(
                Mode: QualityExecutionMode.LeanFailSafe,
                FrontierEscalationModel: "claude-sonnet-5"));

        var result = await island.ExecuteIslandAsync(request);

        Assert.True(result.IsSuccess);
        Assert.Equal(2, result.Telemetry.TotalCandidatesGenerated);
        Assert.True(result.Telemetry.EscalationTriggered);
        Assert.Equal(1, result.Telemetry.EscalationCount);
        Assert.Equal("claude-sonnet-5", result.Telemetry.EscalatedModelUsed);

        // Verify that the second call received the correction prompt with deterministic error telemetry
        Assert.Equal(2, mockClient.CapturedCalls.Count);
        var escalationCall = mockClient.CapturedCalls[1];
        Assert.Equal("claude-sonnet-5", escalationCall.ModelId);
        Assert.Contains("[QUALITY ISLAND CORRECTION & ESCALATION DIRECTIVE]", escalationCall.SystemPrompt);
        Assert.Contains("DETERMINISTIC ORACLE REJECTIONS", escalationCall.SystemPrompt);

        // Verify audit trail
        Assert.Contains(auditLedger.Entries, e => e.Action == "CHECK_ESCALATE_ESCALATION_TRIGGERED");
        Assert.Contains(auditLedger.Entries, e => e.Action == "CHECK_ESCALATE_ESCALATION_SUCCEEDED");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 5. Bubble Isolation Tests
    // ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task QualityIsland_MaintainsBubbleIsolation_DoesNotLeakIntermediateFailuresToProgress()
    {
        string brokenOutput = "Broken invalid output { bad json }";
        string fixedOutput = """
        Clean verified diagnosis.
        ```json
        {
          "status": "Healthy",
          "headline": "System is nominal",
          "findings": [ "Host responsive" ],
          "recommendedActions": [ "None" ]
        }
        ```
        """;

        var mockClient = new ConfigurableMockModelClient(brokenOutput, fixedOutput);
        var auditLedger = new InMemoryAuditLedger();
        var island = new QualityIslandEngine(mockClient, auditLedger);

        var streamedTokens = new List<string>();
        var progressHandler = new Progress<string>(token => streamedTokens.Add(token));

        var request = new QualityIslandRequest(
            MissionId: Guid.NewGuid(),
            TemplateId: "sys-health",
            TargetModel: "flash-model",
            SystemPrompt: "Check health",
            UserPayload: "Host responsive",
            OperatorIdentity: "Admin",
            ExpectedTelemetryHaystack: "Host responsive");

        var result = await island.ExecuteIslandAsync(request, tokenProgress: progressHandler);

        Assert.True(result.IsSuccess);
        // The output and winning artifact only contain the clean corrected response
        Assert.Contains("Clean verified diagnosis", result.OutputContent);
        Assert.DoesNotContain("Broken invalid output", result.OutputContent);
    }
}
