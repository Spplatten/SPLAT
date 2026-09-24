using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Core.QualityIsland.Arbiter;
using MissionController.Core.QualityIsland.Contracts;
using MissionController.Core.QualityIsland.Evaluators;
using MissionController.Core.QualityIsland.Oracles;

namespace MissionController.Core.QualityIsland;

/// <summary>
/// Isolated Quality Check & Escalate Island Engine.
/// Operates as an isolated sub-loop adjacent to the execution pipeline, validating candidate AI
/// outputs on a 2D Decision Matrix (Quadrant I: X >= 1.0, Y >= Y_threshold).
/// Only Quadrant I verified artifacts are permitted to propagate downstream.
/// </summary>
public sealed class QualityIslandEngine : IIsolatedQualityIsland
{
    private readonly IModelStreamClient _modelClient;
    private readonly IAuditLedger _auditLedger;
    private readonly IValidationOracle _oracle;
    private readonly ISemanticEvaluator _semanticEvaluator;
    private readonly IBradleyTerryArbiter _arbiter;
    private readonly IDataLossPreventionSanitizer? _dlpSanitizer;
    private readonly ICredentialSanitizer? _credentialSanitizer;
    private readonly IDiagnosticFindingsExtractor _findingsExtractor;

    public QualityIslandEngine(
        IModelStreamClient modelClient,
        IAuditLedger auditLedger,
        IValidationOracle? oracle = null,
        ISemanticEvaluator? semanticEvaluator = null,
        IBradleyTerryArbiter? arbiter = null,
        IDataLossPreventionSanitizer? dlpSanitizer = null,
        ICredentialSanitizer? credentialSanitizer = null,
        IDiagnosticFindingsExtractor? findingsExtractor = null)
    {
        _modelClient = modelClient ?? throw new ArgumentNullException(nameof(modelClient));
        _auditLedger = auditLedger ?? throw new ArgumentNullException(nameof(auditLedger));
        _oracle = oracle ?? new CompositeValidationOracle();
        _semanticEvaluator = semanticEvaluator ?? new CompositeSemanticEvaluator();
        _arbiter = arbiter ?? new BradleyTerryArbiter();
        _dlpSanitizer = dlpSanitizer;
        _credentialSanitizer = credentialSanitizer;
        _findingsExtractor = findingsExtractor ?? new JsonFindingsExtractor();
    }

    public async Task<QuadrantEvaluationResult> EvaluateArtifactAsync(
        string candidateContent,
        string? rawTelemetry,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default)
    {
        var oracleTask = _oracle.ValidateAsync(candidateContent, contractType, options, cancellationToken);
        var semanticTask = _semanticEvaluator.EvaluateAsync(candidateContent, rawTelemetry, contractType, options, cancellationToken);

        await Task.WhenAll(oracleTask, semanticTask);

        var oracleResult = await oracleTask;
        var semanticResult = await semanticTask;

        double x = oracleResult.Score;
        double y = semanticResult.SemanticScore;
        double yThreshold = options.SemanticThreshold;

        EvaluationQuadrant quadrant;
        bool passedQuadrantI;

        if (oracleResult.IsProgrammaticallyValid && x >= 1.0)
        {
            if (y >= yThreshold)
            {
                quadrant = EvaluationQuadrant.QuadrantI_Pass;
                passedQuadrantI = true;
            }
            else
            {
                quadrant = EvaluationQuadrant.QuadrantIV_DeterministicOnly;
                passedQuadrantI = false;
            }
        }
        else
        {
            if (y >= yThreshold)
            {
                quadrant = EvaluationQuadrant.QuadrantII_SemanticOnly;
                passedQuadrantI = false;
            }
            else
            {
                quadrant = EvaluationQuadrant.QuadrantIII_Reject;
                passedQuadrantI = false;
            }
        }

        string summary = $"Quadrant: {quadrant} | Point: ({x:F2}, {y:F2}) | OracleValid: {oracleResult.IsProgrammaticallyValid} | SemanticScore: {y:F2} (Thresh: {yThreshold:F2})";

        return new QuadrantEvaluationResult(
            Point: new DecisionMatrixPoint(x, y),
            Quadrant: quadrant,
            PassedQuadrantI: passedQuadrantI,
            OracleResult: oracleResult,
            SemanticResult: semanticResult,
            Summary: summary);
    }

    public async Task<QualityIslandResult> ExecuteIslandAsync(
        QualityIslandRequest request,
        IProgress<string>? tokenProgress = null,
        IProgress<MissionChunk>? chunkProgress = null,
        CancellationToken cancellationToken = default)
    {
        var options = request.Options ?? new QualityIslandOptions();
        var stopwatch = Stopwatch.StartNew();
        var evaluatedCohort = new List<CandidateArtifact>();

        // Check if model is live
        var availability = await _modelClient.CheckAvailabilityAsync(request.TargetModel, cancellationToken);
        if (!availability.IsLive)
        {
            return await ExecuteSimulatedOrOfflineAsync(request, options, stopwatch, tokenProgress, chunkProgress, cancellationToken);
        }

        QualityIslandResult result;
        switch (options.Mode)
        {
            case QualityExecutionMode.SpeculativeBestOfN:
                result = await ExecuteSpeculativeBestOfNAsync(request, options, stopwatch, tokenProgress, chunkProgress, cancellationToken);
                break;

            case QualityExecutionMode.IncrementalEarlyAbort:
            case QualityExecutionMode.LeanFailSafe:
            default:
                result = await ExecuteLeanFailSafeAsync(request, options, stopwatch, tokenProgress, chunkProgress, cancellationToken);
                break;
        }

        stopwatch.Stop();
        return result;
    }

    private async Task<QualityIslandResult> ExecuteLeanFailSafeAsync(
        QualityIslandRequest request,
        QualityIslandOptions options,
        Stopwatch stopwatch,
        IProgress<string>? tokenProgress,
        IProgress<MissionChunk>? chunkProgress,
        CancellationToken cancellationToken)
    {
        var cohort = new List<CandidateArtifact>();

        // 1. Attempt #0: Fast Single Generation (Standard Model)
        var swCandidate0 = Stopwatch.StartNew();
        string raw0 = await GenerateCandidateStreamInternalAsync(
            request.TargetModel,
            request.SystemPrompt,
            request.UserPayload,
            cancellationToken);
        swCandidate0.Stop();

        string sanitized0 = SanitizeCandidateOutput(raw0);
        var eval0 = await EvaluateArtifactAsync(sanitized0, request.ExpectedTelemetryHaystack, request.RequiredSchema, options, cancellationToken);

        var candidate0 = new CandidateArtifact(
            CandidateId: $"cand-0-{Guid.NewGuid():N}",
            ModelId: request.TargetModel,
            RawContent: raw0,
            SanitizedContent: sanitized0,
            Evaluation: eval0,
            LatencyMs: swCandidate0.ElapsedMilliseconds,
            AttemptIndex: 0);

        cohort.Add(candidate0);

        // Audit first evaluation
        await _auditLedger.AppendLogAsync(
            request.MissionId,
            request.TemplateId,
            "CHECK_ESCALATE_EVALUATION",
            $"Attempt: 0 | Model: {request.TargetModel} | {eval0.Summary}",
            request.OperatorIdentity,
            cancellationToken);

        // 2. Check Quadrant I Pass (Zero Extra Overhead on Happy Path)
        if (eval0.PassedQuadrantI)
        {
            // Emit tokens to caller stream
            EmitTokens(sanitized0, request.MissionId, tokenProgress, chunkProgress);

            await _auditLedger.AppendLogAsync(
                request.MissionId,
                request.TemplateId,
                "CHECK_ESCALATE_QUADRANT_PASSED",
                $"Quadrant I verified on first pass. Total Latency: {swCandidate0.ElapsedMilliseconds}ms",
                request.OperatorIdentity,
                cancellationToken);

            return new QualityIslandResult(
                MissionId: request.MissionId,
                TemplateId: request.TemplateId,
                IsSuccess: true,
                OutputContent: sanitized0,
                WinningArtifact: candidate0,
                EvaluatedCohort: cohort,
                Telemetry: new EscalationTelemetry(
                    TotalCandidatesGenerated: 1,
                    EscalationCount: 0,
                    EscalationTriggered: false,
                    InitialFailureReason: null,
                    EscalatedModelUsed: null,
                    TotalLatencyMs: stopwatch.ElapsedMilliseconds),
                CompletedAtUtc: DateTime.UtcNow);
        }

        // 3. Out-of-Quadrant: Trigger Targeted Single Frontier Escalation
        string initialFailReason = string.Join("; ", eval0.OracleResult.RejectionReasons.Concat(eval0.SemanticResult.QualityNotes));
        string escalationModel = options.FrontierEscalationModel ?? request.TargetModel;

        // "Escalation" to the model that just failed is a RETRY, and a retry is a much weaker claim:
        // same weights, same telemetry, only a sharper prompt. The two were indistinguishable in the
        // ledger, and the default frontier model was the one most of the catalog already targets - so
        // the line an operator reads to decide whether a second opinion was obtained said escalation
        // when none happened. Configuration can still point both at one model; it can no longer do it
        // silently.
        bool sameModel = string.Equals(escalationModel, request.TargetModel, StringComparison.OrdinalIgnoreCase);
        string secondAttempt = sameModel
            ? $"RETRY on the same model '{escalationModel}' - no frontier model is configured above it, so this is a re-ask, not a second opinion"
            : $"escalation to frontier model '{escalationModel}'";

        await _auditLedger.AppendLogAsync(
            request.MissionId,
            request.TemplateId,
            "CHECK_ESCALATE_ESCALATION_TRIGGERED",
            $"First attempt landed in {eval0.Quadrant}. Triggering targeted {secondAttempt}. Failure: {initialFailReason}",
            request.OperatorIdentity,
            cancellationToken);

        string escalationSystemPrompt = BuildTargetedEscalationPrompt(
            request.SystemPrompt,
            eval0,
            request.RequiredSchema);

        var swCandidate1 = Stopwatch.StartNew();
        string raw1 = await GenerateCandidateStreamInternalAsync(
            escalationModel,
            escalationSystemPrompt,
            request.UserPayload,
            cancellationToken);
        swCandidate1.Stop();

        string sanitized1 = SanitizeCandidateOutput(raw1);
        var eval1 = await EvaluateArtifactAsync(sanitized1, request.ExpectedTelemetryHaystack, request.RequiredSchema, options, cancellationToken);

        var candidate1 = new CandidateArtifact(
            CandidateId: $"cand-1-esc-{Guid.NewGuid():N}",
            ModelId: escalationModel,
            RawContent: raw1,
            SanitizedContent: sanitized1,
            Evaluation: eval1,
            LatencyMs: swCandidate1.ElapsedMilliseconds,
            AttemptIndex: 1);

        cohort.Add(candidate1);

        await _auditLedger.AppendLogAsync(
            request.MissionId,
            request.TemplateId,
            "CHECK_ESCALATE_EVALUATION",
            $"Attempt: 1 (Escalated) | Model: {escalationModel} | {eval1.Summary}",
            request.OperatorIdentity,
            cancellationToken);

        CandidateArtifact winner;
        bool overallSuccess;

        if (eval1.PassedQuadrantI)
        {
            winner = candidate1;
            overallSuccess = true;

            await _auditLedger.AppendLogAsync(
                request.MissionId,
                request.TemplateId,
                "CHECK_ESCALATE_ESCALATION_SUCCEEDED",
                $"Targeted {secondAttempt} produced Quadrant I verified output.",
                request.OperatorIdentity,
                cancellationToken);
        }
        else
        {
            // If both attempts failed Quadrant I, pick higher scoring candidate or produce safe deterministic fallback
            if (eval1.OracleResult.Score >= eval0.OracleResult.Score)
            {
                winner = candidate1;
            }
            else
            {
                winner = candidate0;
            }

            overallSuccess = false;

            await _auditLedger.AppendLogAsync(
                request.MissionId,
                request.TemplateId,
                "CHECK_ESCALATE_ESCALATION_EXHAUSTED",
                $"Escalation completed. Output accepted with best-effort score {winner.Evaluation.Summary}",
                request.OperatorIdentity,
                cancellationToken);
        }

        // Emit final winning tokens to caller
        EmitTokens(winner.SanitizedContent, request.MissionId, tokenProgress, chunkProgress);

        return new QualityIslandResult(
            MissionId: request.MissionId,
            TemplateId: request.TemplateId,
            IsSuccess: overallSuccess,
            OutputContent: winner.SanitizedContent,
            WinningArtifact: winner,
            EvaluatedCohort: cohort,
            Telemetry: new EscalationTelemetry(
                TotalCandidatesGenerated: cohort.Count,
                EscalationCount: 1,
                EscalationTriggered: true,
                InitialFailureReason: initialFailReason,
                EscalatedModelUsed: escalationModel,
                TotalLatencyMs: stopwatch.ElapsedMilliseconds),
            CompletedAtUtc: DateTime.UtcNow);
    }

    private async Task<QualityIslandResult> ExecuteSpeculativeBestOfNAsync(
        QualityIslandRequest request,
        QualityIslandOptions options,
        Stopwatch stopwatch,
        IProgress<string>? tokenProgress,
        IProgress<MissionChunk>? chunkProgress,
        CancellationToken cancellationToken)
    {
        int n = Math.Max(2, options.SpeculativeSampleSize);
        var tasks = new List<Task<CandidateArtifact>>();

        for (int i = 0; i < n; i++)
        {
            int index = i;
            tasks.Add(Task.Run(async () =>
            {
                var sw = Stopwatch.StartNew();
                string raw = await GenerateCandidateStreamInternalAsync(
                    request.TargetModel,
                    request.SystemPrompt,
                    request.UserPayload,
                    cancellationToken);
                sw.Stop();

                string sanitized = SanitizeCandidateOutput(raw);
                var eval = await EvaluateArtifactAsync(sanitized, request.ExpectedTelemetryHaystack, request.RequiredSchema, options, cancellationToken);

                return new CandidateArtifact(
                    CandidateId: $"spec-cand-{index}-{Guid.NewGuid():N}",
                    ModelId: request.TargetModel,
                    RawContent: raw,
                    SanitizedContent: sanitized,
                    Evaluation: eval,
                    LatencyMs: sw.ElapsedMilliseconds,
                    AttemptIndex: index);
            }, cancellationToken));
        }

        var cohort = (await Task.WhenAll(tasks)).ToList();

        // Audit candidate cohort
        foreach (var cand in cohort)
        {
            await _auditLedger.AppendLogAsync(
                request.MissionId,
                request.TemplateId,
                "CHECK_ESCALATE_SPECULATIVE_CANDIDATE",
                $"Candidate: {cand.CandidateId} | Latency: {cand.LatencyMs}ms | {cand.Evaluation.Summary}",
                request.OperatorIdentity,
                cancellationToken);
        }

        // Filter to Quadrant I cohort if available
        var quadrantICohort = cohort.Where(c => c.Evaluation.PassedQuadrantI).ToList();
        var arbitrationPool = quadrantICohort.Count > 0 ? quadrantICohort : cohort;

        // Bradley-Terry Pairwise Arbiter with MM convergence
        var ranking = _arbiter.RankCandidates(arbitrationPool, request.ExpectedTelemetryHaystack);
        var winningCandidate = arbitrationPool.First(c => c.CandidateId == ranking.TopCandidateId);

        await _auditLedger.AppendLogAsync(
            request.MissionId,
            request.TemplateId,
            "CHECK_ESCALATE_BRADLEY_TERRY_RANKED",
            $"Arbiter MM Converged: {ranking.Matrix.Converged} in {ranking.Matrix.Iterations} iters. Top Candidate: {winningCandidate.CandidateId} (Score: {ranking.RankedCandidates[0].Score:F4})",
            request.OperatorIdentity,
            cancellationToken);

        EmitTokens(winningCandidate.SanitizedContent, request.MissionId, tokenProgress, chunkProgress);

        return new QualityIslandResult(
            MissionId: request.MissionId,
            TemplateId: request.TemplateId,
            IsSuccess: winningCandidate.Evaluation.PassedQuadrantI,
            OutputContent: winningCandidate.SanitizedContent,
            WinningArtifact: winningCandidate,
            EvaluatedCohort: cohort,
            Telemetry: new EscalationTelemetry(
                TotalCandidatesGenerated: cohort.Count,
                EscalationCount: 0,
                EscalationTriggered: false,
                InitialFailureReason: null,
                EscalatedModelUsed: null,
                TotalLatencyMs: stopwatch.ElapsedMilliseconds,
                ArbiterRanking: ranking),
            CompletedAtUtc: DateTime.UtcNow);
    }

    private async Task<QualityIslandResult> ExecuteSimulatedOrOfflineAsync(
        QualityIslandRequest request,
        QualityIslandOptions options,
        Stopwatch stopwatch,
        IProgress<string>? tokenProgress,
        IProgress<MissionChunk>? chunkProgress,
        CancellationToken cancellationToken)
    {
        // Produce simulated or deterministic findings
        var detResult = JsonFindingsExtractor.AnalyzeRawTelemetryDeterministic(
            request.ExpectedTelemetryHaystack ?? request.UserPayload,
            request.TemplateId,
            "SIMULATED OUTPUT — no AI model is connected");

        var sb = new StringBuilder();
        sb.AppendLine("⚡ [SIMULATED ANALYSIS — Zero-Cost Local Diagnostic Substrate]");
        sb.AppendLine(detResult.StatusHeadline);
        sb.AppendLine();
        sb.AppendLine("```json");
        sb.AppendLine("{");
        sb.AppendLine($"  \"status\": \"{detResult.OverallStatus}\",");
        sb.AppendLine($"  \"headline\": \"{EscapeJson(detResult.StatusHeadline)}\",");
        sb.AppendLine("  \"findings\": [");
        for (int i = 0; i < detResult.KeyFindings.Count; i++)
        {
            sb.Append($"    \"{EscapeJson(detResult.KeyFindings[i])}\"");
            if (i < detResult.KeyFindings.Count - 1) sb.Append(",");
            sb.AppendLine();
        }
        sb.AppendLine("  ],");
        sb.AppendLine("  \"recommendedActions\": [");
        if (detResult.RecommendedActions != null)
        {
            for (int i = 0; i < detResult.RecommendedActions.Count; i++)
            {
                sb.Append($"    \"{EscapeJson(detResult.RecommendedActions[i])}\"");
                if (i < detResult.RecommendedActions.Count - 1) sb.Append(",");
                sb.AppendLine();
            }
        }
        sb.AppendLine("  ]");
        sb.AppendLine("}");
        sb.AppendLine("```");

        string content = sb.ToString();
        var eval = await EvaluateArtifactAsync(content, request.ExpectedTelemetryHaystack, request.RequiredSchema, options, cancellationToken);

        var candidate = new CandidateArtifact(
            CandidateId: $"sim-{Guid.NewGuid():N}",
            ModelId: "local-deterministic-engine",
            RawContent: content,
            SanitizedContent: content,
            Evaluation: eval,
            LatencyMs: 1);

        EmitTokens(content, request.MissionId, tokenProgress, chunkProgress);

        // The offline artifact is evaluated by the same oracles as a model's, and then that verdict
        // is REPORTED. Hardcoding success here meant the one path that runs when no model is
        // configured - the default on a fresh install - returned IsSuccess regardless of what its
        // own evaluation said, so a deterministic analysis that failed its schema or grounding
        // checks still reached the caller as accepted evidence.
        string? offlineFailureReason = eval.PassedQuadrantI
            ? null
            : string.Join("; ", eval.OracleResult.RejectionReasons.Concat(eval.SemanticResult.QualityNotes));

        return new QualityIslandResult(
            MissionId: request.MissionId,
            TemplateId: request.TemplateId,
            IsSuccess: eval.PassedQuadrantI,
            OutputContent: content,
            WinningArtifact: candidate,
            EvaluatedCohort: new[] { candidate },
            Telemetry: new EscalationTelemetry(
                TotalCandidatesGenerated: 1,
                EscalationCount: 0,
                EscalationTriggered: false,
                InitialFailureReason: offlineFailureReason,
                EscalatedModelUsed: null,
                TotalLatencyMs: stopwatch.ElapsedMilliseconds),
            CompletedAtUtc: DateTime.UtcNow);
    }

    private async Task<string> GenerateCandidateStreamInternalAsync(
        string modelId,
        string systemPrompt,
        string userPayload,
        CancellationToken cancellationToken)
    {
        var sb = new StringBuilder();
        await foreach (var chunk in _modelClient.StreamAnalysisAsync(modelId, systemPrompt, userPayload, cancellationToken))
        {
            sb.Append(chunk);
        }
        return sb.ToString();
    }

    private string SanitizeCandidateOutput(string rawOutput)
    {
        string text = rawOutput;
        if (_credentialSanitizer != null)
        {
            text = _credentialSanitizer.Sanitize(text).SanitizedText;
        }
        if (_dlpSanitizer != null)
        {
            text = _dlpSanitizer.Sanitize(text).SanitizedContent;
        }
        return text;
    }

    private static string BuildTargetedEscalationPrompt(
        string baseSystemPrompt,
        QuadrantEvaluationResult failureEval,
        SchemaContractType contractType)
    {
        var sb = new StringBuilder();
        sb.AppendLine(baseSystemPrompt);
        sb.AppendLine();
        sb.AppendLine("[QUALITY ISLAND CORRECTION & ESCALATION DIRECTIVE]");
        sb.AppendLine("A previous model generation failed strict programmatic validity and grounding checks:");

        if (failureEval.OracleResult.RejectionReasons.Count > 0)
        {
            sb.AppendLine("- DETERMINISTIC ORACLE REJECTIONS:");
            foreach (var reason in failureEval.OracleResult.RejectionReasons)
            {
                sb.AppendLine($"  * {reason}");
            }
        }

        if (failureEval.SemanticResult.UngroundedClaims.Count > 0)
        {
            sb.AppendLine("- UNGROUNDED / FABRICATED CLAIMS DETECTED (MUST BE ELIMINATED):");
            foreach (var claim in failureEval.SemanticResult.UngroundedClaims)
            {
                sb.AppendLine($"  * {claim}");
            }
        }

        if (failureEval.SemanticResult.QualityNotes.Count > 0)
        {
            sb.AppendLine("- QUALITY DEFICIENCIES:");
            foreach (var note in failureEval.SemanticResult.QualityNotes)
            {
                sb.AppendLine($"  * {note}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("MANDATORY ESCALATION RULES:");
        sb.AppendLine("1. Strictly fix all JSON syntax, missing properties, or AST security violations listed above.");
        sb.AppendLine("2. Ground all key findings and values STRICTLY in the provided telemetry without inventing numbers, hosts, or paths.");
        sb.AppendLine("3. Emit the required fenced JSON block exactly as specified in the schema contract.");

        return sb.ToString();
    }

    private static void EmitTokens(
        string content,
        Guid missionId,
        IProgress<string>? tokenProgress,
        IProgress<MissionChunk>? chunkProgress)
    {
        tokenProgress?.Report(content);
        chunkProgress?.Report(new MissionChunk(
            missionId,
            MissionChunkType.AiToken,
            content,
            DateTime.UtcNow));
    }

    private static string EscapeJson(string? s)
    {
        if (s == null) return string.Empty;
        return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
    }
}
