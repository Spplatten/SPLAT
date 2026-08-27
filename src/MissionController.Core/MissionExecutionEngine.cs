using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core;

public sealed class MissionExecutionEngine : IMissionExecutionEngine
{
    private readonly IJailManager _jailManager;
    private readonly IProcessLauncher _processLauncher;
    private readonly IModelStreamClient _modelClient;
    private readonly IAuditLedger _auditLedger;
    private readonly Func<string, IJobSandbox> _jobSandboxFactory;
    private readonly ISemanticMemoryIndex? _semanticMemoryIndex;
    private readonly IDataLossPreventionSanitizer? _dlpSanitizer;
    private readonly ICredentialSanitizer? _credentialSanitizer;
    private readonly IIncidentRevocationManager? _revocationManager;

    public MissionExecutionEngine(
        IJailManager jailManager,
        IProcessLauncher processLauncher,
        IModelStreamClient modelClient,
        IAuditLedger auditLedger,
        Func<string, IJobSandbox> jobSandboxFactory,
        ISemanticMemoryIndex? semanticMemoryIndex = null,
        IDataLossPreventionSanitizer? dlpSanitizer = null,
        ICredentialSanitizer? credentialSanitizer = null,
        IIncidentRevocationManager? revocationManager = null)
    {
        _jailManager = jailManager;
        _processLauncher = processLauncher;
        _modelClient = modelClient;
        _auditLedger = auditLedger;
        _jobSandboxFactory = jobSandboxFactory;
        _semanticMemoryIndex = semanticMemoryIndex;
        _dlpSanitizer = dlpSanitizer;
        _credentialSanitizer = credentialSanitizer;
        _revocationManager = revocationManager;
    }

    public async IAsyncEnumerable<MissionChunk> ExecuteMissionAsync(
        SingleToolTemplate template,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        // 1. Strict 1:1:1 Rule Enforcement
        template.ValidateStrictRules();

        var missionId = Guid.NewGuid();
        string jailPath = string.Empty;
        var fullOutput = new StringBuilder();
        var fullAiAnalysis = new StringBuilder();

        // 1.1 Revocation Circuit Breaker Check
        if (_revocationManager != null)
        {
            var revStatus = await _revocationManager.CheckRevocationAsync(operatorIdentity, cancellationToken);
            if (revStatus.IsRevoked)
            {
                yield return new MissionChunk(
                    missionId,
                    MissionChunkType.Stderr,
                    $"SECURITY ABORT: Operator '{operatorIdentity}' or session is explicitly revoked ({revStatus.Entry?.Reason}).",
                    DateTime.UtcNow);
                yield return new MissionChunk(
                    missionId,
                    MissionChunkType.StatusChange,
                    "Mission aborted by Circuit Breaker (Revoked Identity).",
                    DateTime.UtcNow);
                yield break;
            }
        }

        yield return new MissionChunk(
            missionId,
            MissionChunkType.StatusChange,
            $"Initiating Mission [{missionId}] using agent template '{template.Name}' (Strict 1:1:1 Governed Flow)",
            DateTime.UtcNow);


        // 2. Audit Start
        await _auditLedger.AppendLogAsync(
            missionId,
            template.TemplateId,
            "MISSION_INITIATED",
            $"Template: {template.Name} | Model: {template.TargetModel} | Tool: {template.Tool.Name} | Egress: {template.EgressRule.AllowedFqdn}",
            operatorIdentity,
            cancellationToken);

        // 3. Provision Isolated NT ACL Jail
        yield return new MissionChunk(
            missionId,
            MissionChunkType.StatusChange,
            "Provisioning ACL-isolated jail directory...",
            DateTime.UtcNow);

        jailPath = await _jailManager.ProvisionJailAsync(missionId, cancellationToken);

        // A jail directory now exists on disk, so the guard must open BEFORE the next yield:
        // an async iterator abandoned at a yield outside the try would skip the finally and leak
        // the jail. Everything below runs inside try/finally (body intentionally left at this
        // indentation to keep the guarded region reviewable as one diff) so the jail is drained
        // on EVERY exit path - success, tool failure, AI fault, cancellation, abandonment.
        bool jailDrained = false;
        try
        {

        yield return new MissionChunk(
            missionId,
            MissionChunkType.StatusChange,
            $"Jail established at '{jailPath}' (Parent inheritance stripped).",
            DateTime.UtcNow);

        // 4. Create Win32 Job Object & Launch Process Suspended
        using var jobSandbox = _jobSandboxFactory($"MissionJob_{missionId:N}");
        jobSandbox.ConfigureExtendedLimits(template.Tool.MaxMemoryBytes, template.Tool.MaxCpuPercent);

        yield return new MissionChunk(
            missionId,
            MissionChunkType.StatusChange,
            $"Win32 Job Object configured with {template.Tool.MaxMemoryBytes / (1024 * 1024)}MB RAM cap and {template.Tool.MaxCpuPercent}% CPU limit.",
            DateTime.UtcNow);

        // Construct command line arguments
        string resolvedArguments = template.Tool.ArgumentsTemplate;
        var effectiveDefaults = template.GetEffectiveDefaults();

        foreach (var (key, val) in effectiveDefaults)
        {
            resolvedArguments = resolvedArguments.Replace($"{{{key}}}", val);
        }

        foreach (var (key, val) in parameters)
        {
            if (!string.IsNullOrWhiteSpace(val))
            {
                resolvedArguments = resolvedArguments.Replace($"{{{key}}}", val);
            }
        }

        yield return new MissionChunk(
            missionId,
            MissionChunkType.StatusChange,
            $"Spawning agent sensor suspended: {template.Tool.ExecutablePath} {resolvedArguments}",
            DateTime.UtcNow);

        var stdoutProgress = new Progress<string>();
        var stderrProgress = new Progress<string>();

        // The Win32 launch path (CreateProcessW, token restriction, job assignment) is the most
        // failure-prone native call in the mission. Capture instead of throwing so the operator
        // gets a readable failure chunk and a sealed MISSION_FAILED audit row - an unhandled
        // exception here would otherwise kill the UI's stream with no terminal record.
        ProcessExecutionResult? launchResult = null;
        Exception? launchFailure = null;
        try
        {
            launchResult = await _processLauncher.LaunchSuspendedInJobAsync(
                template.Tool.ExecutablePath,
                resolvedArguments,
                jailPath,
                jobSandbox,
                template.Tool.RequiresRestrictedToken,
                template.Tool.TimeoutSeconds,
                stdoutProgress,
                stderrProgress,
                cancellationToken);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            launchFailure = ex;
        }

        if (launchFailure is not null)
        {
            yield return new MissionChunk(
                missionId,
                MissionChunkType.Stderr,
                $"⚠ MISSION FAILED: the confined sensor tool could not be executed ({launchFailure.Message}). No AI analysis was performed.",
                DateTime.UtcNow);

            await _auditLedger.AppendLogAsync(
                missionId,
                template.TemplateId,
                "MISSION_FAILED",
                $"Tool launch failure: {launchFailure.GetType().Name}: {launchFailure.Message}",
                operatorIdentity,
                cancellationToken);

            yield return new MissionChunk(
                missionId,
                MissionChunkType.StatusChange,
                "Mission aborted. Failure sealed in the audit ledger; jail will be drained.",
                DateTime.UtcNow);
            yield break;
        }

        var execResult = launchResult!;
        fullOutput.Append(execResult.StandardOutput);
        if (!string.IsNullOrEmpty(execResult.StandardError))
        {
            fullOutput.AppendLine();
            fullOutput.Append(execResult.StandardError);
        }

        yield return new MissionChunk(
            missionId,
            MissionChunkType.Stdout,
            execResult.StandardOutput,
            DateTime.UtcNow,
            null,
            execResult.FinalMetrics.PeakMemoryBytes);

        if (!string.IsNullOrEmpty(execResult.StandardError))
        {
            yield return new MissionChunk(
                missionId,
                MissionChunkType.Stderr,
                execResult.StandardError,
                DateTime.UtcNow);
        }

        yield return new MissionChunk(
            missionId,
            MissionChunkType.Metric,
            $"Process exited with code {execResult.ExitCode}. Kernel CPU: {execResult.FinalMetrics.TotalCpuKernelTimeMs}ms, User CPU: {execResult.FinalMetrics.TotalCpuUserTimeMs}ms",
            DateTime.UtcNow);

        // 5. Audit Process Completion
        await _auditLedger.AppendLogAsync(
            missionId,
            template.TemplateId,
            "TOOL_EXECUTION_COMPLETED",
            $"ExitCode: {execResult.ExitCode} | OutputBytes: {fullOutput.Length}",
            operatorIdentity,
            cancellationToken);

        // 6. Layer 4: In-Memory DLP & Credential Sanitization before Egress
        string sanitizedPayload = fullOutput.ToString();
        if (_credentialSanitizer != null)
        {
            var credResult = _credentialSanitizer.Sanitize(sanitizedPayload);
            if (credResult.RedactedCount > 0)
            {
                sanitizedPayload = credResult.SanitizedText;
                yield return new MissionChunk(
                    missionId,
                    MissionChunkType.StatusChange,
                    $"⚡ Credential Shield: Redacted {credResult.RedactedCount} sensitive credentials/keys before AI analysis.",
                    DateTime.UtcNow);
            }
        }

        if (_dlpSanitizer != null)
        {
            var dlpResult = _dlpSanitizer.Sanitize(sanitizedPayload);
            if (dlpResult.RedactedCount > 0)
            {
                sanitizedPayload = dlpResult.SanitizedContent;
                yield return new MissionChunk(
                    missionId,
                    MissionChunkType.StatusChange,
                    $"⚡ DLP Filter Guard: Redacted {dlpResult.RedactedCount} sensitive items ({string.Join(", ", dlpResult.RedactedCategories)}) before transmission.",
                    DateTime.UtcNow);

                await _auditLedger.AppendLogAsync(
                    missionId,
                    template.TemplateId,
                    "DLP_REDACTION_ENFORCED",
                    $"RedactedCount: {dlpResult.RedactedCount} | Categories: {string.Join(",", dlpResult.RedactedCategories)}",
                    operatorIdentity,
                    cancellationToken);
            }
        }

        // 7. AI Synthesis & Streaming (provider-governed)
        string effectiveSystemPrompt = template.SystemPrompt;
        if (parameters.TryGetValue("UserInstruction", out var userInstruction) && !string.IsNullOrWhiteSpace(userInstruction))
        {
            effectiveSystemPrompt = $"{template.SystemPrompt}\n\n[SPECIFIC OPERATOR GOAL / DIRECTIVE]:\n{userInstruction}";
        }
        else if (parameters.TryGetValue("UserGoalPrompt", out var userGoal) && !string.IsNullOrWhiteSpace(userGoal))
        {
            effectiveSystemPrompt = $"{template.SystemPrompt}\n\n[SPECIFIC OPERATOR GOAL / DIRECTIVE]:\n{userGoal}";
        }

        if (_credentialSanitizer != null)
        {
            effectiveSystemPrompt = _credentialSanitizer.Sanitize(effectiveSystemPrompt).SanitizedText;
        }

        // Probe for a live model FIRST. If none is connected, emit a loud SimulatedNotice so the
        // analysis that follows can never be mistaken for genuine model output.
        var availability = await _modelClient.CheckAvailabilityAsync(template.TargetModel, cancellationToken);
        if (availability.IsLive)
        {
            yield return new MissionChunk(
                missionId,
                MissionChunkType.StatusChange,
                $"Engaging {availability.ProviderName} model '{availability.ModelId}' for analysis (egress governed)...",
                DateTime.UtcNow);
            await _auditLedger.AppendLogAsync(
                missionId,
                template.TemplateId,
                "AI_MODEL_ENGAGED",
                $"Provider: {availability.ProviderName} | Model: {availability.ModelId}",
                operatorIdentity,
                cancellationToken);
        }
        else
        {
            yield return new MissionChunk(
                missionId,
                MissionChunkType.SimulatedNotice,
                $"No live AI model connected ({availability.UnavailableReason}). The analysis below is a local simulation, not real model output.",
                DateTime.UtcNow);
            await _auditLedger.AppendLogAsync(
                missionId,
                template.TemplateId,
                "AI_SIMULATED_FALLBACK",
                availability.UnavailableReason ?? "No live model connected.",
                operatorIdentity,
                cancellationToken);
        }

        await foreach (var aiChunk in _modelClient.StreamAnalysisAsync(
            template.TargetModel,
            effectiveSystemPrompt,
            sanitizedPayload,
            cancellationToken))
        {
            fullAiAnalysis.Append(aiChunk);
            yield return new MissionChunk(
                missionId,
                MissionChunkType.AiToken,
                aiChunk,
                DateTime.UtcNow);
        }

        // 8. Audit AI Completion
        await _auditLedger.AppendLogAsync(
            missionId,
            template.TemplateId,
            "AI_ANALYSIS_COMPLETED",
            $"AnalysisLength: {fullAiAnalysis.Length} chars",
            operatorIdentity,
            cancellationToken);

        // 9. Index into In-Process Semantic Memory
        if (_semanticMemoryIndex != null)
        {
            await _semanticMemoryIndex.IndexMissionDocumentAsync(
                missionId,
                template.TemplateId,
                $"{template.Name}\n{sanitizedPayload}\n{fullAiAnalysis}",
                cancellationToken);
        }

        // 10. Drain & Clean Jail
        yield return new MissionChunk(
            missionId,
            MissionChunkType.StatusChange,
            "Draining and releasing filesystem jail...",
            DateTime.UtcNow);

        await _jailManager.DrainAndCleanupJailAsync(jailPath);
        jailDrained = true;

        yield return new MissionChunk(
            missionId,
            MissionChunkType.Completed,
            "Mission Completed Successfully. All resources released, DLP sanitized, semantic memory indexed, and audit ledger sealed.",
            DateTime.UtcNow);

        }
        finally
        {
            if (!jailDrained && !string.IsNullOrEmpty(jailPath))
            {
                // Backstop for every abnormal exit (launch failure, AI fault, cancellation,
                // abandoned enumerator). Best-effort: a cleanup exception must never mask the
                // original fault or throw from a finally during unwind.
                try { await _jailManager.DrainAndCleanupJailAsync(jailPath); } catch { }
            }
        }
    }
}
