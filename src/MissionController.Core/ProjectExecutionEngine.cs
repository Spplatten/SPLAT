using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Core;

public sealed class ProjectExecutionEngine : IProjectExecutionEngine
{
    private const int MaxContextCharacters = 24000;
    private readonly ITemplateRegistry _templateRegistry;
    private readonly IMissionExecutionEngine _missionEngine;
    private readonly IAuditLedger? _auditLedger;

    public ProjectExecutionEngine(
        ITemplateRegistry templateRegistry,
        IMissionExecutionEngine missionEngine,
        IAuditLedger? auditLedger = null)
    {
        _templateRegistry = templateRegistry;
        _missionEngine = missionEngine;
        _auditLedger = auditLedger;
    }

    public async IAsyncEnumerable<MissionChunk> ExecuteProjectAsync(
        ProjectTemplate project,
        IReadOnlyDictionary<string, string> parameters,
        string operatorIdentity,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        project.Validate();
        var projectMissionId = Guid.NewGuid();
        var projectContext = BuildInitialContext(project, parameters);
        var hadToleratedFailure = false;

        if (_auditLedger != null)
        {
            await _auditLedger.AppendLogAsync(
                projectMissionId,
                project.ProjectId,
                "PROJECT_INITIATED",
                $"Stages: {project.Stages.Count} | Deliverables: {project.Deliverables.Count}",
                operatorIdentity,
                cancellationToken);
        }

        yield return new MissionChunk(
            projectMissionId,
            MissionChunkType.StatusChange,
            $"Starting governed project '{project.Name}' with {project.Stages.Count} ordered agent stages.",
            DateTime.UtcNow);

        for (var index = 0; index < project.Stages.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var stage = project.Stages[index];
            var template = await _templateRegistry.GetTemplateByIdAsync(stage.TemplateId, cancellationToken);
            if (template == null)
            {
                yield return new MissionChunk(
                    projectMissionId,
                    MissionChunkType.Stderr,
                    $"PROJECT FAILED: stage '{stage.Name}' references unavailable agent template '{stage.TemplateId}'.",
                    DateTime.UtcNow);

                if (_auditLedger != null)
                {
                    await _auditLedger.AppendLogAsync(
                        projectMissionId,
                        project.ProjectId,
                        "PROJECT_FAILED",
                        $"Stage {index + 1} references unavailable template '{stage.TemplateId}'.",
                        operatorIdentity,
                        cancellationToken);
                }

                if (!stage.ContinueOnFailure)
                {
                    yield return new MissionChunk(
                        projectMissionId,
                        MissionChunkType.StatusChange,
                        $"Project aborted at stage {index + 1}/{project.Stages.Count}.",
                        DateTime.UtcNow);
                    yield break;
                }

                hadToleratedFailure = true;
                continue;
            }

            yield return new MissionChunk(
                projectMissionId,
                MissionChunkType.StatusChange,
                $"Stage {index + 1}/{project.Stages.Count}: {stage.Name} → {template.Name}",
                DateTime.UtcNow);

            var stageParameters = new Dictionary<string, string>(parameters, StringComparer.OrdinalIgnoreCase)
            {
                ["UserInstruction"] = stage.Directive,
                ["ProjectContext"] = projectContext
            };

            var stageEvidence = new StringBuilder();
            var stageFailed = false;

            await foreach (var chunk in _missionEngine.ExecuteMissionAsync(
                template,
                stageParameters,
                operatorIdentity,
                cancellationToken))
            {
                if (chunk.ChunkType is MissionChunkType.Stdout or MissionChunkType.AiToken)
                {
                    AppendBounded(stageEvidence, chunk.Content);
                }

                if (chunk.ChunkType is MissionChunkType.Stderr &&
                    (chunk.Content.Contains("MISSION FAILED", StringComparison.OrdinalIgnoreCase) ||
                     chunk.Content.Contains("SECURITY ABORT", StringComparison.OrdinalIgnoreCase) ||
                     chunk.Content.Contains("PROJECT FAILED", StringComparison.OrdinalIgnoreCase)))
                {
                    stageFailed = true;
                }

                yield return chunk;
            }

            projectContext = AppendStageContext(projectContext, stage, stageEvidence, stageFailed);

            if (_auditLedger != null)
            {
                await _auditLedger.AppendLogAsync(
                    projectMissionId,
                    project.ProjectId,
                    "PROJECT_STAGE_COMPLETED",
                    $"Stage {index + 1}/{project.Stages.Count}: {stage.StageId} | Failed: {stageFailed}",
                    operatorIdentity,
                    cancellationToken);
            }

            if (stageFailed && !stage.ContinueOnFailure)
            {
                if (_auditLedger != null)
                {
                    await _auditLedger.AppendLogAsync(
                        projectMissionId,
                        project.ProjectId,
                        "PROJECT_FAILED",
                        $"Stage {index + 1}/{project.Stages.Count} failed and its continue policy was disabled.",
                        operatorIdentity,
                        cancellationToken);
                }

                yield return new MissionChunk(
                    projectMissionId,
                    MissionChunkType.StatusChange,
                    $"Project aborted after failed stage {index + 1}/{project.Stages.Count}.",
                    DateTime.UtcNow);
                yield break;
            }

            if (stageFailed)
            {
                hadToleratedFailure = true;
            }

            yield return new MissionChunk(
                projectMissionId,
                MissionChunkType.StatusChange,
                $"Stage {index + 1}/{project.Stages.Count} completed; bounded evidence context forwarded to the next stage.",
                DateTime.UtcNow);
        }

        if (_auditLedger != null)
        {
            await _auditLedger.AppendLogAsync(
                projectMissionId,
                project.ProjectId,
                hadToleratedFailure ? "PROJECT_COMPLETED_WITH_WARNINGS" : "PROJECT_COMPLETED",
                hadToleratedFailure
                    ? $"Completed {project.Stages.Count} ordered stages with tolerated failures."
                    : $"Completed {project.Stages.Count} ordered stages.",
                operatorIdentity,
                cancellationToken);
        }

        yield return new MissionChunk(
            projectMissionId,
            MissionChunkType.Completed,
            hadToleratedFailure
                ? $"Project '{project.Name}' completed with tolerated stage failures. Deliverables: {string.Join(", ", project.Deliverables)}"
                : $"Project '{project.Name}' completed. Deliverables: {string.Join(", ", project.Deliverables)}",
            DateTime.UtcNow);
    }

    private static string BuildInitialContext(ProjectTemplate project, IReadOnlyDictionary<string, string> parameters)
    {
        var context = new StringBuilder();
        context.AppendLine($"Project objective: {project.Description}");
        if (parameters.TryGetValue("ProjectGoal", out var goal) && !string.IsNullOrWhiteSpace(goal))
        {
            context.AppendLine($"Operator project goal: {goal}");
        }

        return context.ToString();
    }

    private static string AppendStageContext(
        string currentContext,
        ProjectStage stage,
        StringBuilder stageEvidence,
        bool stageFailed)
    {
        var nextContext = new StringBuilder(currentContext);
        nextContext.AppendLine();
        nextContext.AppendLine($"Completed stage '{stage.Name}' (failed: {stageFailed}).");
        nextContext.AppendLine(stageEvidence.ToString());

        if (nextContext.Length <= MaxContextCharacters)
        {
            return nextContext.ToString();
        }

        return nextContext.ToString()[^MaxContextCharacters..];
    }

    private static void AppendBounded(StringBuilder builder, string content)
    {
        if (builder.Length >= MaxContextCharacters)
        {
            return;
        }

        var remaining = MaxContextCharacters - builder.Length;
        builder.Append(content.AsSpan(0, Math.Min(content.Length, remaining)));
    }
}
