using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Oracles;

/// <summary>
/// Deterministic Oracle that performs AST and static security analysis on generated scripts/commands.
/// Bridges <see cref="DynamicCodeAstValidator"/> to reject uncontained or high-risk primitives.
/// </summary>
public sealed class AstCodeValidationOracle : IValidationOracle
{
    private static readonly Regex CodeBlockRegex = new(
        @"```(?:[a-zA-Z0-9_-]+)?\s*([\s\S]*?)\s*```",
        RegexOptions.Compiled);

    public Task<OracleValidationResult> ValidateAsync(
        string candidateContent,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(candidateContent))
        {
            return Task.FromResult(OracleValidationResult.Fail("Candidate code is empty."));
        }

        string language = options.DynamicLanguage ?? "bash";

        // If dynamic code script contract, validate the entire content plus any embedded code blocks
        if (contractType == SchemaContractType.DynamicCodeScript)
        {
            var wholeValidation = DynamicCodeAstValidator.Validate(candidateContent, language);
            if (!wholeValidation.IsSafe)
            {
                return Task.FromResult(OracleValidationResult.Fail(
                    wholeValidation.RejectionReason ?? "AST validation rejected code payload.",
                    wholeValidation.DetectedRisks));
            }
        }

        // Also scan any fenced code blocks in other contract types
        foreach (Match match in CodeBlockRegex.Matches(candidateContent))
        {
            string blockContent = match.Groups[1].Value;
            if (string.IsNullOrWhiteSpace(blockContent)) continue;

            // Skip pure JSON blocks in structured contracts
            if (blockContent.TrimStart().StartsWith("{") && blockContent.TrimEnd().EndsWith("}"))
            {
                continue;
            }

            var blockValidation = DynamicCodeAstValidator.Validate(blockContent, language);
            if (!blockValidation.IsSafe)
            {
                return Task.FromResult(OracleValidationResult.Fail(
                    blockValidation.RejectionReason ?? "AST validation rejected embedded code block.",
                    blockValidation.DetectedRisks));
            }
        }

        return Task.FromResult(OracleValidationResult.Pass());
    }
}
