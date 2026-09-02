using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Oracles;

/// <summary>
/// Deterministic Oracle verifying structural integrity, balanced delimiters,
/// non-truncation, and absence of control character corruption.
/// </summary>
public sealed class StructureIntegrityOracle : IValidationOracle
{
    private static readonly Regex FencedBlockRegex = new(
        @"```",
        RegexOptions.Compiled);

    public Task<OracleValidationResult> ValidateAsync(
        string candidateContent,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(candidateContent))
        {
            return Task.FromResult(OracleValidationResult.Fail("Output is empty."));
        }

        var errors = new List<string>();

        // 1. Check minimum length
        if (candidateContent.Trim().Length < 10)
        {
            errors.Add("Output is suspiciously short (< 10 chars), likely truncated or incomplete.");
        }

        // 2. Check balanced code fences (```)
        int fenceCount = FencedBlockRegex.Matches(candidateContent).Count;
        if (fenceCount % 2 != 0)
        {
            errors.Add($"Unbalanced markdown code fences detected (found {fenceCount} '```' markers). Output was likely truncated.");
        }

        // 3. Check for balanced braces in JSON structured contracts
        if (contractType is SchemaContractType.StructuredDiagnosis or SchemaContractType.ReActDecision or SchemaContractType.GoalDecomposition or SchemaContractType.CustomJson)
        {
            int openBraces = 0;
            int closeBraces = 0;
            foreach (char c in candidateContent)
            {
                if (c == '{') openBraces++;
                if (c == '}') closeBraces++;
            }

            if (openBraces == 0)
            {
                errors.Add("No JSON object braces '{...}' found in structured contract output.");
            }
            else if (openBraces != closeBraces)
            {
                errors.Add($"Unbalanced JSON braces detected ({openBraces} open vs {closeBraces} closed).");
            }
        }

        // 4. Check for null bytes or control characters
        foreach (char c in candidateContent)
        {
            if (c != '\r' && c != '\n' && c != '\t' && char.IsControl(c))
            {
                errors.Add($"Illegal binary/control character (0x{(int)c:X2}) detected in output stream.");
                break;
            }
        }

        if (errors.Count > 0)
        {
            return Task.FromResult(OracleValidationResult.Fail(errors));
        }

        return Task.FromResult(OracleValidationResult.Pass());
    }
}
