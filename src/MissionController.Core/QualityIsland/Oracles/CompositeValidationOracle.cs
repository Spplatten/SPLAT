using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.QualityIsland.Contracts;

namespace MissionController.Core.QualityIsland.Oracles;

/// <summary>
/// Chains multiple deterministic oracles and computes the aggregate programmatic validity score (X-Axis: [0.0, 1.0]).
/// </summary>
public sealed class CompositeValidationOracle : IValidationOracle
{
    private readonly IReadOnlyList<IValidationOracle> _oracles;

    public CompositeValidationOracle(IEnumerable<IValidationOracle>? oracles = null)
    {
        _oracles = oracles?.ToList() ?? new List<IValidationOracle>
        {
            new StructureIntegrityOracle(),
            new JsonSchemaValidationOracle(),
            new AstCodeValidationOracle()
        };
    }

    public async Task<OracleValidationResult> ValidateAsync(
        string candidateContent,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(candidateContent))
        {
            return OracleValidationResult.Fail("Candidate content is empty.", score: 0.0);
        }

        var allRejections = new List<string>();
        var allRisks = new List<string>();
        var details = new Dictionary<string, string>();
        int passedCount = 0;

        foreach (var oracle in _oracles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var res = await oracle.ValidateAsync(candidateContent, contractType, options, cancellationToken);

            if (res.IsProgrammaticallyValid)
            {
                passedCount++;
            }
            else
            {
                allRejections.AddRange(res.RejectionReasons);
                allRisks.AddRange(res.DetectedRisks);
                if (res.ViolationDetails != null)
                {
                    foreach (var kv in res.ViolationDetails)
                    {
                        details[kv.Key] = kv.Value;
                    }
                }
            }
        }

        if (allRejections.Count > 0)
        {
            double fractionalScore = _oracles.Count > 0 ? (double)passedCount / _oracles.Count : 0.0;
            return new OracleValidationResult(
                IsProgrammaticallyValid: false,
                Score: fractionalScore,
                RejectionReasons: allRejections,
                DetectedRisks: allRisks,
                ViolationDetails: details);
        }

        return OracleValidationResult.Pass();
    }
}
