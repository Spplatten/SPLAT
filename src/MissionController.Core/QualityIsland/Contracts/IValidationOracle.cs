using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core.QualityIsland.Contracts;

/// <summary>
/// Deterministic Programmatic Oracle (X-Axis: [0.0, 1.0]).
/// Assesses whether a generated artifact strictly complies with AST rules, JSON schemas,
/// syntax bounds, and non-corruption guarantees without circular LLM bias.
/// </summary>
public interface IValidationOracle
{
    /// <summary>
    /// Evaluates programmatic validity of the candidate output.
    /// </summary>
    Task<OracleValidationResult> ValidateAsync(
        string candidateContent,
        SchemaContractType contractType,
        QualityIslandOptions options,
        CancellationToken cancellationToken = default);
}
