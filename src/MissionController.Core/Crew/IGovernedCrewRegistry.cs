using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace MissionController.Core.Crew;

/// <summary>
/// Registry for discovering, registering, and retrieving governed multi-agent crew definitions.
/// </summary>
public interface IGovernedCrewRegistry
{
    Task<IReadOnlyList<GovernedCrewDefinition>> GetAllCrewsAsync(CancellationToken cancellationToken = default);
    Task<GovernedCrewDefinition?> GetCrewByIdAsync(string crewId, CancellationToken cancellationToken = default);
    Task RegisterCrewAsync(GovernedCrewDefinition crew, CancellationToken cancellationToken = default);
    Task<bool> UnregisterCrewAsync(string crewId, CancellationToken cancellationToken = default);
}
