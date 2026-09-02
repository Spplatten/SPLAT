using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Crew;
using MissionController.Infrastructure.Data.Catalog;

namespace MissionController.Infrastructure.Data;

public sealed class SqliteGovernedCrewRegistry : IGovernedCrewRegistry
{
    private readonly SqliteStorageContext _context;

    public SqliteGovernedCrewRegistry(SqliteStorageContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        InitializeDefaultCrewsAsync().GetAwaiter().GetResult();
    }

    private async Task InitializeDefaultCrewsAsync()
    {
        foreach (var crew in GovernedCrewCatalog.All)
        {
            await RegisterCrewAsync(crew);
        }
    }

    public async Task<IReadOnlyList<GovernedCrewDefinition>> GetAllCrewsAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT CrewJson FROM GovernedCrews ORDER BY ProcessType, Name";

        var crews = new List<GovernedCrewDefinition>();
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var crew = JsonSerializer.Deserialize<GovernedCrewDefinition>(reader.GetString(0));
            if (crew != null)
            {
                crews.Add(crew);
            }
        }

        return crews;
    }

    public async Task<GovernedCrewDefinition?> GetCrewByIdAsync(string crewId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(crewId)) return null;

        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT CrewJson FROM GovernedCrews WHERE CrewId = @id";
        command.Parameters.AddWithValue("@id", crewId);

        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (await reader.ReadAsync(cancellationToken))
        {
            return JsonSerializer.Deserialize<GovernedCrewDefinition>(reader.GetString(0));
        }

        return null;
    }

    public async Task RegisterCrewAsync(GovernedCrewDefinition crew, CancellationToken cancellationToken = default)
    {
        crew.Validate();

        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO GovernedCrews (CrewId, Name, ProcessType, CrewJson)
            VALUES (@id, @name, @processType, @json)
            ON CONFLICT(CrewId) DO UPDATE SET
                Name = excluded.Name,
                ProcessType = excluded.ProcessType,
                CrewJson = excluded.CrewJson";
        command.Parameters.AddWithValue("@id", crew.CrewId);
        command.Parameters.AddWithValue("@name", crew.Name);
        command.Parameters.AddWithValue("@processType", crew.ProcessType.ToString());
        command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(crew));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<bool> UnregisterCrewAsync(string crewId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(crewId)) return false;

        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM GovernedCrews WHERE CrewId = @id";
        command.Parameters.AddWithValue("@id", crewId);

        int rows = await command.ExecuteNonQueryAsync(cancellationToken);
        return rows > 0;
    }
}
