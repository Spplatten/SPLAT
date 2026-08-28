using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;

namespace MissionController.Infrastructure.Data;

public sealed class SqliteProjectTemplateRegistry : IProjectTemplateRegistry
{
    private readonly SqliteStorageContext _context;

    public SqliteProjectTemplateRegistry(SqliteStorageContext context)
    {
        _context = context;
        InitializeDefaultProjectsAsync().GetAwaiter().GetResult();
    }

    private async Task InitializeDefaultProjectsAsync()
    {
        foreach (var project in GovernedProjectCatalog.All)
        {
            await RegisterProjectTemplateAsync(project);
        }
    }

    public async Task<IReadOnlyList<ProjectTemplate>> GetAllProjectTemplatesAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ProjectJson FROM ProjectTemplates ORDER BY Category, Name";

        var projects = new List<ProjectTemplate>();
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var project = JsonSerializer.Deserialize<ProjectTemplate>(reader.GetString(0));
            if (project != null)
            {
                projects.Add(project);
            }
        }

        return projects;
    }

    public async Task<ProjectTemplate?> GetProjectTemplateByIdAsync(string projectId, CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ProjectJson FROM ProjectTemplates WHERE ProjectId = @id";
        command.Parameters.AddWithValue("@id", projectId);

        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (await reader.ReadAsync(cancellationToken))
        {
            return JsonSerializer.Deserialize<ProjectTemplate>(reader.GetString(0));
        }

        return null;
    }

    public async Task RegisterProjectTemplateAsync(ProjectTemplate project, CancellationToken cancellationToken = default)
    {
        project.Validate();

        using var connection = _context.CreateConnection();
        using var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO ProjectTemplates (ProjectId, Name, Category, ProjectJson)
            VALUES (@id, @name, @category, @json)
            ON CONFLICT(ProjectId) DO UPDATE SET
                Name = excluded.Name,
                Category = excluded.Category,
                ProjectJson = excluded.ProjectJson";
        command.Parameters.AddWithValue("@id", project.ProjectId);
        command.Parameters.AddWithValue("@name", project.Name);
        command.Parameters.AddWithValue("@category", project.Category);
        command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(project));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
