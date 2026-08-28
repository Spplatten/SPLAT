using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using MissionController.Core.Enums;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;

namespace MissionController.Infrastructure.Data.Templates;

public sealed class SqliteTemplateRegistry : ITemplateRegistry
{
    private readonly SqliteStorageContext _context;

    public SqliteTemplateRegistry(SqliteStorageContext context)
    {
        _context = context;
        InitializeDefaultCatalogAsync().GetAwaiter().GetResult();
    }

    private async Task InitializeDefaultCatalogAsync()
    {
        // Seed the reviewable catalog on every startup so upgrades replace the obsolete seed set
        // while user-authored templates remain intact under their own TemplateId values.
        foreach (var template in GovernedTemplateCatalog.All)
        {
            await RegisterTemplateAsync(template);
        }
    }

    public async Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT TemplateJson FROM Templates ORDER BY Category, Name";

        var list = new List<SingleToolTemplate>();
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var json = reader.GetString(0);
            var template = JsonSerializer.Deserialize<SingleToolTemplate>(json);
            if (template != null)
                list.Add(template);
        }

        return list;
    }

    public async Task<SingleToolTemplate?> GetTemplateByIdAsync(string templateId, CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT TemplateJson FROM Templates WHERE TemplateId = @id";
        command.Parameters.AddWithValue("@id", templateId);

        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (await reader.ReadAsync(cancellationToken))
        {
            var json = reader.GetString(0);
            return JsonSerializer.Deserialize<SingleToolTemplate>(json);
        }

        return null;
    }

    public async Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default)
    {
        template.ValidateStrictRules();

        using var connection = _context.CreateConnection();

        var command = connection.CreateCommand();
        command.CommandText = @"
            INSERT INTO Templates (TemplateId, Name, Category, TemplateJson)
            VALUES (@id, @name, @category, @json)
            ON CONFLICT(TemplateId) DO UPDATE SET
                Name = excluded.Name,
                Category = excluded.Category,
                TemplateJson = excluded.TemplateJson";

        command.Parameters.AddWithValue("@id", template.TemplateId);
        command.Parameters.AddWithValue("@name", template.Name);
        command.Parameters.AddWithValue("@category", template.Category);
        command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(template));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
