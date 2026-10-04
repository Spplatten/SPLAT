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
        // Blocking on async work in a constructor is a deadlock shape wherever a single-threaded
        // SynchronizationContext exists - and this type IS resolved on the WinUI UI thread, via the
        // MainWindow constructor. It survives today only because Microsoft.Data.Sqlite has no true
        // async I/O: its *Async methods return completed tasks, so the awaits below never post a
        // continuation back to the blocked thread. That is a property of the provider, not of this
        // code, so the awaits are ConfigureAwait(false) - the seeding stays correct if the store is
        // ever swapped for one that really yields.
        InitializeDefaultCatalogAsync().GetAwaiter().GetResult();
    }

    private async Task InitializeDefaultCatalogAsync()
    {
        // Refresh active seeds without erasing historical or user-authored rows. Retirement is
        // checked on every read and save, so an obsolete seed retained here cannot still run.
        foreach (var template in GovernedTemplateCatalog.All)
        {
            await RegisterTemplateAsync(template).ConfigureAwait(false);
        }
    }

    public async Task<IReadOnlyList<SingleToolTemplate>> GetAllTemplatesAsync(CancellationToken cancellationToken = default)
    {
        using var connection = _context.CreateConnection();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT TemplateJson FROM Templates ORDER BY Category, Name";

        var list = new List<SingleToolTemplate>();
        var rejected = new List<string>();
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var json = reader.GetString(0);
            var template = JsonSerializer.Deserialize<SingleToolTemplate>(json);
            if (template is null)
                continue;

            // A derived row whose containment no longer matches its base is withheld from the list
            // rather than repaired, so it cannot be selected and launched. Withheld, not silently
            // dropped: the reason is kept for the catalog page to show, because a template that
            // vanishes with no explanation is indistinguishable from one the operator never saved.
            if (DerivedTemplateGuard.Problem(template) is { } problem)
            {
                rejected.Add(problem);
                continue;
            }

            list.Add(template);
        }

        WithheldOnLastLoad = rejected;
        return list;
    }

    /// <summary>
    /// Why any stored template was withheld from the most recent <see cref="GetAllTemplatesAsync"/>.
    /// Empty on a clean load, which is the normal case.
    /// </summary>
    public IReadOnlyList<string> WithheldOnLastLoad { get; private set; } = Array.Empty<string>();

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
            var template = JsonSerializer.Deserialize<SingleToolTemplate>(json);

            // This is the read a mission launches from, so a drifted row throws here rather than
            // being withheld: the caller asked for this exact agent by id and must not be handed
            // null, which reads as "no such agent" and hides that one exists and was refused.
            if (template is not null)
            {
                DerivedTemplateGuard.Validate(template);
            }

            return template;
        }

        return null;
    }

    public async Task RegisterTemplateAsync(SingleToolTemplate template, CancellationToken cancellationToken = default)
    {
        template.ValidateStrictRules();

        // Refused at the door as well as on the way out. ValidateStrictRules asks only that a tool is
        // bound; this asks whether a derived agent still runs its base's tool.
        DerivedTemplateGuard.Validate(template);

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
