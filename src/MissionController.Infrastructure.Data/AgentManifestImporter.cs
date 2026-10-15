using System.Text.Json;
using Microsoft.Data.Sqlite;
using MissionController.Infrastructure.Data.Catalog;

namespace MissionController.Infrastructure.Data;

public sealed class AgentManifestImporter(SqliteStorageContext context)
{
    public async Task<CompiledAgentManifest> ImportAsync(string json, CancellationToken cancellationToken = default)
    {
        var compiled = AgentManifestCompiler.Compile(json);
        using var connection = context.CreateConnection();
        using var transaction = connection.BeginTransaction();
        try
        {
            // One transaction and insert-only semantics prevent a conflicting import from replacing
            // an existing agent or leaving half an agent's capabilities registered after a refusal.
            foreach (var template in compiled.Templates)
            {
                using var command = connection.CreateCommand();
                command.Transaction = transaction;
                command.CommandText = "INSERT INTO Templates (TemplateId, Name, Category, TemplateJson) VALUES (@id, @name, @category, @json)";
                command.Parameters.AddWithValue("@id", template.TemplateId);
                command.Parameters.AddWithValue("@name", template.Name);
                command.Parameters.AddWithValue("@category", template.Category);
                command.Parameters.AddWithValue("@json", JsonSerializer.Serialize(template));
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            using var projectCommand = connection.CreateCommand();
            projectCommand.Transaction = transaction;
            projectCommand.CommandText = "INSERT INTO ProjectTemplates (ProjectId, Name, Category, ProjectJson) VALUES (@id, @name, @category, @json)";
            projectCommand.Parameters.AddWithValue("@id", compiled.Project.ProjectId);
            projectCommand.Parameters.AddWithValue("@name", compiled.Project.Name);
            projectCommand.Parameters.AddWithValue("@category", compiled.Project.Category);
            projectCommand.Parameters.AddWithValue("@json", JsonSerializer.Serialize(compiled.Project));
            await projectCommand.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            using var approval = connection.CreateCommand();
            approval.Transaction = transaction;
            approval.CommandText = "INSERT INTO AgentManifests (AgentId, ContractSha256, ManifestJson) VALUES (@id, @sha, @json)";
            approval.Parameters.AddWithValue("@id", AgentManifestApproval.AgentIdOf(compiled));
            approval.Parameters.AddWithValue("@sha", AgentManifestApproval.Hash(compiled));
            approval.Parameters.AddWithValue("@json", json);
            await approval.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            transaction.Commit();
            return compiled;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            throw new InvalidOperationException("This agent ID or one of its template IDs already exists. Choose a different agentId; nothing was imported.", ex);
        }
    }

    public async Task<AgentManifestApproval> LoadApprovedAsync(string agentId, string sha256,
        CancellationToken cancellationToken = default)
    {
        AgentManifestApproval.ValidateSelection(agentId, sha256);
        using var connection = context.CreateConnection();
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT ContractSha256, ManifestJson FROM AgentManifests WHERE AgentId = @id";
        command.Parameters.AddWithValue("@id", agentId);
        using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false)
            || !string.Equals(reader.GetString(0), sha256, StringComparison.Ordinal))
            throw new InvalidOperationException("The selected agent and approved contract version are not registered.");
        var compiled = AgentManifestCompiler.Compile(reader.GetString(1));
        reader.Close();
        // Bind the catalog definitions as well as the manifest. A catalog upgrade or mutable registry
        // row must never silently change the executable, arguments, resources or grants approved here.
        if (AgentManifestApproval.AgentIdOf(compiled) != agentId || AgentManifestApproval.Hash(compiled) != sha256)
            throw new InvalidOperationException("The agent contract changed; review and import a new agent version.");
        foreach (var template in compiled.Templates)
        {
            using var saved = connection.CreateCommand();
            saved.Transaction = transaction;
            saved.CommandText = "SELECT TemplateJson FROM Templates WHERE TemplateId = @id";
            saved.Parameters.AddWithValue("@id", template.TemplateId);
            if (await saved.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) is not string stored
                || stored != JsonSerializer.Serialize(template))
                throw new InvalidOperationException("A saved agent template is missing or differs from its approved contract.");
        }
        return new AgentManifestApproval(agentId, sha256, compiled);
    }
}
