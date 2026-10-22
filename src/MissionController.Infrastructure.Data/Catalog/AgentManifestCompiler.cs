using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public sealed record AgentToolBinding(string Name, string TemplateId, bool AllowNetwork = false,
    ExecutionPolicy? ExecutionPolicy = null);

public sealed record AgentManifest(
    int SchemaVersion,
    string AgentId,
    string Name,
    string Description,
    string Instructions,
    string TargetModel,
    IReadOnlyList<AgentToolBinding> Tools);

public sealed record CompiledAgentManifest(
    ProjectTemplate Project,
    IReadOnlyList<SingleToolTemplate> Templates);

/// <summary>
/// Binds an agent definition to reviewed catalog capabilities. MCP input schemas describe arguments,
/// not executable or filesystem authority; only an explicit catalog binding can supply that authority.
/// See https://modelcontextprotocol.io/specification/2025-11-25/server/tools .
/// Explicit executionPolicy contracts add Landlock file grants and generated seccomp filters at
/// launch. Tool names and MCP schemas still cannot establish a complete syscall contract.
/// Evidence: AgentManifestCompilerTests exercises compilation through the lease compiler and registry.
/// </summary>
public static class AgentManifestCompiler
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16
    };

    public const string ExampleJson = """
        {
          "schemaVersion": 1,
          "agentId": "capacity-reader",
          "name": "Capacity Reader",
          "description": "Review the Linux guest's capacity using observed evidence.",
          "instructions": "Report capacity risks, cite the readings, and mark missing evidence as unknown.",
          "targetModel": "claude-haiku-4-5",
          "tools": [
            { "name": "inspect_disk", "templateId": "linux-disk-usage" },
            { "name": "inspect_memory", "templateId": "linux-guest-identity" }
          ]
        }
        """;

    public static CompiledAgentManifest Compile(string json)
    {
        if (string.IsNullOrWhiteSpace(json) || json.Length > 131072)
            throw new InvalidOperationException("Provide an agent manifest of at most 131,072 characters.");

        AgentManifest manifest;
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            RejectDuplicateProperties(document.RootElement);
            manifest = JsonSerializer.Deserialize<AgentManifest>(json, Options)
                ?? throw new InvalidOperationException("An agent manifest must be a JSON object.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Invalid SPLAT agent manifest: {ex.Message}", ex);
        }

        if (manifest.SchemaVersion != 1)
            throw new InvalidOperationException("Only SPLAT agent manifest schemaVersion 1 is supported.");
        if (manifest.AgentId is null || !Regex.IsMatch(manifest.AgentId, "\\A[a-z][a-z0-9]*(?:-[a-z0-9]+)*\\z")
            || manifest.AgentId.Length > 48)
            throw new InvalidOperationException("agentId must start with a lowercase letter and use at most 48 lowercase letters, digits or single hyphens.");
        if (string.IsNullOrWhiteSpace(manifest.Name) || string.IsNullOrWhiteSpace(manifest.Description)
            || string.IsNullOrWhiteSpace(manifest.Instructions) || string.IsNullOrWhiteSpace(manifest.TargetModel))
            throw new InvalidOperationException("name, description, instructions and targetModel are required.");
        if (manifest.Tools is null || manifest.Tools.Count is < 1 or > 6)
            throw new InvalidOperationException("An agent must bind between 1 and 6 tools, in execution order.");

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var templates = new List<SingleToolTemplate>();
        var stages = new List<ProjectStage>();
        foreach (var binding in manifest.Tools)
        {
            if (binding is null || string.IsNullOrWhiteSpace(binding.Name)
                || !Regex.IsMatch(binding.Name, "\\A[A-Za-z][A-Za-z0-9_.-]{0,63}\\z") || !names.Add(binding.Name))
                throw new InvalidOperationException("Tool names must be unique identifiers of 1 to 64 letters, digits, underscores, dots or hyphens.");

            // Resolve against source, never a database row or the imported tool's descriptive name.
            // A manifest cannot register a new executable by describing it as a harmless reader.
            var source = GovernedTemplateCatalog.All.SingleOrDefault(t => t.TemplateId == binding.TemplateId)
                ?? throw new InvalidOperationException($"Tool '{binding.Name}' needs a current catalog templateId; '{binding.TemplateId}' is not one.");
            if (source.Tool.Substrate != ToolSubstrate.LinuxLease)
                throw new InvalidOperationException($"Tool '{binding.Name}' needs a Linux-lease catalog template. '{source.TemplateId}' runs on Windows.");
            if (source.EgressRule.ToolProcessNeedsNetwork && !binding.AllowNetwork)
                throw new InvalidOperationException($"Tool '{binding.Name}' requires network access to {source.EgressRule.AllowedFqdn}:{source.EgressRule.AllowedPort}. Set allowNetwork to true to accept that catalog capability.");

            // Each tool stays in its own mission and cgroup; combining the agent's tools into one
            // lease would lend a local reader the network authority of a different stage.
            var template = source with
            {
                TemplateId = $"custom-agent-{manifest.AgentId}-{templates.Count + 1}",
                Name = $"{manifest.Name.Trim()}: {binding.Name}",
                Description = manifest.Description.Trim(),
                Category = "Custom Agents",
                TargetModel = manifest.TargetModel.Trim(),
                SystemPrompt = $"{source.SystemPrompt}\n\n[AGENT INSTRUCTIONS]\n{manifest.Instructions.Trim()}",
                Kind = TemplateKind.TaskAgent,
                SourceTemplateId = source.TemplateId,
                IsUserCreated = true,
                Tool = source.Tool with { ExecutionPolicy = binding.ExecutionPolicy ?? source.Tool.ExecutionPolicy },
                AvailableRemediations = Array.Empty<RemediationAction>()
            };
            template.ValidateStrictRules();
            DerivedTemplateGuard.Validate(template);
            templates.Add(template);
            stages.Add(new ProjectStage(binding.Name, binding.Name, template.TemplateId, manifest.Instructions.Trim()));
        }

        var project = new ProjectTemplate(
            $"project-agent-{manifest.AgentId}", manifest.Name.Trim(), manifest.Description.Trim(), "Custom Agents",
            stages.AsReadOnly(), templates.SelectMany(t => t.EffectiveOutputContract.Deliverables).Distinct().ToArray());
        project.Validate();
        return new CompiledAgentManifest(project, templates.AsReadOnly());
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw new InvalidOperationException($"Duplicate manifest property '{property.Name}' is not allowed.");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
                RejectDuplicateProperties(item);
        }
    }
}
