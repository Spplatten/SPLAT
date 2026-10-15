using System.Text.Json;
using MissionController.Core;
using MissionController.Core.Interfaces;
using MissionController.Infrastructure.Linux;
using MissionController.Infrastructure.Network.Dlp;

namespace SplatMcp;

public partial class McpServerHandler
{
    private McpJsonRpcMessage ListAgentTools(McpJsonRpcMessage request)
    {
        var tools = _agent!.Manifest.Project.Stages.Select(stage =>
        {
            var template = _agent.Manifest.Templates.Single(t => t.TemplateId == stage.TemplateId);
            return new McpToolDefinition
            {
                Name = stage.StageId,
                Description = template.Description,
                InputSchema = JsonSerializer.SerializeToElement(new
                {
                    type = "object", additionalProperties = false,
                    properties = new
                    {
                        parameters = new
                        {
                            type = "object", additionalProperties = false,
                            properties = template.ParameterFields.ToDictionary(f => f.Key,
                                f => new { type = "string", description = f.Description }),
                        },
                        traceId = new { type = "string" }, clientName = new { type = "string" }
                    }
                })
            };
        }).ToArray();
        return new McpJsonRpcMessage { JsonRpc = "2.0", Id = request.Id,
            Result = JsonSerializer.SerializeToElement(new { tools,
                agent = new { id = _agent.AgentId, version = _agent.Sha256 } }) };
    }

    private async Task<McpToolCallResult> ExecuteAgentToolAsync(string name, JsonElement args,
        string actor, CancellationToken ct)
    {
        var mission = Guid.NewGuid();
        var binding = _agent!.Manifest.Project.Stages.SingleOrDefault(s => s.StageId == name);
        var authority = new { agentId = _agent.AgentId, contractSha256 = _agent.Sha256,
            tool = name, templateId = binding?.TemplateId, missionId = mission };
        try
        {
            if (binding is null)
                throw new InvalidOperationException("This tool is outside the host's approved agent manifest.");
            var template = _agent.Manifest.Templates.Single(t => t.TemplateId == binding.TemplateId);
            if (args.ValueKind == JsonValueKind.Undefined)
                args = JsonSerializer.SerializeToElement(new { });
            if (args.ValueKind != JsonValueKind.Object)
                throw new InvalidOperationException("Tool arguments must be an object.");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in args.EnumerateObject())
                if (!seen.Add(field.Name) || field.Name is not ("parameters" or "traceId" or "clientName")
                    || (field.Name != "parameters" && field.Value.ValueKind != JsonValueKind.String))
                    throw new InvalidOperationException("Only declared parameters and trace metadata are accepted; execution authority is fixed by the host.");
            var parameters = new Dictionary<string, string>(StringComparer.Ordinal);
            if (args.TryGetProperty("parameters", out var values))
            {
                if (values.ValueKind != JsonValueKind.Object)
                    throw new InvalidOperationException("parameters must be an object of declared string values.");
                foreach (var field in values.EnumerateObject())
                    if (!template.ParameterFields.Any(f => f.Key == field.Name)
                        || field.Value.ValueKind != JsonValueKind.String
                        || !parameters.TryAdd(field.Name, field.Value.GetString()!))
                        throw new InvalidOperationException("An unknown, duplicate or non-string template parameter was refused.");
            }
            foreach (var field in template.ParameterFields.Where(f => f.IsRequired))
                if (string.IsNullOrWhiteSpace(parameters.GetValueOrDefault(field.Key, field.DefaultValue)))
                    throw new InvalidOperationException($"Required parameter '{field.Key}' is missing.");
            var argv = PosixArgumentSplitter.Split(GovernedArgumentBinder.Bind(template, parameters));
            var lease = _policyCompiler.CompileTemplatePolicy(template, mission,
                $"{LinuxLeaseSubstrate.DefaultMissionsRoot}/{mission:N}", (uint)template.Tool.TimeoutSeconds);
            lease = lease with { RequireEnforcing = true };
            if (template.Tool.PassLeaseEgressAsArguments)
            {
                if (!lease.AllowNetwork || lease.AllowedEgressIps.Count == 0
                    || !lease.AllowedEgressPorts.SequenceEqual(new uint[] { 443 }))
                    throw new InvalidOperationException("The approved HTTPS sensor requires resolved lease destinations on port 443.");
                argv = argv.Append(string.Join(",", lease.AllowedEgressIps)).ToArray();
            }
            // Admission is durable before any effect and includes the exact operator-selected version.
            await AppendScrubbedLogAsync(mission, template.TemplateId, "AGENT_TOOL_AUTHORIZED",
                JsonSerializer.Serialize(authority), actor, ct);
            var execution = JsonSerializer.SerializeToElement(new
            {
                command = template.Tool.ExecutablePath, args = argv,
                workingDirectory = lease.WorkingDirectory, allowNetwork = lease.AllowNetwork,
                timeoutSeconds = lease.LeaseDurationSeconds
            });
            var result = await ExecuteRunCommandAsync(execution, ct, name, lease);
            result.Content.Add(new McpContentItem { Type = "text",
                Text = JsonSerializer.Serialize(new { agentContract = authority }) });
            return result;
        }
        catch (Exception ex) when (ex is InvalidOperationException or TemplateParameterRejectedException
            or PolicyCompilationException or FormatException)
        {
            await AppendScrubbedLogAsync(mission, binding?.TemplateId ?? "agent-manifest", "AGENT_TOOL_REFUSED",
                JsonSerializer.Serialize(authority) + " " + ex.Message, actor, ct);
            return new McpToolCallResult { IsError = true, Content = new List<McpContentItem>
            {
                new() { Type = "text", Text = "[SPLAT POLICY] " + Scrub(ex.Message) },
                new() { Type = "text", Text = JsonSerializer.Serialize(new { agentContract = authority }) }
            } };
        }
    }
}
