using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace MissionController.Infrastructure.Data.Catalog;

public sealed record AgentManifestApproval(string AgentId, string Sha256, CompiledAgentManifest Manifest)
{
    public static string AgentIdOf(CompiledAgentManifest manifest) => manifest.Project.ProjectId["project-agent-".Length..];

    public static string Hash(CompiledAgentManifest manifest) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(manifest))));

    public static void ValidateSelection(string agentId, string sha256)
    {
        if (agentId is null || agentId.Length > 48
            || !Regex.IsMatch(agentId, "\\A[a-z][a-z0-9]*(?:-[a-z0-9]+)*\\z")
            || sha256 is null || !Regex.IsMatch(sha256, "\\A[0-9a-f]{64}\\z"))
            throw new InvalidOperationException("Select an agent ID and its approved lowercase SHA-256 contract version.");
    }
}
