using System.Text.Json;
using MissionController.Core.Interfaces;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Linux;

public static class LeaseEgressArguments
{
    public static IReadOnlyList<string> Append(SingleToolDefinition tool, LeaseSpec lease, IReadOnlyList<string> argv)
    {
        if (!tool.PassLeaseEgressAsArguments && !tool.PassLeaseHostPinsAsArguments) return argv;
        if (!lease.AllowNetwork || lease.AllowedEgressIps.Count == 0
            || !lease.AllowedEgressPorts.SequenceEqual(new uint[] { 443 }))
            throw new PolicyCompilationException("This HTTPS sensor requires compiled IPv4 destinations on port 443.");
        if (!tool.PassLeaseHostPinsAsArguments)
            return argv.Append(string.Join(",", lease.AllowedEgressIps)).ToArray();
        if (lease.ResolvedEgressHosts is not { Count: > 0 } hosts
            || hosts.Any(h => h.Value.Count == 0 || h.Value.Any(ip => !lease.AllowedEgressIps.Contains(ip))))
            throw new PolicyCompilationException("The sensor's host pins must be a subset of the effective lease.");
        return argv.Append(JsonSerializer.Serialize(hosts)).ToArray();
    }
}
