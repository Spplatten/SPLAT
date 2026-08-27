using System;
using System.Net.Http;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core.Interfaces;

namespace MissionController.Infrastructure.Network.Egress;

public sealed class EgressFirewallHandler : DelegatingHandler, IEgressFirewall
{
    private readonly AsyncLocal<string?> _currentAllowedFqdn = new();

    public void SetActiveAllowedFqdn(string allowedFqdn)
    {
        _currentAllowedFqdn.Value = allowedFqdn;
    }

    public void ClearActiveAllowedFqdn()
    {
        _currentAllowedFqdn.Value = null;
    }

    public void ValidateOutboundTarget(Uri requestUri, string expectedFqdn)
    {
        if (string.IsNullOrWhiteSpace(expectedFqdn))
        {
            throw new SecurityException("Outbound request blocked by Egress Firewall: No approved FQDN configured.");
        }

        if (!string.Equals(requestUri.Host, expectedFqdn, StringComparison.OrdinalIgnoreCase))
        {
            throw new SecurityException($"Outbound request to '{requestUri.Host}' BLOCKED by In-Memory Egress Firewall. Active template strictly permits egress ONLY to '{expectedFqdn}'.");
        }
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri != null && _currentAllowedFqdn.Value != null)
        {
            ValidateOutboundTarget(request.RequestUri, _currentAllowedFqdn.Value);
        }

        return await base.SendAsync(request, cancellationToken);
    }
}
