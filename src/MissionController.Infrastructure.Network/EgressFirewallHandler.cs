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

    /// <summary>
    /// Arms the firewall for the duration of the returned scope and restores the previous policy on
    /// dispose. Prefer this over a bare <see cref="SetActiveAllowedFqdn"/>: an un-restored policy
    /// leaks across awaits into unrelated work on the same async context, where it either blocks a
    /// legitimate call or - worse - keeps a stale host armed after the request it was meant for.
    /// </summary>
    public IDisposable BeginScope(string allowedFqdn)
    {
        var previous = _currentAllowedFqdn.Value;
        _currentAllowedFqdn.Value = allowedFqdn;
        return new EgressScope(this, previous);
    }

    private sealed class EgressScope : IDisposable
    {
        private readonly EgressFirewallHandler _owner;
        private readonly string? _previous;
        private bool _disposed;

        public EgressScope(EgressFirewallHandler owner, string? previous)
        {
            _owner = owner;
            _previous = previous;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _owner._currentAllowedFqdn.Value = _previous;
        }
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
        // DENY BY DEFAULT. This previously validated only when a policy happened to be armed, which
        // meant every caller that forgot to arm one - the SIEM forwarder, both OAuth token services -
        // sent through the "hardened" client completely unchecked. A firewall that inspects traffic
        // only when asked is not a firewall, so an unarmed request is now a blocked request.
        string? allowedFqdn = _currentAllowedFqdn.Value;

        if (request.RequestUri is null)
        {
            throw new SecurityException(
                "Outbound request BLOCKED by In-Memory Egress Firewall: request has no target URI to validate.");
        }

        if (allowedFqdn is null)
        {
            throw new SecurityException(
                $"Outbound request to '{request.RequestUri.Host}' BLOCKED by In-Memory Egress Firewall: " +
                "no egress policy is active on this call path. Wrap the call in BeginScope(allowedFqdn) " +
                "so the permitted destination is declared before the request leaves the process.");
        }

        ValidateOutboundTarget(request.RequestUri, allowedFqdn);

        return await base.SendAsync(request, cancellationToken);
    }
}
