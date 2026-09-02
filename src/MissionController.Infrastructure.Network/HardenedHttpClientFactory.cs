using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using MissionController.Infrastructure.Network.Egress;

namespace MissionController.Infrastructure.Network.Http;

public static class HardenedHttpClientFactory
{
    public static (HttpClient HttpClient, EgressFirewallHandler Firewall) CreateHardenedClient()
    {
        // CRITICAL HARDENING FIX 3: SocketsHttpHandler configured for Windows SChannel, Online CRL & Proxy
        var socketsHandler = new SocketsHttpHandler
        {
            // Auto-redirect is handled INSIDE this handler, which sits below the egress firewall in
            // the pipeline - so a 302 from an approved FQDN to any other host was fetched without
            // ever re-entering EgressFirewallHandler.SendAsync. The strict allow-list held for the
            // first request only. Redirects must surface to the caller as a 3xx response instead,
            // so that following one means issuing a new request the firewall gets to validate.
            AllowAutoRedirect = false,
            UseProxy = true,
            DefaultProxyCredentials = CredentialCache.DefaultNetworkCredentials,
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode = X509RevocationMode.Online,
                EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
            },
            PooledConnectionLifetime = TimeSpan.FromMinutes(15),
            PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
            EnableMultipleHttp2Connections = true
        };

        var firewallHandler = new EgressFirewallHandler
        {
            InnerHandler = socketsHandler
        };

        var client = new HttpClient(firewallHandler)
        {
            Timeout = TimeSpan.FromSeconds(120)
        };

        return (client, firewallHandler);
    }
}
