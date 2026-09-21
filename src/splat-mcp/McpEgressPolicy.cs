using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace SplatMcp;

/// <summary>
/// Which IPv4 endpoints a <c>run_command</c> lease may name: the operator's decision, never the caller's.
///
/// The exec half of a run_command lease has been pinned by this server since the request stopped
/// being its own authorization. The network half never was: allowNetwork and allowedEgressIps went
/// from the calling agent into the lease as sent, with 80 and 443 added for every address, so an
/// agent talked into it could name any destination and the kernel would faithfully enforce the lease
/// the agent had written. Now a caller may ask for part of this policy and never for more, and a host
/// with no policy refuses network outright.
///
/// Entries are endpoints - <c>a.b.c.d:port</c> - because that is what the kernel checks. The lease
/// speaks in addresses and ports and installs their cross product, so a grant carries only the ports
/// the operator approved for every address in it: approving A:443 and B:80 must not quietly approve
/// A:80 and B:443 as well.
/// </summary>
public sealed class McpEgressPolicy
{
    private readonly IReadOnlyDictionary<string, SortedSet<uint>> _portsByAddress;

    private McpEgressPolicy(IReadOnlyDictionary<string, SortedSet<uint>> portsByAddress)
    {
        _portsByAddress = portsByAddress;
    }

    /// <summary>No endpoints: every request for network is refused.</summary>
    public static McpEgressPolicy None { get; } = new(new Dictionary<string, SortedSet<uint>>());

    public bool IsEmpty => _portsByAddress.Count == 0;

    /// <summary>
    /// Whether this policy names somewhere to go and no way to look a name up.
    ///
    /// Since the kernel started policing datagrams as well as connections, a leased tool's DNS query
    /// is refused like any other destination - correctly, and surprisingly, because the symptom is a
    /// tool that cannot resolve rather than one that cannot connect. A resolver is an endpoint like
    /// any other and the operator names it or does not; nothing adds one on their behalf. This is the
    /// line that tells them, and it is only a note: a policy of raw addresses needs no resolver.
    /// </summary>
    public bool NamesNoResolver => !IsEmpty && !_portsByAddress.Values.Any(ports => ports.Contains(53));

    /// <summary>The approved endpoints, for the startup note an operator reads on stderr.</summary>
    public override string ToString() => string.Join(", ",
        _portsByAddress.OrderBy(entry => entry.Key, StringComparer.Ordinal)
            .SelectMany(entry => entry.Value.Select(port => $"{entry.Key}:{port}")));

    /// <summary>
    /// Parses <c>a.b.c.d:port</c> endpoints separated by commas, semicolons or whitespace. A malformed
    /// entry refuses the whole list: a policy that is half understood is not a policy. So does a list
    /// that names nothing, which is what a config whose value went missing looks like; no network is
    /// asked for by giving no list, never by giving an empty one.
    /// </summary>
    public static McpEgressPolicy Parse(string spec)
    {
        ArgumentNullException.ThrowIfNull(spec);

        var portsByAddress = new Dictionary<string, SortedSet<uint>>(StringComparer.Ordinal);
        foreach (string entry in spec.Split(new[] { ',', ';', ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            int colon = entry.LastIndexOf(':');
            if (colon <= 0 || !TryCanonicalIpv4(entry[..colon], out string address))
            {
                throw new FormatException($"'{entry}' is not an IPv4 endpoint. Write each one as a.b.c.d:port, four decimal octets with no leading zeros.");
            }

            if (!uint.TryParse(entry[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out uint port)
                || port is 0 or > 65535)
            {
                throw new FormatException($"'{entry}' does not name a port from 1 to 65535.");
            }

            if (!portsByAddress.TryGetValue(address, out var ports))
            {
                portsByAddress[address] = ports = new SortedSet<uint>();
            }

            ports.Add(port);
        }

        if (portsByAddress.Count == 0)
        {
            throw new FormatException("the list names no endpoints. Write each one as a.b.c.d:port.");
        }

        return new McpEgressPolicy(portsByAddress);
    }

    /// <summary>
    /// What a request for network is granted, or why it is refused. An empty request means "what the
    /// operator allows": every approved address, on the ports they all share.
    /// </summary>
    public EgressDecision Authorize(IReadOnlyList<string> requestedAddresses)
    {
        ArgumentNullException.ThrowIfNull(requestedAddresses);

        if (IsEmpty)
        {
            return EgressDecision.Refused(
                "this host has no operator egress policy, so a request for network is refused. Which " +
                "endpoints a leased command may reach is the operator's decision, not the caller's.");
        }

        var addresses = new List<string>();
        if (requestedAddresses.Count == 0)
        {
            addresses.AddRange(_portsByAddress.Keys.OrderBy(a => a, StringComparer.Ordinal));
        }
        else
        {
            var outside = new List<string>();
            foreach (string requested in requestedAddresses)
            {
                if (TryCanonicalIpv4(requested.Trim(), out string address) && _portsByAddress.ContainsKey(address))
                {
                    if (!addresses.Contains(address))
                    {
                        addresses.Add(address);
                    }
                }
                else
                {
                    outside.Add(requested);
                }
            }

            if (outside.Count > 0)
            {
                return EgressDecision.Refused(
                    $"{string.Join(", ", outside)} {(outside.Count == 1 ? "is" : "are")} not in this host's egress policy.");
            }
        }

        IEnumerable<uint> shared = _portsByAddress[addresses[0]];
        foreach (string address in addresses.Skip(1))
        {
            shared = shared.Intersect(_portsByAddress[address]);
        }

        var ports = shared.OrderBy(p => p).ToList();
        if (ports.Count == 0)
        {
            return EgressDecision.Refused(
                $"the policy approves no single port for all of {string.Join(", ", addresses)}, and a lease " +
                "grants every address it names on every port it names. Request them separately.");
        }

        return new EgressDecision(addresses, ports, null);
    }

    /// <summary>
    /// Four decimal octets and nothing else. IPAddress.TryParse would also accept "1" as 0.0.0.1 and
    /// read a leading zero as octal - spellings under which an operator's list would not mean what it
    /// appears to say.
    /// </summary>
    private static bool TryCanonicalIpv4(string text, out string address)
    {
        address = string.Empty;
        string[] parts = text.Split('.');
        if (parts.Length != 4)
        {
            return false;
        }

        var octets = new int[4];
        for (int i = 0; i < 4; i++)
        {
            string part = parts[i];
            if (part.Length is 0 or > 3 || (part.Length > 1 && part[0] == '0') || !part.All(char.IsAsciiDigit))
            {
                return false;
            }

            octets[i] = int.Parse(part, CultureInfo.InvariantCulture);
            if (octets[i] > 255)
            {
                return false;
            }
        }

        address = string.Join('.', octets);
        return true;
    }
}

/// <summary>The addresses and ports one lease may name, or the reason it may name none.</summary>
public sealed record EgressDecision(IReadOnlyList<string> Addresses, IReadOnlyList<uint> Ports, string? Refusal)
{
    public static EgressDecision Refused(string reason) => new(Array.Empty<string>(), Array.Empty<uint>(), reason);
}
