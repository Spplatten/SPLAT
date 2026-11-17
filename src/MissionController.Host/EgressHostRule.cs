using System;
using System.Globalization;
using System.Linq;
using System.Net;

namespace MissionController.Host;

/// <summary>
/// One hostname the daemon's per-lease egress proxy may carry: an exact name, or every name below a
/// suffix, on one port. Written <c>name</c>, <c>name:port</c>, <c>*.suffix</c> or
/// <c>*.suffix:port</c>; the port defaults to 443.
///
/// This is the second reading of a grammar whose first is <c>HostRule</c> in the daemon's
/// egress_proxy.rs. The daemon's is the one that decides: it checks every request against the
/// ceiling in the guest. This one exists so an operator's typo and a caller's overreach are refused
/// here, with a sentence, before a lease is requested. Where the two ever disagree the daemon wins,
/// and the disagreement is a defect in this file.
/// </summary>
public sealed record EgressHostRule
{
    private EgressHostRule(string name, bool wildcard, int port)
    {
        Name = name;
        Wildcard = wildcard;
        Port = port;
    }

    /// <summary>Lower-case ASCII with no trailing dot. For a wildcard, the part after <c>*.</c></summary>
    public string Name { get; }
    public bool Wildcard { get; }
    public int Port { get; }

    public static bool TryParse(string entry, out EgressHostRule rule)
    {
        rule = null!;
        string host = entry;
        int port = 443;
        int colon = entry.LastIndexOf(':');
        if (colon >= 0)
        {
            if (!int.TryParse(entry[(colon + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port is 0 or > 65535)
            {
                return false;
            }

            host = entry[..colon];
        }

        bool wildcard = host.StartsWith("*.", StringComparison.Ordinal);
        string name = wildcard ? host[2..] : host;
        if (!IsHostname(name))
        {
            return false;
        }

        rule = new EgressHostRule(name, wildcard, port);
        return true;
    }

    /// <summary>Whether everything <paramref name="inner"/> admits, this rule admits too.</summary>
    public bool Covers(EgressHostRule inner)
    {
        if (inner.Port != Port)
        {
            return false;
        }

        if (!Wildcard)
        {
            return !inner.Wildcard && inner.Name == Name;
        }

        // Whole labels below the suffix: *.example.com covers a.example.com and *.cdn.example.com,
        // never example.com itself and never badexample.com.
        return (inner.Wildcard && inner.Name == Name) || inner.Name.EndsWith("." + Name, StringComparison.Ordinal);
    }

    public override string ToString() => $"{(Wildcard ? "*." : string.Empty)}{Name}:{Port.ToString(CultureInfo.InvariantCulture)}";

    /// <summary>
    /// Letters, digits and hyphens in dot-separated labels, at least two of them, and not an address:
    /// a pinned address has its own, older, vocabulary. An all-digit last label is how 1.2.3 and
    /// 0x7f.1 reach a resolver as addresses, so it is refused as well.
    /// </summary>
    private static bool IsHostname(string name)
    {
        if (name.Length is 0 or > 253 || !name.Contains('.') || IPAddress.TryParse(name, out _))
        {
            return false;
        }

        string[] labels = name.Split('.');
        return labels.All(label => label.Length is > 0 and <= 63 && label[0] != '-' && label[^1] != '-'
                && label.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'))
            && !labels[^1].All(char.IsAsciiDigit);
    }
}
