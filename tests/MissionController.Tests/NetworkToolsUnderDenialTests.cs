using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using Xunit;
using Xunit.Abstractions;

namespace MissionController.Tests;

/// <summary>
/// Network denial runs the tool in an AppContainer with no capabilities, at Low integrity. That
/// takes away more than the network: the ICMP handle `ping` needs, the RPC `netsh`, `tasklist` and
/// the Net* cmdlets need, and the registry reads a policy audit needs. `ToolNeedsLocalSubsystems`
/// exempts a template from denial by matching a few cmdlet names in its command line, and this is
/// the test that measures what that text match misses.
///
/// Every network-denied template's own bound command line is run twice - inside the container the
/// engine would give it, and outside, same jail and same restricted token, the container flag the
/// only variable - and the ids whose answer changed are pinned below.
///
/// **21 of 33, measured 2026-09-20, and that is a floor.** Three return nothing at all and exit 0,
/// which a model reads as findings. The criterion here only catches an error phrase or a halving of
/// the evidence, so a template that answers confidently and wrongly counts as "same":
/// `sysops-ad-dc-health` resolves its DC to 127.0.0.1 in the container and to the real server
/// outside it, and is not in this list.
///
/// The list is pinned rather than asserted empty because emptying it is a catalog decision, not a
/// test fix. What this guards is the pretence: nobody can now add a template to the denied census
/// without this saying whether the agent still works in there.
/// </summary>
public class NetworkToolsUnderDenialTests
{
    private readonly ITestOutputHelper _out;

    public NetworkToolsUnderDenialTests(ITestOutputHelper output) => _out = output;

    /// <summary>Measured twice on 2026-09-20, identical both times.</summary>
    private static readonly string[] AnswersDifferentlyInsideTheContainer =
    {
        "campus-dns-cache-hygiene",
        "campus-subnet-latency-sweep",
        "campus-switchport-neighbor",
        "compliance-audit-policy",
        "compliance-powershell-logging",
        "compliance-security-baseline",
        "endpoint-firewall-audit",
        "identity-ad-group-hygiene",
        "identity-gpo-rsop",
        "identity-local-admin-drift",
        "net-dns-audit",
        "network-adapter-dhcp",
        "network-path-mtu-route",
        "network-port-exhaustion",
        "network-proxy-config",
        "network-smb-posture",
        "network-wifi-8021x",
        "secops-process-scan",
        "sysops-software-inventory",
        "sysops-time-sync",
        "web-autonomous-site-deploy",
    };

    private static readonly string[] Errors =
    {
        "Unable to contact IP driver", "General failure", "Access is denied", "The RPC server is unavailable",
        "command was not found", "was not found", "cannot find", "is not recognized", "Exception",
    };

    [Fact]
    public async Task TheDeniedCensus_SaysWhichOfItsTemplatesStillWorkInThere()
    {
        var denied = GovernedTemplateCatalog.All
            .Where(t => !t.EgressRule.ToolProcessNeedsNetwork && !t.ToolNeedsLocalSubsystems)
            .OrderBy(t => t.TemplateId, StringComparer.Ordinal)
            .ToList();

        // Four at a time, each in its own jail. This is the slowest test in the suite - about two
        // minutes, most of it one template's tracert, which runs twice because the comparison is
        // the whole point. Raising the concurrency does not help; capping the timeouts would
        // measure the cap instead of the container. The cost is the price of the claim.
        var findings = new System.Collections.Concurrent.ConcurrentBag<(string Id, string Why, string Line, string Contained)>();
        var jails = new NtAclJailManager();
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        using var gate = new SemaphoreSlim(4);

        await Task.WhenAll(denied.Select(async template =>
        {
            await gate.WaitAsync();
            try
            {
                string arguments = GovernedArgumentBinder.Bind(template, new Dictionary<string, string>());
                var missionId = Guid.NewGuid();
                string jail = await jails.ProvisionJailAsync(missionId);
                try
                {
                    using var inside = new Win32JobSandbox($"Denied_{missionId:N}");
                    var contained = await launcher.LaunchSuspendedInJobAsync(
                        template.Tool.ExecutablePath, arguments, jail, inside,
                        template.Tool.RequiresRestrictedToken, template.Tool.TimeoutSeconds, denyNetworkAccess: true);

                    using var outside = new Win32JobSandbox($"Open_{missionId:N}");
                    var uncontained = await launcher.LaunchSuspendedInJobAsync(
                        template.Tool.ExecutablePath, arguments, jail, outside,
                        template.Tool.RequiresRestrictedToken, template.Tool.TimeoutSeconds, denyNetworkAccess: false);

                    string a = Payload(contained.StandardOutput + contained.StandardError);
                    string b = Payload(uncontained.StandardOutput + uncontained.StandardError);

                    // Two ways the container changes the answer: the tool says something it
                    // otherwise would not, or it says much less than it otherwise would.
                    bool spoke = Errors.Any(e => a.Contains(e, StringComparison.OrdinalIgnoreCase)
                                                 && !b.Contains(e, StringComparison.OrdinalIgnoreCase));
                    bool silenced = b.Length > 60 && a.Length < b.Length / 2;

                    if (spoke || silenced)
                    {
                        findings.Add((template.TemplateId, spoke ? "error" : "silenced",
                            $"exit {contained.ExitCode,3}/{uncontained.ExitCode,-3} evidence {a.Length,6}/{b.Length,-6}",
                            Trim(a)));
                    }
                }
                finally
                {
                    await jails.DrainAndCleanupJailAsync(jail);
                }
            }
            finally
            {
                gate.Release();
            }
        }));

        var broken = findings.Select(f => f.Id).OrderBy(s => s, StringComparer.Ordinal).ToList();
        foreach (var f in findings.OrderBy(f => f.Id, StringComparer.Ordinal))
        {
            _out.WriteLine($"{f.Id,-34} {f.Why,-9} {f.Line}");
            _out.WriteLine($"    contained: {f.Contained}");
        }

        _out.WriteLine($"{broken.Count} of {denied.Count} network-denied templates answer differently inside the container.");

        Assert.Equal(AnswersDifferentlyInsideTheContainer.OrderBy(s => s, StringComparer.Ordinal), broken);
    }

    /// <summary>The evidence, with the template's own echoed section headers taken out.</summary>
    private static string Payload(string text)
        => Regex.Replace(text, @"---[^-\r\n]*---", " ").Replace("\r", " ").Replace("\n", " ").Trim();

    private static string Trim(string flat)
    {
        while (flat.Contains("  ")) flat = flat.Replace("  ", " ");
        return flat.Length > 200 ? flat[..200] + "…" : flat;
    }
}
