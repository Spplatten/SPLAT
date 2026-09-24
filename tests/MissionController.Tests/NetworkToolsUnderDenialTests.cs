using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MissionController.Core;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using MissionController.Infrastructure.Windows.Jails;
using MissionController.Infrastructure.Windows.JobObjects;
using MissionController.Infrastructure.Windows.Process;
using MissionController.Infrastructure.Windows.Security;
using Xunit;
using Xunit.Abstractions;

namespace MissionController.Tests;

/// <summary>
/// The catalog claims, template by template, that denying the network does not change what a tool
/// reports. This runs each claim: the template's own bound command line, inside the container the
/// engine would give it and outside, same jail and same restricted token, the denial flag the only
/// variable.
///
/// It used to pin the opposite - the 21 of 33 templates that a text match had left denied while the
/// container blinded them, three of them returning nothing at all and exiting 0. Those templates
/// now keep their plumbing, and this test guards the claim rather than recording the damage.
///
/// It is the slowest test in the suite, because it runs real processes rather than asserting about
/// them. Capping the timeouts would measure the cap instead of the container.
/// </summary>
public class NetworkToolsUnderDenialTests
{
    private readonly ITestOutputHelper _out;

    public NetworkToolsUnderDenialTests(ITestOutputHelper output) => _out = output;

    /// <summary>What a tool says when the container has taken something away from it.</summary>
    private static readonly string[] Errors =
    {
        "Unable to contact IP driver", "General failure", "Access is denied", "The RPC server is unavailable",
        "command was not found", "was not found", "cannot find", "is not recognized", "Exception",
        // Added 2026-09-21 after sysops-boot-performance passed the coarse test while losing its
        // boot time to this one. Every phrase here was seen in a real contained run.
        "Attempted to perform an unauthorized operation",
        "Requested registry access is not allowed",
        "Object reference not set",
        "System error 5",
    };

    private sealed record Comparison(string Id, bool Changed, string Why, string Inside, string Outside);

    [Fact]
    public async Task EveryTemplateDeniedTheNetwork_AnswersTheSameInsideTheContainerAsOutsideIt()
    {
        var results = await CompareAsync(GovernedTemplateCatalog.All
            // The AppContainer is a Windows question; a tool that runs under the Linux lease never
            // launches here at all.
            .Where(t => t.Tool.Substrate == ToolSubstrate.Windows)
            .Where(t => !t.EgressRule.ToolProcessNeedsNetwork)
            .OrderBy(t => t.TemplateId, StringComparer.Ordinal)
            .ToList());

        var denied = results.Where(r => IsDenied(r.Id)).ToList();
        var changed = denied.Where(r => r.Changed).ToList();

        foreach (var r in changed)
        {
            _out.WriteLine($"{r.Id,-34} {r.Why}");
            _out.WriteLine($"    inside : {r.Inside}");
            _out.WriteLine($"    outside: {r.Outside}");
        }

        // The other direction is reported, never failed. A template that would survive denial and is
        // not claimed is containment left on the table, and worth knowing; but the answer depends on
        // the machine - a desktop with no wireless adapter makes the Wi-Fi template look survivable -
        // so it is not something to fail a build over.
        var couldBeDenied = results.Where(r => !IsDenied(r.Id) && !r.Changed).Select(r => r.Id).ToList();
        _out.WriteLine("");
        _out.WriteLine($"{denied.Count} templates claim denial changes nothing; {changed.Count} of those claims are false.");
        _out.WriteLine($"{couldBeDenied.Count} not claimed would have survived it here: {string.Join(", ", couldBeDenied)}");
        Assert.True(changed.Count == 0,
            "these templates are denied the network and the container changes what they report: " +
            string.Join(", ", changed.Select(c => $"{c.Id} ({c.Why})")));
    }

    private static bool IsDenied(string templateId)
    {
        var template = GovernedTemplateCatalog.All.Single(t => t.TemplateId == templateId);
        return !template.EgressRule.ToolProcessNeedsNetwork && !template.ToolNeedsLocalSubsystems;
    }

    private static async Task<List<Comparison>> CompareAsync(IReadOnlyList<Core.Models.SingleToolTemplate> templates)
    {
        var results = new ConcurrentBag<Comparison>();
        var jails = new NtAclJailManager();
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        using var gate = new SemaphoreSlim(4);

        await Task.WhenAll(templates.Select(async template =>
        {
            await gate.WaitAsync();
            try
            {
                string arguments = GovernedArgumentBinder.Bind(template, new Dictionary<string, string>());
                var missionId = Guid.NewGuid();
                string jail = await jails.ProvisionJailAsync(missionId);
                try
                {
                    using var insideJob = new Win32JobSandbox($"Denied_{missionId:N}");
                    var contained = await launcher.LaunchSuspendedInJobAsync(
                        template.Tool.ExecutablePath, arguments, jail, insideJob,
                        template.Tool.RequiresRestrictedToken, template.Tool.TimeoutSeconds, denyNetworkAccess: true);

                    using var outsideJob = new Win32JobSandbox($"Open_{missionId:N}");
                    var uncontained = await launcher.LaunchSuspendedInJobAsync(
                        template.Tool.ExecutablePath, arguments, jail, outsideJob,
                        template.Tool.RequiresRestrictedToken, template.Tool.TimeoutSeconds, denyNetworkAccess: false);

                    string inside = Payload(contained.StandardOutput + contained.StandardError);
                    string outside = Payload(uncontained.StandardOutput + uncontained.StandardError);

                    // Two ways the container changes the answer: the tool says something it would
                    // not otherwise say, or it says much less than it would otherwise say.
                    string? spoke = Errors.FirstOrDefault(e => inside.Contains(e, StringComparison.OrdinalIgnoreCase)
                                                               && !outside.Contains(e, StringComparison.OrdinalIgnoreCase));
                    bool silenced = outside.Length > 60 && inside.Length < outside.Length / 2;

                    results.Add(new Comparison(
                        template.TemplateId,
                        spoke is not null || silenced,
                        spoke is not null ? $"says \"{spoke}\" only inside" : $"{inside.Length} chars inside against {outside.Length} outside",
                        Trim(inside),
                        Trim(outside)));
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

        return results.OrderBy(r => r.Id, StringComparer.Ordinal).ToList();
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
