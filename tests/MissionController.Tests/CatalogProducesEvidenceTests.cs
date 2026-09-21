using System;
using System.Collections.Concurrent;
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
/// The question the suite never asked: does a template's tool produce evidence at all? Every other
/// test here checks what the tool is contained by. This one runs each of the 49 with its own default
/// parameters, outside the container, with the restricted token and jail a mission gives it, and
/// looks at what comes back.
/// </summary>
public class CatalogProducesEvidenceTests
{
    private readonly ITestOutputHelper _out;

    public CatalogProducesEvidenceTests(ITestOutputHelper output) => _out = output;

    /// <summary>A tool that answered with one of these produced no evidence, whatever it exited with.</summary>
    private static readonly string[] NotEvidence =
    {
        "is not recognized as an internal or external command",
        "The term '", "CommandNotFoundException",
        "Failed to open event query",
        "Access is denied",
        "The following command was not found",
        "Usage:", "usage:",
        "The system cannot find the file specified",
    };

    [Fact]
    public async Task EveryTemplate_IsRunOnceOutsideTheContainer_AndSaysWhetherItProducedEvidence()
    {
        var all = GovernedTemplateCatalog.All.OrderBy(t => t.TemplateId, StringComparer.Ordinal).ToList();
        var rows = new ConcurrentBag<(string Id, string Verdict, int Exit, int Chars, string Head)>();
        var jails = new NtAclJailManager();
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        using var gate = new SemaphoreSlim(4);

        await Task.WhenAll(all.Select(async template =>
        {
            await gate.WaitAsync();
            try
            {
                string arguments = GovernedArgumentBinder.Bind(template, new Dictionary<string, string>());
                var missionId = Guid.NewGuid();
                string jail = await jails.ProvisionJailAsync(missionId);
                try
                {
                    using var job = new Win32JobSandbox($"Evidence_{missionId:N}");
                    var run = await launcher.LaunchSuspendedInJobAsync(
                        template.Tool.ExecutablePath, arguments, jail, job,
                        template.Tool.RequiresRestrictedToken, template.Tool.TimeoutSeconds,
                        denyNetworkAccess: false);

                    string text = Payload(run.StandardOutput + run.StandardError);
                    bool exitOk = template.Tool.AllowedExitCodes.Contains(run.ExitCode);
                    string? refusal = NotEvidence.FirstOrDefault(n => text.Contains(n, StringComparison.Ordinal));

                    string verdict =
                        text.Length < 40 ? "EMPTY" :
                        refusal is not null ? "NO EVIDENCE" :
                        !exitOk ? "EXIT OUTSIDE CONTRACT" :
                        "evidence";

                    rows.Add((template.TemplateId, verdict, run.ExitCode, text.Length, Trim(text)));
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

        foreach (var r in rows.OrderBy(r => r.Verdict, StringComparer.Ordinal).ThenBy(r => r.Id, StringComparer.Ordinal))
        {
            _out.WriteLine($"{r.Verdict,-22} {r.Id,-36} exit {r.Exit,4} {r.Chars,7} chars");
            if (r.Verdict != "evidence") _out.WriteLine($"      {r.Head}");
        }

        var bad = rows.Where(r => r.Verdict != "evidence").Select(r => r.Id).OrderBy(s => s, StringComparer.Ordinal).ToList();
        _out.WriteLine("");
        _out.WriteLine($"{bad.Count} of {all.Count} produced no usable evidence: {string.Join(",", bad)}");

        Assert.Equal(ProduceNoEvidence.OrderBy(s => s, StringComparer.Ordinal), bad);
    }

    /// <summary>
    /// Measured 2026-09-21. Pinned rather than asserted empty, because each of these is a template
    /// to rewrite or retire and that is content work, not a test fix. The list can only shrink
    /// without someone editing this file, which is the point.
    ///
    /// Two call `wmic`, which Windows 11 has removed. One passes `klist` arguments it answers with
    /// its usage text. Three want rights the restricted token deliberately removes - the Security
    /// event log and `gpresult` need elevation - so those templates ask the tier for something it
    /// is built not to give. One returns good evidence and exits outside its own contract.
    /// </summary>
    private static readonly string[] ProduceNoEvidence =
    {
        "campus-switchport-neighbor",
        "compliance-security-baseline",
        "identity-gpo-rsop",
        "identity-kerberos-spn",
        "identity-lockout-trace",
        "secops-auth-inspector",
        "secops-process-scan",
        "sysops-disk-space",
    };

    private static string Payload(string text)
        => Regex.Replace(text, @"---[^-\r\n]*---", " ").Replace("\r", " ").Replace("\n", " ").Trim();

    private static string Trim(string flat)
    {
        while (flat.Contains("  ")) flat = flat.Replace("  ", " ");
        return flat.Length > 160 ? flat[..160] + "…" : flat;
    }
}
