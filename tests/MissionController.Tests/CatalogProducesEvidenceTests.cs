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
/// Runs alone. This is the only collection in the suite marked
/// <see cref="CollectionDefinitionAttribute.DisableParallelization"/>, so no other collection runs
/// beside it.
///
/// It is here because the test below spawns every catalog template as a real sandboxed process, and
/// xUnit otherwise runs it alongside every other class - including others that spawn processes. Under
/// that contention individual launches exceed their template's own TimeoutSeconds and the test
/// reports that a tool produced no evidence, which is indistinguishable from a catalog defect and is
/// not one. On 2026-09-26 it went red, green, then red again on identical code, and passed alone in
/// 2m22s each time; a task was filed to investigate a catalog that was never broken.
///
/// The cost is real and deliberate: a full-suite run grows by roughly the time this test takes,
/// because it no longer overlaps anything. A flaky proof is worth less than a slow one.
/// </summary>
[CollectionDefinition(SerialProcessSpawning.Name, DisableParallelization = true)]
public sealed class SerialProcessSpawning
{
    public const string Name = "serial process spawning";
}

/// <summary>
/// The question the suite never asked: does a template's tool produce evidence at all? Every other
/// test here checks what the tool is contained by. This one runs each of the 49 with its own default
/// parameters, outside the container, with the restricted token and jail a mission gives it, and
/// looks at what comes back.
/// </summary>
[Collection(SerialProcessSpawning.Name)]
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
        // The Windows sensors. A template whose tool runs under the Linux lease produces its evidence in
        // the guest, and LeasedMissionTests holds that path; nothing here could launch /bin/df.
        var all = GovernedTemplateCatalog.All
            .Where(t => t.Tool.Substrate == ToolSubstrate.Windows)
            .OrderBy(t => t.TemplateId, StringComparer.Ordinal)
            .ToList();
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

                    // Timed out comes first: the launcher kills the job with exit code 99, and read
                    // as an exit code that looked like a tool breaking its contract when it was a
                    // truncated answer.
                    string verdict =
                        run.TimedOut ? "TIMED OUT" :
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
    /// Measured 2026-09-22. Pinned rather than asserted empty, because each of these is a template
    /// to give an elevated tier or retire, and that is the operator's decision, not a test fix.
    ///
    /// All five want a right the restricted token deliberately removes: the Security event log
    /// (identity-lockout-trace, secops-auth-inspector), <c>gpresult</c> (identity-gpo-rsop),
    /// <c>secedit</c>'s policy export (compliance-security-baseline) and the BitLocker and TPM
    /// cmdlets (endpoint-bitlocker-compliance, which answered with empty labels and so passed as
    /// evidence until <see cref="Payload"/> stopped counting them).
    ///
    /// Four left on 2026-09-22 by being fixed. Two had called <c>wmic</c>, which Windows 11 removed.
    /// identity-kerberos-spn had been running a JDK's <c>klist</c>, found ahead of System32 on the
    /// host's PATH; the launcher now gives every tool the Windows default PATH. secops-process-scan
    /// never exited outside its contract: 99 is the launcher's timeout code, and <c>tasklist /v</c>
    /// needed 105 s of a 45 s budget. And sysops-time-sync, which asked the running time service for
    /// its configuration, passed on 2026-09-21 and failed on 2026-09-22 with no line changed: the
    /// service refuses this token only while it is running, and it starts on a trigger.
    /// </summary>
    private static readonly string[] ProduceNoEvidence =
    {
        "compliance-security-baseline",
        "endpoint-bitlocker-compliance",
        "identity-gpo-rsop",
        "identity-lockout-trace",
        "secops-auth-inspector",
    };

    /// <summary>
    /// The evidence, less what carries none: the template's own echoed section headers, and a
    /// property label with nothing after it. endpoint-bitlocker-compliance answered with seven such
    /// labels and not one value, which read as a hundred characters of evidence.
    /// </summary>
    private static string Payload(string text)
        => Regex.Replace(Regex.Replace(text, @"(?m)^[ \t]*[A-Za-z][\w .()-]*:[ \t]*\r?$", " "), @"---[^-\r\n]*---", " ")
            .Replace("\r", " ").Replace("\n", " ").Trim();

    private static string Trim(string flat)
    {
        while (flat.Contains("  ")) flat = flat.Replace("  ", " ");
        return flat.Length > 160 ? flat[..160] + "…" : flat;
    }
}
