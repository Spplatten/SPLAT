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

    /// <summary>
    /// The tool's own failure, read from its error stream alone - never from what it printed.
    ///
    /// These phrases mean "the thing I was asked to run did not run". Several of them are also
    /// ordinary English that a *working* tool can quote: on 2026-11-13 this test failed on
    /// <c>sysops-event-triage</c>, which exited 0 with 8609 characters of real event-log evidence
    /// and was called a refusal because one Windows Firewall event (Id 2042) carried the line
    /// <c>Error:\tAccess is denied.</c> in its own Message body, at column 26. The scan was over
    /// stdout and stderr concatenated, so the verdict moved with the contents of the machine's
    /// event log instead of with any code, and it reproduced in isolation - which is why
    /// "run it alone before believing it" did not clear it.
    ///
    /// The stream is the discriminator, and it was measured rather than assumed. Driven through
    /// this same launcher and jail, each failure class puts its diagnostic on stderr and leaves
    /// stdout empty: a missing executable under cmd ("is not recognized as an internal or external
    /// command"), a missing cmdlet under PowerShell ("The term '...'" / CommandNotFoundException),
    /// and a denied read under cmd ("Access is denied."). PowerShell routes a mid-script cmdlet
    /// error there too, which is where <c>secops-tls-cipher-audit</c> and
    /// <c>sysops-boot-performance</c> report theirs. No template's payload can reach stderr, and
    /// <see cref="EveryTemplate_IsRunOnceOutsideTheContainer_AndSaysWhetherItProducedEvidence"/>
    /// alone cannot prove the narrowing still fires, because today no catalog tool is broken - so
    /// <see cref="ABrokenTool_IsStillCaught_AfterTheScanNarrowedToStandardError"/> is the control
    /// that keeps this honest. Delete that test and this one stops discriminating silently.
    ///
    /// Raw stderr, not <see cref="Payload"/>: that normaliser replaces a line holding nothing but a
    /// label with a space, and a bare "Usage:" is exactly such a line.
    /// </summary>
    private const string CmdExe = @"C:\Windows\System32\cmd.exe";
    private const string PowerShellExe = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

    private static string? OwnFailure(string standardError)
        => NotEvidence.FirstOrDefault(n => standardError.Contains(n, StringComparison.Ordinal));

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
                    string? refusal = OwnFailure(run.StandardError);

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
    /// The control for <see cref="OwnFailure"/>. The test above passes when every catalog tool
    /// works, which is also what it would report if the refusal scan had stopped matching
    /// anything at all - so on its own it cannot tell a narrowed detector from a disabled one.
    ///
    /// This drives three tools that really are broken through the same launcher, jail and
    /// restricted token, and asserts each is still caught. It is the measurement that earns
    /// reading stderr alone: every one of them leaves stdout empty, so nothing here would have
    /// been found by a scan of what the tool printed.
    /// </summary>
    [Fact]
    public async Task ABrokenTool_IsStillCaught_AfterTheScanNarrowedToStandardError()
    {
        var jails = new NtAclJailManager();
        var launcher = new SuspendedProcessLauncher(new RestrictedTokenProvider());
        var missionId = Guid.NewGuid();
        string jail = await jails.ProvisionJailAsync(missionId);
        try
        {
            foreach (var (what, executable, arguments) in new[]
            {
                ("a missing executable", CmdExe, "/c no_such_tool_xyz.exe --help"),
                ("a missing cmdlet", PowerShellExe, "-NoProfile -Command \"Get-NoSuchCmdletXyz\""),
                ("a denied read", CmdExe, @"/c type C:\Windows\System32\config\SAM"),
            })
            {
                using var job = new Win32JobSandbox($"BrokenTool_{Guid.NewGuid():N}");
                var run = await launcher.LaunchSuspendedInJobAsync(
                    executable, arguments, jail, job,
                    dropAdminPrivileges: true, timeoutSeconds: 30, denyNetworkAccess: false);

                string? caught = OwnFailure(run.StandardError);
                _out.WriteLine($"{what,-22} exit {run.ExitCode,3} stdout {run.StandardOutput.Length,4} chars  caught: {caught ?? "NOTHING"}");

                Assert.False(run.TimedOut, $"{what} timed out rather than failing");
                Assert.NotNull(caught);
                Assert.True(
                    string.IsNullOrWhiteSpace(run.StandardOutput),
                    $"{what} wrote to stdout, so the stream is no longer the discriminator: {Trim(run.StandardOutput)}");
            }
        }
        finally
        {
            await jails.DrainAndCleanupJailAsync(jail);
        }
    }

    /// <summary>
    /// Measured 2026-09-22, and decided 2026-10-01: four of the five were retired rather than given
    /// an elevated tier. <c>compliance-security-baseline</c> (<c>secedit</c>'s policy export),
    /// <c>endpoint-bitlocker-compliance</c> (the BitLocker and TPM cmdlets, which answered with
    /// seven empty labels and so passed as evidence until <see cref="Payload"/> stopped counting
    /// them), <c>identity-gpo-rsop</c> (<c>gpresult</c>) and <c>identity-lockout-trace</c> (the
    /// Security event log) are gone from the catalog: a second privilege tier would have cost the
    /// zero-admin pillar, which is a load-bearing claim, to recover four outputs nobody asked for.
    ///
    /// The fifth was the harder call and was settled on 2026-10-03. <c>secops-auth-inspector</c>
    /// wanted the Security event log too, and it was the only authentication telemetry in the
    /// product - a governed crew's auth-hunter agent and a project's identity stage were built on
    /// it - so retiring it would have removed a capability rather than a dead end. It was
    /// <em>replaced</em>: <c>identity-auth-posture</c> reads the lockout policy, the local accounts
    /// and the open session types, all of which a standard-user token can see, and says in its own
    /// prompt that it reads no authentication events. That is a narrower question answered honestly
    /// instead of the same question answered with 66 characters of "Access is denied."
    ///
    /// **This list is now empty, and that is the claim.** Every Windows template in the shipped
    /// catalog produces usable evidence under the restricted token; measured 2026-10-03 on an
    /// otherwise idle machine, because this test spawns all of them unisolated and contention
    /// reports a working template as silent.
    ///
    /// Four left on 2026-09-22 by being fixed. Two had called <c>wmic</c>, which Windows 11 removed.
    /// identity-kerberos-spn had been running a JDK's <c>klist</c>, found ahead of System32 on the
    /// host's PATH; the launcher now gives every tool the Windows default PATH. secops-process-scan
    /// never exited outside its contract: 99 is the launcher's timeout code, and <c>tasklist /v</c>
    /// needed 105 s of a 45 s budget. And sysops-time-sync, which asked the running time service for
    /// its configuration, passed on 2026-09-21 and failed on 2026-09-22 with no line changed: the
    /// service refuses this token only while it is running, and it starts on a trigger.
    /// </summary>
    private static readonly string[] ProduceNoEvidence = Array.Empty<string>();

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
