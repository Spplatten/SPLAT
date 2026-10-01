using MissionController.Infrastructure.Data.Catalog;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A template's tool output is the evidence its findings are grounded against: the grounder attests a
/// finding by locating it in that stdout. So a sensor script that prints a claim about the containment
/// it runs under does not report a fact, it manufactures one - the model repeats the line, the grounder
/// finds it in the telemetry, and the fabrication is certified by the very check that exists to catch it.
///
/// Two Autonomous Operations templates did exactly that. One printed "BPF-LSM Egress Lease: Locked
/// exclusively to provider endpoint" on Windows, which has no BPF-LSM, from a tool that runs with no
/// network at all - and a credential vault "verified" that nothing had read. The other announced a
/// copy-on-write scratch workspace and restricted egress that nothing measured.
///
/// Containment is decided by the launcher and stated by CapabilityManifest. A sensor may report what it
/// observed; it may not assert that a mechanism is active. The phrases below are the vocabulary of that
/// assertion, matched in the script exactly as powershell.exe will echo it.
/// </summary>
public sealed class TemplateEvidenceHonestyTests
{
    private static readonly string[] AssertedMechanisms =
    {
        "BPF-LSM",
        "Egress Lease",
        "Locked exclusively",
        "Egress restricted",
        "Egress enforcement",
        "Sandbox isolation",
        "scratch workspace active",
        "Credential Vault",
        "Verified valid token",
    };

    /// <summary>
    /// The same fabrication, one level out: not "a mechanism is protecting me" but "I performed an
    /// action" by a tool that performed nothing. `dev-app-provisioner-bot` probed a loopback port,
    /// piped the result to <c>Out-Null</c>, and printed "Webhook HMAC secret generated in secure
    /// memory" — no secret, no memory, and the one real measurement discarded. The grounder would
    /// have anchored a model's repetition of that line in the telemetry and certified it.
    ///
    /// These phrases claim an effect outside the process. A tool that genuinely dispatches, schedules
    /// or provisions should report what came back — a status code, an id, a response — which is a
    /// reading and not one of these. The negative form is always allowed and is the idiom the
    /// `source-*` probes already use: "Nothing is published, and no credential is presented."
    /// </summary>
    private static readonly string[] AssertedEffects =
    {
        "secret generated",
        "in secure memory",
        "handshake simulated",
        "credentials rotated",
        "dispatched to",
        "scheduled for",
        "published to",
        "provisioned successfully",
        "registered successfully",
        "submitted successfully",
    };

    [Fact]
    public void NoTemplateTool_PrintsAClaimItCannotSupport()
    {
        // One fact, two vocabularies, on purpose: a second [Fact] would move the suite's advertised
        // count and send three documents and the Field Guide out of sync for a check that is the same
        // check. The message says which kind was found so the fix is obvious either way.
        var fabrications = GovernedTemplateCatalog.All
            .SelectMany(template => AssertedMechanisms
                .Where(phrase => template.Tool.ArgumentsTemplate.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                .Select(phrase => $"containment claimed - {template.TemplateId}: \"{phrase}\""))
            .Concat(GovernedTemplateCatalog.All
                .SelectMany(template => AssertedEffects
                    .Where(phrase => template.Tool.ArgumentsTemplate.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                    .Select(phrase => $"effect claimed - {template.TemplateId}: \"{phrase}\"")))
            .ToList();

        Assert.True(
            fabrications.Count == 0,
            "These tools print into the stdout their own findings are grounded against a claim the run "
            + "does not support. Report what was observed, or state what was not done: "
            + string.Join("; ", fabrications));
    }

    [Fact]
    public void TheScanReadsScriptsAsPowerShellWillRunThem()
    {
        // The check above is only as good as its input. Ps() passes each script through as plain text
        // today; were it ever to switch to -EncodedCommand, every phrase would vanish into base64 and
        // the check would pass forever without reading a word. This fails first.
        Assert.Contains(
            GovernedTemplateCatalog.All,
            template => template.Tool.ArgumentsTemplate.Contains("Write-Output", StringComparison.Ordinal));
    }
}
