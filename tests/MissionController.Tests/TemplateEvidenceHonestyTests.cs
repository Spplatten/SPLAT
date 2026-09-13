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

    [Fact]
    public void NoTemplateTool_PrintsTheContainmentItRunsUnder()
    {
        var fabrications = GovernedTemplateCatalog.All
            .SelectMany(template => AssertedMechanisms
                .Where(phrase => template.Tool.ArgumentsTemplate.Contains(phrase, StringComparison.OrdinalIgnoreCase))
                .Select(phrase => $"{template.TemplateId}: \"{phrase}\""))
            .ToList();

        Assert.True(
            fabrications.Count == 0,
            "These tools print containment claims into the stdout their findings are grounded against: "
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
