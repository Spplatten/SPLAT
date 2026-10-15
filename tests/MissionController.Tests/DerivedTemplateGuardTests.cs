using System;
using System.Linq;
using MissionController.Core.Enums;
using MissionController.Core.Models;
using MissionController.Infrastructure.Data.Catalog;
using Xunit;

namespace MissionController.Tests;

/// <summary>
/// A user-authored checkup may rewrite its words. It may not rewrite what it runs.
///
/// The create-template dialog only ever offers the wording, but the result is stored as a whole row
/// in the Templates table, and <c>ValidateStrictRules</c> asks only that a tool is bound - never
/// which one. So a row edited in the database, or a dialog that one day grows a field too many,
/// could name any executable and any destination and the engine would launch it. These tests hold
/// the guard that closes that, and they are written against the shipped catalog rather than a stub
/// so they keep holding as the catalog changes.
/// </summary>
public class DerivedTemplateGuardTests
{
    private static SingleToolTemplate Base() =>
        GovernedTemplateCatalog.All.First(t => t.TemplateId == "endpoint-persistence-audit");

    /// <summary>A copy the dialog would produce: same tool, same egress, new words.</summary>
    private static SingleToolTemplate DerivedFrom(SingleToolTemplate source) =>
        new(
            "custom-my-persistence-review",
            "My persistence review",
            "Checks what starts with this PC, the way our team reads it.",
            "Custom Operations",
            source.TargetModel,
            source.Tool,
            source.EgressRule,
            "You are our threat hunter. Flag anything starting from a folder a user can write to.",
            source.ParameterFields,
            source.GetEffectiveDefaults(),
            Array.Empty<RemediationAction>(),
            TemplateKind.TaskAgent,
            new TemplateOutputContract("What starts with this PC", new[] { "A list" }, new[] { "Every entry named" }),
            source.TemplateId,
            true,
            source.NetworkDenialMeasuredHarmless);

    [Fact]
    public void ACatalogTemplate_StatesNoBase_AndIsNeverRefused()
    {
        foreach (var template in GovernedTemplateCatalog.All)
        {
            Assert.Null(DerivedTemplateGuard.Problem(template));
        }
    }

    [Fact]
    public void AFaithfulCopy_IsAccepted()
    {
        Assert.Null(DerivedTemplateGuard.Problem(DerivedFrom(Base())));
    }

    [Fact]
    public void ACopyThatSwapsTheExecutable_IsRefused()
    {
        var tampered = DerivedFrom(Base()) with
        {
            Tool = Base().Tool with { ExecutablePath = @"C:\Windows\System32\cmd.exe" }
        };

        var problem = DerivedTemplateGuard.Problem(tampered);

        Assert.NotNull(problem);
        Assert.Contains("the tool it runs", problem);
    }

    [Fact]
    public void ACopyThatRewritesTheCommandLine_IsRefused()
    {
        var tampered = DerivedFrom(Base()) with
        {
            Tool = Base().Tool with { ArgumentsTemplate = "-NoProfile -Command \"whoami\"" }
        };

        Assert.Contains("the tool it runs", DerivedTemplateGuard.Problem(tampered));
    }

    [Fact]
    public void ACopyThatLoosensAClamp_IsRefused()
    {
        var tampered = DerivedFrom(Base()) with
        {
            Tool = Base().Tool with { RequiresRestrictedToken = false }
        };

        Assert.Contains("the tool it runs", DerivedTemplateGuard.Problem(tampered));
    }

    [Fact]
    public void ACopyCannotChangeItsSubstrateOrLeaseArgumentBinding()
    {
        var source = GovernedTemplateCatalog.All.First(t => t.TemplateId == "linux-disk-usage");
        var copy = DerivedFrom(source);
        Assert.NotNull(DerivedTemplateGuard.Problem(copy with { Tool = source.Tool with { Substrate = ToolSubstrate.Windows } }));
        Assert.NotNull(DerivedTemplateGuard.Problem(copy with { Tool = source.Tool with { PassLeaseEgressAsArguments = true } }));
        Assert.NotNull(DerivedTemplateGuard.Problem(copy with { Tool = source.Tool with { ExecutablePath = source.Tool.ExecutablePath.ToUpperInvariant() } }));
    }

    [Fact]
    public void ACopyCannotChangeItsEgressPortOrTransport()
    {
        var source = Base();
        var copy = DerivedFrom(source);
        Assert.NotNull(DerivedTemplateGuard.Problem(copy with { EgressRule = source.EgressRule with { AllowedPort = 22 } }));
        Assert.NotNull(DerivedTemplateGuard.Problem(copy with { EgressRule = source.EgressRule with { EnforceHttpsOnly = false } }));
    }

    [Fact]
    public void ACopyThatPointsAtAnotherDestination_IsRefused()
    {
        var tampered = DerivedFrom(Base()) with
        {
            EgressRule = Base().EgressRule with { AllowedFqdn = "evil.example.com" }
        };

        Assert.Contains("its approved destination", DerivedTemplateGuard.Problem(tampered));
    }

    /// <summary>
    /// The bug this guard found on the way in: the dialog built its copy without carrying the base's
    /// measured network denial, so every copy of a network-denied checkup quietly got a network stack
    /// back. A default that silently widens containment is exactly what this refuses.
    /// </summary>
    [Fact]
    public void ACopyThatDropsMeasuredNetworkDenial_IsRefused()
    {
        var denied = GovernedTemplateCatalog.All.First(t => t.NetworkDenialMeasuredHarmless);
        var tampered = DerivedFrom(denied) with { NetworkDenialMeasuredHarmless = false };

        Assert.Contains("no network stack", DerivedTemplateGuard.Problem(tampered));
    }

    [Fact]
    public void ACopyNamingABaseThatIsNotInTheCatalog_IsRefused()
    {
        var orphan = DerivedFrom(Base()) with { SourceTemplateId = "catalog-agent-that-never-existed" };

        Assert.Contains("not a governed catalog agent", DerivedTemplateGuard.Problem(orphan));
    }

    /// <summary>
    /// Wording is the whole point of a derived checkup, and changing all of it must stay free.
    /// </summary>
    [Fact]
    public void ACopyThatChangesOnlyItsWords_IsAccepted()
    {
        var reworded = DerivedFrom(Base()) with
        {
            Name = "Something else entirely",
            Description = "A different description.",
            Category = "Another group",
            SystemPrompt = "You are a different analyst with different priorities."
        };

        Assert.Null(DerivedTemplateGuard.Problem(reworded));
    }

    [Fact]
    public void Validate_ThrowsWithTheReason_SoALaunchCannotProceedQuietly()
    {
        var tampered = DerivedFrom(Base()) with
        {
            Tool = Base().Tool with { ExecutablePath = @"C:\Windows\System32\cmd.exe" }
        };

        var thrown = Assert.Throws<InvalidOperationException>(() => DerivedTemplateGuard.Validate(tampered));
        Assert.Contains("custom-my-persistence-review", thrown.Message);
    }
}
