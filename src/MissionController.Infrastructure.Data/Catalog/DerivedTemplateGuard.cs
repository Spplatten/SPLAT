using System;
using System.Collections.Generic;
using System.Linq;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

/// <summary>
/// Holds a user-authored template to the containment of the catalog agent it was derived from.
///
/// The create-template button copies a governed agent and lets the operator rewrite its words: the
/// name, the description, the role prompt, the output contract. It never offers to change what the
/// agent RUNS. But the copy is then serialized to the Templates table as a whole row, and until this
/// guard existed nothing re-checked it: a row edited in the database - or a future dialog that grew
/// one field too many - could name any executable, any command line, any destination, and the engine
/// would launch it, because <c>ValidateStrictRules</c> only asks that a tool is present, never which.
///
/// So containment is re-derived from the catalog on every load and every save, and a row that has
/// drifted from its base is refused rather than repaired: a template that cannot be trusted to say
/// what it runs must not run at all, and silently substituting the base's tool would hide the fact
/// that something rewrote the row.
///
/// Three properties are held, and only three, because only these three decide what the sandbox
/// permits:
///  - <see cref="SingleToolTemplate.Tool"/>: the executable, its argument template, the exit codes
///    treated as success, and every clamp (timeout, memory, CPU, restricted token, integrity level).
///  - <see cref="SingleToolTemplate.EgressRule"/>: the one destination, and whether the SENSOR is the
///    leg that opens it.
///  - <see cref="SingleToolTemplate.NetworkDenialMeasuredHarmless"/>: whether the tool launches with
///    no network stack at all. It is a measurement (see <c>NetworkToolsUnderDenialTests</c>), so a
///    derived template inherits it rather than asserting it - and a copy that quietly dropped it
///    would hand a network stack back to an agent measured not to need one.
///
/// Deliberately NOT held: the target model, the parameter fields and their defaults. Neither changes
/// what may be reached. A parameter's value is already the operator's to set at launch, and the
/// binder validates every value it substitutes, so a template that bakes in a different default is
/// equivalent to an operator typing it - not an escalation.
/// </summary>
public static class DerivedTemplateGuard
{
    /// <summary>
    /// Why this template is retired or may not be trusted as a derivative of its stated base,
    /// or null when it may be used, including current catalog templates with no stated base.
    /// </summary>
    public static string? Problem(SingleToolTemplate template)
    {
        ArgumentNullException.ThrowIfNull(template);

        if (GovernedTemplateCatalog.RetirementReason(template.TemplateId) is { } retired)
        {
            return $"'{template.TemplateId}' is retired: {retired} Its stored record is retained, but it may not run.";
        }

        if (string.IsNullOrWhiteSpace(template.SourceTemplateId))
        {
            return null;
        }

        if (GovernedTemplateCatalog.RetirementReason(template.SourceTemplateId) is { } retiredBase)
        {
            return $"'{template.TemplateId}' derives from retired template '{template.SourceTemplateId}': {retiredBase}";
        }

        var source = GovernedTemplateCatalog.All
            .FirstOrDefault(candidate => string.Equals(
                candidate.TemplateId, template.SourceTemplateId, StringComparison.Ordinal));

        if (source is null)
        {
            return $"'{template.TemplateId}' is derived from '{template.SourceTemplateId}', which is not " +
                   "a governed catalog agent. Its containment cannot be verified against anything.";
        }

        var drifted = new List<string>();

        if (!ToolMatches(template.Tool, source.Tool))
        {
            drifted.Add($"the tool it runs ('{Describe(template.Tool)}' against the base's '{Describe(source.Tool)}')");
        }

        if (!EgressMatches(template.EgressRule, source.EgressRule))
        {
            drifted.Add($"its approved destination ('{Describe(template.EgressRule)}' against the base's " +
                        $"'{Describe(source.EgressRule)}')");
        }

        if (template.NetworkDenialMeasuredHarmless != source.NetworkDenialMeasuredHarmless)
        {
            drifted.Add(source.NetworkDenialMeasuredHarmless
                ? "whether it launches with no network stack (the base is network-denied; this copy is not)"
                : "whether it launches with no network stack (this copy claims denial the base was not measured for)");
        }

        if (drifted.Count == 0)
        {
            return null;
        }

        return $"'{template.TemplateId}' claims to be derived from '{source.TemplateId}' but has drifted from " +
               $"its containment in {drifted.Count} way(s): {string.Join("; ", drifted)}. A derived agent may " +
               "rewrite its words, never what it runs or what it may reach.";
    }

    /// <summary>Throws when <see cref="Problem"/> has something to say. The registry's entry point.</summary>
    public static void Validate(SingleToolTemplate template)
    {
        if (Problem(template) is { } problem)
        {
            throw new InvalidOperationException(problem);
        }
    }

    private static bool ToolMatches(SingleToolDefinition derived, SingleToolDefinition source) =>
        derived is not null
        && source is not null
        && string.Equals(derived.ExecutablePath, source.ExecutablePath,
            source.Substrate == ToolSubstrate.LinuxLease ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase)
        && string.Equals(derived.ArgumentsTemplate, source.ArgumentsTemplate, StringComparison.Ordinal)
        && derived.TimeoutSeconds == source.TimeoutSeconds
        && derived.MaxMemoryBytes == source.MaxMemoryBytes
        && derived.MaxCpuPercent == source.MaxCpuPercent
        && derived.RequiresRestrictedToken == source.RequiresRestrictedToken
        && derived.IntegrityLevel == source.IntegrityLevel
        && derived.Substrate == source.Substrate
        && derived.PassLeaseEgressAsArguments == source.PassLeaseEgressAsArguments
        && derived.PassLeaseHostPinsAsArguments == source.PassLeaseHostPinsAsArguments
        // Adding an opt-in restriction to an unrestricted base cannot expand its jail/exec/egress.
        // A base that already requires one must retain it verbatim, including after database reload.
        && (source.ExecutionPolicy is null || System.Text.Json.JsonSerializer.Serialize(derived.ExecutionPolicy)
            == System.Text.Json.JsonSerializer.Serialize(source.ExecutionPolicy))
        && (derived.AllowedExitCodes ?? Array.Empty<int>())
            .SequenceEqual(source.AllowedExitCodes ?? Array.Empty<int>());

    private static bool EgressMatches(EgressRule derived, EgressRule source) =>
        derived is not null
        && source is not null
        && string.Equals(derived.AllowedFqdn, source.AllowedFqdn, StringComparison.OrdinalIgnoreCase)
        && derived.AllowedPort == source.AllowedPort
        && derived.EnforceHttpsOnly == source.EnforceHttpsOnly
        && derived.Scope == source.Scope
        && (derived.AdditionalFqdns ?? Array.Empty<string>())
            .SequenceEqual(source.AdditionalFqdns ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);

    private static string Describe(SingleToolDefinition? tool) =>
        tool is null ? "(none)" : $"{tool.ExecutablePath} {tool.ArgumentsTemplate}".Trim();

    private static string Describe(EgressRule? egress) =>
        egress is null ? "(none)" : egress.AllowedFqdn;
}
