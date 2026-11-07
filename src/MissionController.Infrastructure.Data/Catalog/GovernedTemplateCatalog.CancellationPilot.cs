using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

/// <summary>
/// The two workloads the cancellation proof leases (docs/FALCON-CANCELLATION-PILOT.md): a target the
/// synthetic control event cancels, and a control on the same guest that must survive it. Both run
/// native/experiments/alert-cancellation/workload_fixture.py, which reads no secrets and opens no
/// sockets, deployed root-owned at <see cref="CancellationPilotFixturePath"/> under the jail's
/// read-only /usr.
///
/// Kept out of <see cref="All"/> on purpose. A fixture that sleeps and spins is no capability for an
/// operator to find, the census counts only what an operator can run, and a normal import or A2A host
/// must not approve an agent bound to one. Only a caller that names the pilot resolves these
/// (AgentManifestCompiler's includeCancellationPilot), and the registry refuses them as missions.
/// </summary>
public static partial class GovernedTemplateCatalog
{
    public const string CancellationPilotFixturePath = "/usr/local/lib/splat/pilot/workload_fixture.py";

    // The fixture ends inside its lease: a control that outlives the proof exits 0 on its own, so
    // "survived" can never be a lease deadline killing it afterwards.
    private const int CancellationPilotSeconds = 240;

    private static IReadOnlyList<SingleToolTemplate>? _cancellationPilot;

    public static IReadOnlyList<SingleToolTemplate> CancellationPilot => _cancellationPilot ??= new[]
    {
        PilotWorkload("target", "Target",
            "Leases the pilot fixture's target role: it prints its READY line, keeps a descendant alive in the same cgroup, and runs until the proof cancels it.",
            "The proof expects this task to be cancelled; an exit on its own means the proof did not run."),
        PilotWorkload("control", "Control",
            "Leases the pilot fixture's control role: it prints its READY line and advances CPU accounting at a bounded duty cycle while the target is cancelled.",
            "The proof expects this task to survive the target's cancellation and exit 0 on its own."),
    };

    private static SingleToolTemplate PilotWorkload(string role, string title, string description, string expectation)
    {
        var template = LeasedTemplate(
            $"cancellation-pilot-{role}",
            $"Cancellation Pilot {title}",
            description,
            ModelFlash,
            $"cancellation_pilot_{role}_tool",
            $"Pilot Fixture ({title} Role)",
            "/usr/bin/python3",
            $"-I {CancellationPilotFixturePath} {role} --seconds {CancellationPilotSeconds}",
            Plain("The fixture produces no evidence about the host; the reasoning block would invent analysis of a sleep loop.",
                $"You are reporting a public-data pilot fixture, not a host. Quote its READY line and say how the run ended. {expectation} Never report a finding about the guest."),
            timeoutSeconds: CancellationPilotSeconds + 60);
        template.ValidateStrictRules();
        return template;
    }
}
