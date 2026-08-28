using System.Collections.Generic;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static class GovernedProjectCatalog
{
    public static IReadOnlyList<ProjectTemplate> All { get; } = new[]
    {
        new ProjectTemplate(
            "project-workstation-incident-review",
            "Workstation Incident Review",
            "A bounded evidence pass that correlates event failures, authentication pressure, and network health before an escalation decision.",
            "Projects",
            new[]
            {
                new ProjectStage("events", "Collect system and application failure clusters", "sysops-event-triage", "Cluster the machine's recent critical and error events by root cause. Prioritize storage, unexpected shutdown, and driver evidence."),
                new ProjectStage("identity", "Check authentication pressure", "secops-auth-inspector", "Look for failed logon bursts, lockout patterns, and identity evidence that could explain the incident."),
                new ProjectStage("network", "Check local connectivity path", "net-dns-audit", "Measure the local connectivity path and identify whether the incident is local, upstream, or external.")
            },
            new[]
            {
                "Incident health decision",
                "Evidence-backed root-cause shortlist",
                "Escalation-ready next actions"
            },
            true),
        new ProjectTemplate(
            "project-change-readiness-review",
            "Endpoint Change Readiness Review",
            "Reviews patch state, service stability, and endpoint security posture before a controlled workstation or lab rollout.",
            "Projects",
            new[]
            {
                new ProjectStage("patch", "Review update history and reboot state", "sysops-patch-compliance", "Identify missing updates, repeated failures, and pending reboot state that could invalidate a rollout."),
                new ProjectStage("services", "Review service failure risk", "sysops-service-failures", "Identify automatic services that are stopped or crash-looping and could make the change unsafe."),
                new ProjectStage("security", "Review endpoint control posture", "secops-defender-status", "Confirm that Defender and the endpoint security controls are active before proceeding.")
            },
            new[]
            {
                "Go or no-go readiness recommendation",
                "Blocking evidence and owners",
                "Ordered pre-change actions"
            },
            true)
    };
}
