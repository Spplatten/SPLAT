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
            true),
        new ProjectTemplate(
            "project-grant-capture-pipeline",
            "Grant Capture Pipeline",
            "Discovers open federal funding opportunities, audits the applicant against each program's eligibility gates, drafts the proposal narrative, and independently reconciles the budget. Draft-only: no stage presents a credential or files an application.",
            "Projects",
            new[]
            {
                // Discovery is the one stage allowed to fail without stopping the run: it reaches the
                // network, and a DNS blip must not block a drafting session against a program the
                // operator already named. Its directive therefore has to keep an empty result from
                // being read downstream as an eligibility finding.
                new ProjectStage("ingest", "Discover open funding opportunities", "grants-opportunity-ingestion", "Retrieve currently open opportunities matching the applicant's sector and rank them by fit. Report each opportunity number, agency, and close date. If retrieval failed, state that the opportunity set is UNKNOWN and do not conclude that no programs match.", true),
                new ProjectStage("qualify", "Audit eligibility and draft the proposal narrative", "grants-eligibility-proposal-engine", "Screen the applicant profile against the eligibility gates of the shortlisted opportunities carried in the upstream evidence, and against the operator's named target program. Emit the PASS/FAIL/CAUTION audit first with per-gate rationale, then draft the five proposal sections only for programs that cleared. Tag every unsupported figure [OPERATOR-VERIFY]."),
                new ProjectStage("budget", "Reconcile the budget and audit allowable costs", "grants-budget-compliance-auditor", "Reconcile the budget behind the drafted narrative. Report the variance, the allowability of each cost line under 2 CFR 200 Subpart E, and the basis claimed for the indirect rate. Close with the blocking items that must be resolved before this draft could be filed.")
            },
            new[]
            {
                "Ranked shortlist of open opportunities with close dates",
                "Per-program eligibility audit with PASS/FAIL/CAUTION rationale",
                "Five-section proposal draft for qualifying programs",
                "Reconciled budget with allowable-cost findings",
                "Blocking items requiring operator verification before filing"
            },
            true)
    };
}
