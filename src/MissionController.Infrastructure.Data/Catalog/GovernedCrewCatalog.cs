using System.Collections.Generic;
using MissionController.Core.Crew;

namespace MissionController.Infrastructure.Data.Catalog;

public static class GovernedCrewCatalog
{
    public static IReadOnlyList<GovernedCrewDefinition> All { get; } = new[]
    {
        // 1. Hierarchical SecOps Incident Response Crew
        new GovernedCrewDefinition(
            CrewId: "secops-incident-response-crew",
            Name: "SecOps Incident Response & Threat Hunting Crew",
            Description: "A hierarchical multi-agent team orchestrated by an Incident Commander to triage endpoint anomalies, brute-force pressure, and suspicious network egress.",
            ProcessType: CrewProcessType.Hierarchical,
            ManagerAgent: new GovernedCrewAgent(
                AgentId: "secops-commander",
                Role: "SecOps Incident Commander",
                Goal: "Coordinate threat triage, delegate diagnostic probes to specialized agents, and synthesize a unified security containment plan.",
                Backstory: "You are an elite Incident Response Commander. You do not run low-level sensor tools directly; you formulate hypotheses and delegate to specialized triage agents.",
                TargetModel: "claude-sonnet-5",
                AllowDelegation: true,
                MaxIterations: 6),
            Agents: new[]
            {
                new GovernedCrewAgent(
                    AgentId: "auth-hunter",
                    Role: "Identity & Authentication Specialist",
                    Goal: "Judge whether this host would survive a password-guessing attempt: the lockout arithmetic, the enabled local accounts and the open session types.",
                    Backstory: "You are a specialist in Windows identity configuration. You work from posture, not from authentication events - the Security channel is not readable under the token these missions run with - so you say what you cannot see before you say what you found.",
                    TargetModel: "claude-sonnet-5",
                    AssignedTemplateIds: new[] { "identity-auth-posture" },
                    AllowDelegation: false),
                new GovernedCrewAgent(
                    AgentId: "defender-auditor",
                    Role: "Endpoint Security Posture Auditor",
                    Goal: "Verify Defender real-time protection, signature freshness, and tamper protection state.",
                    Backstory: "You specialize in EDR telemetry and Windows Defender endpoint health.",
                    TargetModel: "claude-sonnet-5",
                    AssignedTemplateIds: new[] { "secops-defender-status" },
                    AllowDelegation: false),
                new GovernedCrewAgent(
                    AgentId: "network-prober",
                    Role: "Network Perimeter & Egress Hunter",
                    Goal: "Audit DNS resolution latency, dropped packets, and abnormal egress paths.",
                    Backstory: "You are a network protocol analyst specializing in Layer 3/4 and DNS telemetry.",
                    TargetModel: "claude-sonnet-5",
                    AssignedTemplateIds: new[] { "net-dns-audit" },
                    AllowDelegation: false)
            },
            Tasks: new[]
            {
                new GovernedCrewTask(
                    TaskId: "task-auth-triage",
                    Description: "Read the lockout policy, the enabled local accounts and the open logon session types, and judge the host's resistance to credential guessing.",
                    ExpectedOutput: "A structured report on lockout resistance and account exposure, stating that authentication events were not available to it.",
                    AssignedAgentId: "auth-hunter",
                    TemplateId: "identity-auth-posture"),
                new GovernedCrewTask(
                    TaskId: "task-defender-posture",
                    Description: "Audit local antivirus and real-time behavioral protection status.",
                    ExpectedOutput: "Endpoint posture health and signature currency verdict.",
                    AssignedAgentId: "defender-auditor",
                    TemplateId: "secops-defender-status"),
                new GovernedCrewTask(
                    TaskId: "task-network-egress",
                    Description: "Verify local gateway reachability and DNS resolution health.",
                    ExpectedOutput: "Network latency and packet drop telemetry.",
                    AssignedAgentId: "network-prober",
                    TemplateId: "net-dns-audit")
            },
            MaxRpm: 30,
            MaxCrewIterations: 8,
            EnableSemanticMemory: true),

        // 2. Sequential Campus Infrastructure Audit Crew
        new GovernedCrewDefinition(
            CrewId: "campus-infrastructure-audit-crew",
            Name: "Campus Infrastructure & SysOps Health Crew",
            Description: "An ordered sequential multi-agent pipeline validating network performance, storage headroom, and core system services.",
            ProcessType: CrewProcessType.Sequential,
            Agents: new[]
            {
                new GovernedCrewAgent(
                    AgentId: "dns-specialist",
                    Role: "DNS & Connectivity Engineer",
                    Goal: "Measure DNS latency and gateway connectivity.",
                    Backstory: "You specialize in DNS latency and local network resolution.",
                    TargetModel: "claude-sonnet-5",
                    AssignedTemplateIds: new[] { "net-dns-audit" },
                    AllowDelegation: false),
                new GovernedCrewAgent(
                    AgentId: "disk-capacity-analyst",
                    Role: "Storage Capacity Analyst",
                    Goal: "Inspect disk volumes for headroom exhaustion and temp clutter.",
                    Backstory: "You audit filesystem health and disk saturation.",
                    TargetModel: "claude-sonnet-5",
                    AssignedTemplateIds: new[] { "sysops-disk-space" },
                    AllowDelegation: false),
                new GovernedCrewAgent(
                    AgentId: "service-reliability-engineer",
                    Role: "Service Reliability Engineer",
                    Goal: "Audit automatic Windows services for crashes and stopped states.",
                    Backstory: "You ensure critical system daemons and background services are operational.",
                    TargetModel: "claude-sonnet-5",
                    AssignedTemplateIds: new[] { "sysops-service-failures" },
                    AllowDelegation: false)
            },
            Tasks: new[]
            {
                new GovernedCrewTask(
                    TaskId: "audit-dns",
                    Description: "Audit local DNS resolution time and gateway packet loss.",
                    ExpectedOutput: "DNS latency metrics and network health status.",
                    AssignedAgentId: "dns-specialist",
                    TemplateId: "net-dns-audit"),
                new GovernedCrewTask(
                    TaskId: "audit-storage",
                    Description: "Verify system volume free space and identify temp file buildup.",
                    ExpectedOutput: "Disk capacity metrics and cleanup recommendations.",
                    AssignedAgentId: "disk-capacity-analyst",
                    TemplateId: "sysops-disk-space",
                    ContextTaskIds: new[] { "audit-dns" }),
                new GovernedCrewTask(
                    TaskId: "audit-services",
                    Description: "Check all automatic startup services for unexpected failures.",
                    ExpectedOutput: "Service availability matrix and failed daemon list.",
                    AssignedAgentId: "service-reliability-engineer",
                    TemplateId: "sysops-service-failures",
                    ContextTaskIds: new[] { "audit-storage" })
            },
            MaxRpm: 30,
            MaxCrewIterations: 6,
            EnableSemanticMemory: true)
    };
}
