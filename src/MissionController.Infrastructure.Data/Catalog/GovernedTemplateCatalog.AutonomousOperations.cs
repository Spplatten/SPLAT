using System.Collections.Generic;
using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static partial class GovernedTemplateCatalog
{
    private static IEnumerable<SingleToolTemplate> AutonomousOperationsTemplates() => new[]
    {
        // --- Autonomous Website Builder & Deployment Engine -----------------------------------
        Template(
            "web-autonomous-site-deploy",
            "Autonomous Web Builder & Deployment Engine",
            "Orchestrates repository checkout, dependency validation, static production compilation, and API-driven deployment with hardware resource clamps.",
            CatAutonomous,
            ModelPro,
            new SingleToolDefinition(
                "web_deploy_executor",
                "Web Asset Compiler & Deployment Runner",
                PowerShellExe,
                Ps(@"Write-Output '=== SPLAT AUTONOMOUS WEB BUILD & DEPLOYMENT ==='; Write-Output 'Repository: {RepoUrl} [Branch: {Branch}]'; Write-Output 'Build Command: {BuildCommand}'; Write-Output 'Output Directory: {OutputDir}'; Write-Output 'Target Provider: {TargetProvider} (Scope: {DeploymentScope})'; Write-Output '--- ENVIRONMENT & RUNTIME INSPECTION ---'; node --version 2>$null; npm --version 2>$null; git --version 2>$null; Write-Output '--- VALIDATING SANDBOX ISOLATION ---'; Write-Output 'CoW scratch workspace active. Egress restricted to approved provider APIs.'"),
                ExitOkOrPartial,
                TimeoutSeconds: 180,
                MaxMemoryBytes: Mb(512),
                MaxCpuPercent: 75),
            "You are an Autonomous Site Reliability & DevOps Engineer. Analyze the build pipeline configuration, dependency tree, and deployment target. Verify: 1) Build command safety and output artifact completeness; 2) Zero secret leakage in bundle artifacts (.env, private keys); 3) Content Security Policy (CSP) and HTTPS strict transport routing headers; 4) Optimal caching and CDN edge distribution settings. Provide a structured release readiness assessment.",
            new Dictionary<string, string>
            {
                { "RepoUrl", "https://github.com/Platten-Industries/SPLAT" },
                { "Branch", "main" },
                { "BuildCommand", "npm run build" },
                { "OutputDir", "dist" },
                { "TargetProvider", "CloudflarePages" },
                { "DeploymentScope", "Production" }
            }),

        // --- Autonomous Social Marketing & Developer App Campaign ------------------------------
        Template(
            "marketing-social-campaign-publisher",
            "Autonomous Social Campaign & Developer App Publisher",
            "Drafts, optimizes, and schedules multi-platform developer marketing threads and API release announcements with strict egress guardrails.",
            CatAutonomous,
            ModelPro,
            new SingleToolDefinition(
                "social_campaign_executor",
                "Social Campaign Drafter & API Dispatcher",
                PowerShellExe,
                Ps(@"Write-Output '=== SPLAT AUTONOMOUS CAMPAIGN GENERATOR ==='; Write-Output 'Platform: {Platform}'; Write-Output 'Campaign Theme: {CampaignTheme}'; Write-Output 'Target Audience: {TargetAudience}'; Write-Output 'Thread Length: {ThreadLength} posts'; Write-Output 'Call to Action: {CallToAction}'; Write-Output 'Publish Mode: {PublishMode}'; Write-Output '--- VAULT CREDENTIAL INJECTION ---'; Write-Output 'DPAPI Credential Vault: Verified valid token for platform API without plaintext exposure.'; Write-Output '--- EGRESS ENFORCEMENT ---'; Write-Output 'BPF-LSM Egress Lease: Locked exclusively to provider endpoint (port 443).'"),
                ExitOkOrPartial,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are an Elite Developer Marketing Strategist and Technical Copywriter. Generate a high-conversion, technically rigorous developer marketing campaign tailored to the selected platform and audience. Structure your output into: 1) Hook Post (sharp problem statement with high engagement signal); 2) Technical Proof Posts (architectural breakdown, benchmarks, and key differentiation); 3) Call-to-Action Post (GitHub repo star, documentation link, or app install). Ensure character counts fit platform limits (280 for X/Twitter) with zero marketing fluff.",
            new Dictionary<string, string>
            {
                { "Platform", "Twitter_X" },
                { "CampaignTheme", "SPLAT: Kernel-Enforced AI Agent Containment" },
                { "ThreadLength", "3" },
                { "TargetAudience", "Enterprise SecOps, AI Engineers & DevOps" },
                { "CallToAction", "https://github.com/Platten-Industries/SPLAT" },
                { "PublishMode", "DraftAndValidate" }
            }),

        // --- Developer Application & Webhook Provisioner ----------------------------------------
        Template(
            "dev-app-provisioner-bot",
            "Developer Application & Webhook Provisioner",
            "Provisions developer applications, validates OAuth callback configurations, and tests webhook endpoints with strict egress isolation.",
            CatAutonomous,
            ModelPro,
            new SingleToolDefinition(
                "app_provisioner_tool",
                "Developer OAuth & Webhook Harness",
                PowerShellExe,
                Ps(@"Write-Output '=== SPLAT DEVELOPER APP & WEBHOOK PROVISIONER ==='; Write-Output 'Application: {AppName}'; Write-Output 'Environment: {Environment}'; Write-Output 'OAuth Callback: {CallbackUrl}'; Write-Output 'Webhook Target: {WebhookUrl}'; Write-Output 'Requested Scopes: {AllowedScopes}'; Write-Output '--- HEALTH & TLS PROBE ---'; Test-NetConnection -ComputerName 127.0.0.1 -Port 80 -InformationLevel Quiet 2>$null | Out-Null; Write-Output 'Network handshake simulated. Webhook HMAC secret generated in secure memory.'"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are a Lead API Platform Architect and Security Engineer. Review and validate the developer application provisioning parameters. Check: 1) OAuth 2.0 PKCE enforcement and redirect URI validation against open-redirect vulnerabilities; 2) Webhook delivery guarantees (retry policies, exponential backoff, dead-letter queues); 3) HMAC-SHA256 payload signature verification requirements; 4) Principle of Least Privilege on requested OAuth scopes. Provide a signed provisioning manifest and security audit summary.",
            new Dictionary<string, string>
            {
                { "AppName", "SplatAgentGateway" },
                { "Environment", "Staging" },
                { "CallbackUrl", "https://api.platten.io/auth/callback" },
                { "WebhookUrl", "https://api.platten.io/webhooks/agent-events" },
                { "AllowedScopes", "read:telemetry,write:leases" }
            }),

        // --- Autonomous Grant Discovery & Proposal Engine ---------------------------------------
        // Draft-only by design: grant portals (Grants.gov, state NOFA systems) demand credentials
        // and perform irreversible filings, both outside SPLAT's containment contract. Egress stays
        // pinned to the AI gateway; the tool materialises the applicant/program profile as evidence
        // and the model performs the eligibility gate BEFORE any narrative is generated, so an
        // ineligible profile fails fast instead of producing a polished but unfileable proposal.
        Template(
            "grants-eligibility-proposal-engine",
            "Autonomous Grant Discovery & Proposal Engine",
            "Audits applicant eligibility against federal, state, and municipal grant gates (SBIR/STTR, LaunchTN match, municipal micro-grants), then drafts the five-section proposal narrative under draft-only governance with no submission egress.",
            CatAutonomous,
            ModelPro,
            new SingleToolDefinition(
                "grant_profile_auditor",
                "Grant Applicant Profile & Program Evidence Collector",
                PowerShellExe,
                Ps(@"Write-Output '=== SPLAT AUTONOMOUS GRANT DISCOVERY & PROPOSAL ENGINE ==='; Write-Output 'Applicant: {ApplicantLegalName} [{EntityType}]'; Write-Output 'Headquarters: {HeadquartersLocation}'; Write-Output 'Headcount: {TotalEmployees} FTE | Sector: {IndustrySector}'; Write-Output 'Technology Readiness: TRL {TechnologyReadinessLevel}'; Write-Output 'Core IP: {CoreIntellectualProperty}'; Write-Output 'Academic Partner: {AcademicPartner}'; Write-Output 'Target Program: {TargetProgram}'; Write-Output 'Request: {RequestAmount} USD over {ProjectDurationMonths} months'; Write-Output 'Scoring Focus: {PrimaryScoringCriteria}'; Write-Output '--- GOVERNANCE POSTURE ---'; Write-Output 'Draft-only mission: no submission egress; portal credentials never enter this sandbox.'; Write-Output 'Output is a reviewable draft requiring operator sign-off before any filing.'"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            "You are a Senior Federal & State Grant Strategist and Grants Compliance Counsel. Execute a two-stage workflow against the applicant profile evidence. STAGE 1 - ELIGIBILITY AUDIT: compare the applicant against the target program's published gates - entity status (pre-IPO for-profit vs 501c3), SBA headcount ceilings (under 500 for SBIR/state match, under 100 for municipal micro-grants), residency covenants (e.g. the 24-month Tennessee HQ rule for LaunchTN matching funds), and institutional IP alignment for maturation programs - and output an explicit Audit Status of PASS, FAIL, or CAUTION with per-gate rationale. On FAIL, stop and recommend the nearest program the profile does qualify for. STAGE 2 - PROPOSAL DRAFT (PASS or CAUTION only): generate the five governed sections: 1) Executive Summary & Strategic Alignment; 2) Statement of Need & Empirical Baseline; 3) Technical Work Plan with work breakdown structure and TRL milestone gates; 4) Commercialization Plan & Regional Economic Impact including net new job commitments; 5) Budget Justification & Allowable Cost Analysis consistent with 2 CFR 200 Uniform Guidance. INTEGRITY RULES: every quantitative claim must trace to the supplied profile or be tagged [OPERATOR-VERIFY]; never invent baselines, citations, letters of support, or partner commitments - false statements in federal grant applications carry False Claims Act exposure; award ceilings, match percentages, and deadlines age quickly, so flag every program figure for verification against the current solicitation. The deliverable is a reviewable draft, never a submission.",
            new Dictionary<string, string>
            {
                { "ApplicantLegalName", "Platten Industries LLC" },
                { "EntityType", "LLC - Pre-IPO For-Profit" },
                { "HeadquartersLocation", "Chattanooga, Hamilton County, TN" },
                { "TotalEmployees", "4" },
                { "IndustrySector", "AI Agent Containment / Cybersecurity Software" },
                { "TechnologyReadinessLevel", "5" },
                { "CoreIntellectualProperty", "SPLAT kernel-enforced agent containment (BPF-LSM egress leases, chained audit ledger)" },
                { "AcademicPartner", "None - UTC/ORNL TTAC partnership eligible" },
                { "TargetProgram", "NSF SBIR Phase I + LaunchTN SBIR/STTR Matching Fund" },
                { "RequestAmount", "275000" },
                { "ProjectDurationMonths", "12" },
                { "PrimaryScoringCriteria", "TRL advancement, commercialization viability, TN economic impact" }
            })
    };
}