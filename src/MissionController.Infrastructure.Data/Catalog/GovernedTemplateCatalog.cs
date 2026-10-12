using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

/// <summary>
/// Enterprise/campus-scale governed diagnostic catalog.
///
/// Split across partial files by operational domain so a single category can be reviewed,
/// signed off, and change-controlled by its owning team (Identity, Endpoint, Network,
/// SysOps, Compliance, Campus) without forcing a merge conflict across the whole catalog.
///
/// TemplateId is the IDENTITY key written into the tamper-evident audit ledger. Renaming an
/// existing id silently orphans every historical ledger row that references it and breaks the
/// forensic chain, so ids here are APPEND-ONLY: add new ones, never rewrite shipped ones.
/// Category/Name/Description are display metadata and may be renormalised freely.
/// </summary>
public static partial class GovernedTemplateCatalog
{
    /// <summary>
    /// Bumped whenever the seeded set changes. The registry stores this so startup can skip a
    /// redundant full-catalog upsert when the on-disk set already matches the shipped build.
    /// </summary>
    public const string CatalogVersion = "2.6.0";

    // --- Model governance -----------------------------------------------------------------
    // Pro is reserved for templates whose output requires correlation or adversarial reasoning
    // (identity abuse, persistence, crypto posture). Flash handles high-volume structured
    // parsing where the analysis is largely tabular - this keeps per-mission cost proportional
    // to analytic difficulty rather than defaulting the whole fleet onto the expensive model.
    // Both were Claude 3 snapshots until 2026-09-11, retired and answering 404: every mission's
    // first request failed, and only the quality island's escalation rescued the analysis.
    private const string ModelPro = "claude-sonnet-5";
    private const string ModelFlash = "claude-haiku-4-5";

    // --- Egress governance ----------------------------------------------------------------
    // Single source of truth for the approved AI-gateway FQDN, declared centrally so a
    // per-template typo can never silently widen the whitelist. Since the IModelStreamClient
    // refactor, the ACTIVE egress pin is applied by the provider client itself (it knows which
    // host it is about to call); this rule is the governance declaration recorded in templates
    // and audit rows. It names the default provider (Anthropic Claude).
    private const string AiGatewayFqdn = "api.anthropic.com";

    private static readonly EgressRule AiGatewayEgress = new(
        AiGatewayFqdn,
        443,
        true,
        "Anthropic Claude API (default governed AI gateway; egress pinned by provider client)");

    // The first non-gateway destination in the catalog: a template whose SENSOR reaches the network
    // rather than reading the local machine. Declaring it here is what makes the reach governable -
    // TemplatePolicyCompiler resolves this FQDN and pins the /32s into the mission's BPF-LSM
    // LeaseSpec, so on the Linux substrate the tool can open exactly this host on 443 and nothing
    // else.
    //
    // EgressScope.ToolProcess is what carries that fact to the sandbox, and it is the ONLY thing
    // that keeps a network stack switched on for a tool: every other template in this catalog now
    // runs in an AppContainer with zero capabilities and cannot open a socket at all. The cost of
    // that reach is that Windows cannot yet pin WHICH host - an AppContainer chooses network or no
    // network, not a destination - so for this rule specifically the FQDN remains an audited
    // governance claim rather than an enforced boundary until a broker or WFP filter lands.
    // Templates using it must therefore stay read-only and credential-free.
    //
    // Declaring a tool egress does not widen the AI call - the provider client opens its own scope
    // for the synthesis leg, so that request stays pinned to the gateway regardless of this rule.
    private const string GrantsGovFqdn = "api.grants.gov";

    private static readonly EgressRule GrantsGovEgress = new(
        GrantsGovFqdn,
        443,
        true,
        "Grants.gov public Search2 API (read-only opportunity discovery; no credential presented)",
        EgressScope.ToolProcess);

    // --- Tool host binaries ----------------------------------------------------------------
    private const string CmdExe = @"C:\Windows\System32\cmd.exe";
    private const string PowerShellExe = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    private const string WevtutilExe = @"C:\Windows\System32\wevtutil.exe";

    // --- Category taxonomy ------------------------------------------------------------------
    private const string CatIdentity = "Identity & Access";
    private const string CatEndpoint = "Endpoint Security";
    private const string CatNetwork = "Networking";
    private const string CatSysOps = "SysOps & Fleet Health";
    private const string CatCompliance = "Compliance & Audit";
    private const string CatCampus = "Campus & Branch Operations";
    private const string CatAutonomous = "Autonomous Operations & Marketing";
    private const string CatLinuxGuest = "Linux Guest (WSL2)";
    private const string CatSources = "Source Discovery & Feeds";

    // --- Exit code policies -----------------------------------------------------------------
    private static readonly int[] ExitOk = { 0 };

    // powershell.exe returns 1 when the final statement in the pipeline raised a terminating
    // error. Diagnostic templates deliberately use -ErrorAction SilentlyContinue on optional
    // probes, so a 1 still carries usable partial output and must not be treated as a failure.
    private static readonly int[] ExitOkOrPartial = { 0, 1 };

    // 9009 is cmd.exe's "command not recognised" - the expected result when a role-specific
    // binary (appcmd, sqlcmd, nltest) is absent because the host does not hold that role.
    // Surfacing it to the model as evidence beats failing the mission with no output.
    private static readonly int[] ExitOkOrToolAbsent = { 0, 1, 2, 9009 };

    private static long Mb(int megabytes) => megabytes * 1024L * 1024L;

    /// <summary>
    /// Wraps a PowerShell one-liner in the standard hardened invocation preamble.
    /// -NoProfile prevents operator profile scripts from mutating the parsed output surface,
    /// and -NonInteractive guarantees the child cannot stall on a credential prompt inside the
    /// job object until the timeout kill fires and burns the whole mission budget.
    /// </summary>
    private static string Ps(string script) =>
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \"" + script + "\"";

    /// <summary>
    /// The work a table cannot do. Every sensor here is a PowerShell one-liner an engineer could run
    /// in a console; what the console cannot return is the judgement - which of forty autoruns is
    /// the one that matters, what this host has been doing across all six sections at once, the
    /// benign reading and the hostile reading of the same line, and the order to work in. This
    /// block asks for exactly that, in labelled parts, from the templates whose evidence rewards it.
    ///
    /// It sits inside the honesty invariant rather than around it. Findings still quote the output
    /// and are still attested against it by <c>TelemetryGrounder</c>; what the model knows from
    /// outside the output - ATT&amp;CK technique ids, CIS items, end-of-life dates, what a vendor's
    /// agent normally looks like - goes in the analysis and the actions, labelled as knowledge, where
    /// nothing can mistake it for a measurement. The anti-hedging evaluator penalises "cannot be
    /// determined", so the block asks for what is missing instead.
    /// </summary>
    private const string AnalystReasoning =
        "\n\n[ANALYST REASONING - what a table cannot do]\n" +
        "Before the JSON, write four short labelled parts:\n" +
        "STORY - three to five sentences: what this host has been doing according to the evidence, read across " +
        "every section of the output at once, naming the two or three items that decide the verdict.\n" +
        "KNOWN-GOOD - the entries an experienced engineer would recognise and wave through (Windows components, " +
        "signed vendor agents, management tooling) with a one-line reason each is expected here, and the " +
        "lookalike that would NOT be waved through.\n" +
        "HYPOTHESES - for each item you flag, the most likely benign explanation, the most likely hostile one, " +
        "and the single piece of evidence that would settle it.\n" +
        "PLAN - the order to work in and why: the cheap check that refutes the worst hypothesis first, then " +
        "containment, then cleanup.\n" +
        "Then the JSON. Findings quote values from the output. recommendedActions carry the plan: each names " +
        "the exact command, setting or event to check, and where it applies the MITRE ATT&CK technique id or " +
        "CIS benchmark item it maps to, labelled as knowledge. Give a verdict; where evidence is thin, say what " +
        "is missing rather than that it cannot be determined.";

    /// <summary>A role prompt with <see cref="AnalystReasoning"/> appended. Opt-in per template, on purpose.</summary>
    private static string Reasoned(string rolePrompt) => rolePrompt + AnalystReasoning;

    /// <summary>
    /// Builds a template already bound to the single approved egress rule, enforcing the
    /// 1 Template -> 1 Model -> 1 Tool -> 1 Egress FQDN contract at construction time.
    ///
    /// <paramref name="egress"/> overrides the default gateway rule for the rare template whose
    /// SENSOR itself needs a destination. It stays an explicit per-call opt-in so the whole set of
    /// network-reaching templates is greppable: every omission of the argument is a template whose
    /// tool touches nothing but the local machine.
    /// </summary>
    private static SingleToolTemplate Template(
        string templateId,
        string name,
        string description,
        string category,
        string model,
        SingleToolDefinition tool,
        string systemPrompt,
        Dictionary<string, string>? parameters = null,
        EgressRule? egress = null) =>
        new(templateId,
            name,
            description,
            category,
            model,
            tool,
            egress ?? AiGatewayEgress,
            systemPrompt,
            parameters ?? new Dictionary<string, string>());

    private static IReadOnlyList<SingleToolTemplate>? _all;

    /// <summary>
    /// The full governed catalog. Built once and validated eagerly so a malformed template
    /// fails fast at startup rather than at mission-dispatch time in front of an operator.
    /// </summary>
    public static IReadOnlyList<SingleToolTemplate> All => _all ??= BuildAll();

    /// <summary>
    /// The templates whose answer does not change when the network is denied them.
    ///
    /// Network denial is an AppContainer with no capabilities at Low integrity, which takes RPC to
    /// the system services and the ICMP handle away along with the sockets. On 2026-09-20 every
    /// template then being denied was run inside the container and outside it, same jail and same
    /// restricted token: 21 of 33 answered differently inside, three of them with nothing at all
    /// and an exit code of 0. So the catalog no longer guesses from the command line which tools
    /// survive in there. This list is the measurement, and
    /// <c>NetworkToolsUnderDenialTests</c> re-runs it: a template named here that stops surviving
    /// fails the build, and one not named here that would survive is reported so the list can grow.
    ///
    /// It is short, and honestly so. Four of these are templates that compose text and touch
    /// nothing, three produce no evidence in or out of the container because they need rights the
    /// restricted token removes (<c>CatalogProducesEvidenceTests</c> holds those), and one - the SChannel audit - is a real
    /// sensor that genuinely works while denied. The control this tier actually wants is a
    /// socket-layer filter that does not double as an RPC wall; <c>docs/THREAT-MODEL.md</c> has the
    /// argument, and the roadmap has the row.
    /// </summary>
    private static readonly HashSet<string> DenialMeasuredHarmless = new(StringComparer.Ordinal)
    {
        "dev-app-provisioner-bot",
        "endpoint-bitlocker-compliance",
        "grants-budget-compliance-auditor",
        "grants-eligibility-proposal-engine",
        "identity-lockout-trace",
        "marketing-social-campaign-publisher",
        "secops-auth-inspector",
        "secops-tls-cipher-audit",
        // Added 2026-09-21, after reading what they return rather than only the comparison's verdict.
        "compliance-legacy-protocols",
        "endpoint-mdm-enrollment",
        // Added 2026-09-23. It exists to meet the container: its connect attempt is the one line
        // that changes inside, from ALLOWED to BLOCKED, and that is the evidence it is for.
        "compliance-containment-self-proof",

        // Two left on 2026-09-22, when fixing them made them produce evidence at all. Denial had
        // measured harmless because they answered with nothing on either side. sysops-disk-space
        // now reads WMI, which the container refuses; identity-kerberos-spn's klist is refused its
        // own ticket cache inside, and its SPN scan needs a domain controller.

        // Three others the comparison calls unchanged are deliberately absent, because reading what
        // they return says otherwise: sysops-ad-dc-health resolves its domain controller to
        // 127.0.0.1 inside the container and to the real server outside it, identity-entra-hybrid-join
        // loses about 700 characters of its device state, and sysops-boot-performance loses its boot
        // time to "Attempted to perform an unauthorized operation". The test reports all three as
        // containment left on the table. It is not.
    };



    private static IReadOnlyList<SingleToolTemplate> BuildAll()
    {
        var all = new List<SingleToolTemplate>();
        all.AddRange(IdentityAccessTemplates());
        all.AddRange(EndpointSecurityTemplates());
        all.AddRange(NetworkingTemplates());
        all.AddRange(SysOpsTemplates());
        all.AddRange(ComplianceTemplates());
        all.AddRange(CampusOperationsTemplates());
        all.AddRange(AutonomousOperationsTemplates());
        all.AddRange(LinuxLeaseTemplates());
        all.AddRange(SourceDiscoveryTemplates());
        all.AddRange(ConsumerCatalogTemplates());
        all.AddRange(ConsumerEvidenceTemplates());

        for (int i = 0; i < all.Count; i++)
        {
            all[i] = all[i] with
            {
                NetworkDenialMeasuredHarmless = DenialMeasuredHarmless.Contains(all[i].TemplateId)
            };
        }

        // A duplicate TemplateId would not error at the storage layer - the registry upserts on
        // conflict, so the second definition would silently overwrite the first and the operator
        // would run a template whose behaviour does not match its catalog entry. Fail the build
        // of the catalog instead.
        var duplicateTemplateIds = all
            .GroupBy(t => t.TemplateId, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateTemplateIds.Count > 0)
        {
            throw new InvalidOperationException(
                $"Governed catalog integrity failure - duplicate TemplateId(s): {string.Join(", ", duplicateTemplateIds)}");
        }

        var duplicateToolIds = all
            .GroupBy(t => t.Tool.ToolId, StringComparer.OrdinalIgnoreCase)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicateToolIds.Count > 0)
        {
            throw new InvalidOperationException(
                $"Governed catalog integrity failure - duplicate ToolId(s): {string.Join(", ", duplicateToolIds)}");
        }

        foreach (var template in all)
        {
            template.ValidateStrictRules();
        }

        return all;
    }
}
