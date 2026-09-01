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
    public const string CatalogVersion = "2.3.0";

    // --- Model governance -----------------------------------------------------------------
    // Pro is reserved for templates whose output requires correlation or adversarial reasoning
    // (identity abuse, persistence, crypto posture). Flash handles high-volume structured
    // parsing where the analysis is largely tabular - this keeps per-mission cost proportional
    // to analytic difficulty rather than defaulting the whole fleet onto the expensive model.
    private const string ModelPro = "claude-3-5-sonnet-20241022";
    private const string ModelFlash = "claude-3-5-haiku-20241022";

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
    // else. On Windows the Win32 job object clamps memory, CPU, privilege and filesystem but does
    // NOT filter sockets, so there the declaration is an audited governance claim rather than an
    // enforced boundary. Templates using it must therefore stay read-only and credential-free: the
    // containment that makes a fetch safe is not switched on yet on the platform SPLAT ships on.
    // Declaring a tool egress does not widen the AI call - the provider client opens its own scope
    // for the synthesis leg, so that request stays pinned to the gateway regardless of this rule.
    private const string GrantsGovFqdn = "api.grants.gov";

    private static readonly EgressRule GrantsGovEgress = new(
        GrantsGovFqdn,
        443,
        true,
        "Grants.gov public Search2 API (read-only opportunity discovery; no credential presented)");

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
