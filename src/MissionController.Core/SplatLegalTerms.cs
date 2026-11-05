using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace MissionController.Core;

public sealed record LegalDocumentSection(
    string Key, string Uri, string ShortTitle, string Title, string Summary, string FullText);

/// <summary>Community license and informational notices. Existing resource keys remain stable.</summary>
public static class SplatLegalTerms
{
    public const string OwnerEntity = "PLATTEN INDUSTRIES LLC";
    public const string ContactEmail = "plattenindustries@gmail.com";
    public const string ShortNotice =
        "SPLAT Community is licensed under AGPL-3.0-only. Commercial use is permitted. " +
        "Receiving or running it does not require accepting an additional SPLAT EULA. " +
        "See the full license for distribution, source, warranty and liability terms. " +
        "Alternative commercial permissions require a separately executed agreement; third-party licenses remain applicable.";

    public const string EulaTitle = "SPLAT Community License (AGPL-3.0-only)";
    public const string LimitedLiabilityTitle = "Warranty and Liability Notice";
    public const string TermsOfUseTitle = "Operating Guidance and License Scope";
    public const string PrivacyPolicyTitle = "SPLAT Privacy Policy (Local-First Zero-Telemetry Security Software)";

    public static string AgplLicenseText { get; } = ReadLicense();

    // Keep the historical property name and resource URI for callers; this is not a second EULA.
    public static string EulaText { get; } = """
        SPLAT COMMUNITY LICENSE NOTICE

        The published Community code is licensed under GNU Affero General Public License version 3
        only (AGPL-3.0-only). The complete license follows and controls over this explanatory notice.
        Commercial use is permitted. Receiving or running a copy does not require accepting an
        additional SPLAT EULA. Modification and propagation are subject to the license's conditions.

        Conveying covered binaries, modified or unmodified, requires Corresponding Source through a
        method allowed by section 6. Preserve the required notices. Modified network-interactive
        versions must prominently offer their Corresponding Source to all remote interacting users
        as section 13 specifies. Ordinary execution is not a source-disclosure trigger. Do not assume
        a blanket exemption for modified network services merely because they are called internal.

        The AGPL does not require submitting changes to Platten Industries or automatically cover
        independent programs and workload outputs. Third-party components retain their own licenses.
        Alternative permissions apply only through a separately executed commercial agreement and
        only to rights the licensor owns or is authorized to grant. This notice does not amend any
        existing signed agreement. These Community notices add no restrictions to the AGPL grant.

        Copyright and attribution notices remain applicable. Contact: plattenindustries@gmail.com.
        Full license:
        """ + Environment.NewLine + AgplLicenseText;

    public const string LimitedLiabilityText = """
        WARRANTY AND LIABILITY NOTICE

        For the Community edition, the warranty and liability provisions are those in sections
        15, 16 and 17 of the AGPL-3.0-only license, subject to applicable law. This notice imposes no
        additional indemnity, contractual liability cap, jurisdiction or termination condition.
        A separately executed commercial or support agreement may provide its own terms; merely
        installing, viewing these notices or running Community does not execute such an agreement.

        Read SUPPORTED_POLICY.md and the platform threat model before deployment. Enforcement and
        proof cover the specified build, configuration and policy dimensions. Local administrators,
        inherited resources, telemetry loss and other documented limits require deployment-specific
        consideration. A software license is not an assurance of security or regulatory compliance.
        """;

    public const string TermsOfUseText = """
        OPERATING GUIDANCE AND LICENSE SCOPE

        This is informational guidance, not an additional license or acceptance requirement.
        Operate only systems and accounts you are authorized to administer, follow applicable law,
        review workload permissions and preserve relevant evidence. These recommendations do not
        add field-of-use restrictions or alter the permissions or termination provisions of AGPL.

        Inspect the supported-policy and threat-model documents for the exact deployment. Protect
        credentials, ledger keys and signing keys. Regex-based secret masking is best-effort, and
        local keys do not make evidence immune to privileged host manipulation.

        Operator-configured AI gateways and SIEM destinations receive data under their own terms
        and privacy policies. The operator selects those services and manages their charges and
        credentials. Review sensitive output before sharing logs or bundles.

        Independent mission outputs are not claimed by Platten Industries merely because SPLAT
        generated them. Included third-party material retains its own rights. Trade names and marks
        remain separate from copyright permissions; the AGPL grants no general trademark license.
        """;

    private static string ReadLicense()
    {
        using var stream = typeof(SplatLegalTerms).Assembly.GetManifestResourceStream("Splat.Licenses.AGPL-3.0-only.txt")
            ?? throw new InvalidOperationException("The Community license resource is missing.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    public const string PrivacyPolicyText = """
        SPLAT — PRIVACY POLICY
        Owner and Publisher: PLATTEN INDUSTRIES LLC (LaFayette, Georgia, United States)

        SUMMARY: SPLAT IS LOCAL-FIRST SECURITY SOFTWARE. PLATTEN INDUSTRIES LLC COLLECTS ZERO TELEMETRY, OPERATES NO CLOUD COLLECTION SERVERS FOR SPLAT, AND NEVER RECEIVES YOUR PROMPTS, API KEYS, AUDIT LEDGERS, OR HOST DATA.

        1. Zero Telemetry and No "Phone-Home"
        SPLAT (MissionController.UI, splat-mcp, splat-agent, splat-canary, and splat-bench) contains:
        * No usage analytics, tracking beacons, or telemetry callbacks to PLATTEN INDUSTRIES LLC;
        * No automatic crash reporting to PLATTEN INDUSTRIES LLC;
        * No cloud license-check or seat-count servers; and
        * No cloud embedding calls (semantic incident memory computes 128-dimensional embeddings entirely in-process).
        PLATTEN INDUSTRIES LLC receives zero bytes of network traffic from your SPLAT installation.

        2. Local Data Storage on Your Host
        All operational data generated by SPLAT is stored strictly on your local machine under your administrative control:
        * Chained Audit Ledger (`SqliteChainedAuditLedger`): Stored locally in WAL-mode SQLite under `%LOCALAPPDATA%\SPLAT` (or `SPLAT_DB_PATH`).
        * Local Semantic Memory (`SqliteSemanticMemoryIndex`): Stored locally in SQLite using in-process vector embeddings.
        * Credential Vault (`DpapiCredentialVault`): Encrypts your AI provider API keys and tokens at rest on disk using Windows DPAPI (`CurrentUser` scope with application entropy).
        * WSL2 Guest Secrets (`splat-agent`): Root-owned (`0600`) authentication token, lease ceiling (`/etc/splat/policy.json`), and guest outcome signing key (`/etc/splat/outcome.key`) inside your local WSL2 distribution.
        * MCP Workspace & Crash Logs: Confined to `%LOCALAPPDATA%\SPLAT\mcp-workspace` (or `--workspace <dir>`) and `%LOCALAPPDATA%\SPLAT\crash.log`.
        * Exported Run Records (`ComplianceArchiveExporter`): Written only to local paths you explicitly specify.

        3. Sensitive Process and Host Information
        Because SPLAT executes system diagnostics and process containment, local ledger rows and run records may capture live OS state, including usernames, Windows SIDs, process command lines, file paths, registry paths, and network socket tables. You are the sole custodian and data controller of these local files. Clear any confidential secrets before sharing exported bundles or bug reports.

        4. Operator-Configured External Egress
        Data leaves your host ONLY when you explicitly configure and invoke an external destination:
        (a) AI Model Gateways (Anthropic Claude / Google Gemini): When you supply an API key and run an AI-assisted mission, prompts and tool outputs pass through the in-memory `RegexDataLossPreventionSanitizer` (best-effort regex masking of common secrets/PII) and `EgressFirewallHandler` before being sent directly from your host to your chosen provider under that provider's privacy policy.
        (b) SIEM & EDR Forwarders (`SiemForwarder`, `EdrIngestionBridge`): Transmit only to the Sentinel, CEF, syslog, or EDR endpoints you configure.
        (c) Network-Permitted Leases: Connect only to destinations permitted by the template or `--egress` policy.

        5. Data Retention and Cryptographic Erasure
        You may delete your local SQLite databases, DPAPI vault secrets, or logs at any time. In addition, `SqliteChainedAuditLedger` commits each chain hash to a salted digest of the payload rather than raw plaintext, enabling you (`splat-mcp retain --apply`) to purge historical payload plaintext while preserving hash-chain and Merkle-root verifiability.

        6. Direct Contact
        If you email PLATTEN INDUSTRIES LLC at plattenindustries@gmail.com (for commercial licensing, CLA submission, or security reporting), we use your contact details solely to reply and maintain project records, and never sell or rent them to third parties.
        """;

    public static IReadOnlyList<LegalDocumentSection> AllDocuments { get; } = new[]
    {
        new LegalDocumentSection(
            Key: "eula",
            Uri: "splat://legal/eula",
            ShortTitle: "AGPL License",
            Title: EulaTitle,
            Summary: "Community license notice and the complete, unchanged AGPL-3.0-only text.",
            FullText: EulaText),
        new LegalDocumentSection(
            Key: "liability",
            Uri: "splat://legal/limited-liability",
            ShortTitle: "Warranty Notice",
            Title: LimitedLiabilityTitle,
            Summary: "AGPL warranty and liability provisions; separately executed commercial agreements remain separate.",
            FullText: LimitedLiabilityText),
        new LegalDocumentSection(
            Key: "terms",
            Uri: "splat://legal/terms-of-use",
            ShortTitle: "Operating Guidance",
            Title: TermsOfUseTitle,
            Summary: "Operating guidance, configured external services and output rights; no additional Community license conditions.",
            FullText: TermsOfUseText),
        new LegalDocumentSection(
            Key: "privacy",
            Uri: "splat://legal/privacy-policy",
            ShortTitle: "Privacy Policy",
            Title: PrivacyPolicyTitle,
            Summary: "100% local-first security software posture: zero phone-home telemetry, local SQLite/DPAPI storage, and salted-digest erasure.",
            FullText: PrivacyPolicyText),
    };

    public static LegalDocumentSection? TryGetByKeyOrUri(string? selector)
    {
        if (string.IsNullOrWhiteSpace(selector))
        {
            return null;
        }

        string normalized = selector.Trim().ToLowerInvariant();
        return normalized switch
        {
            "eula" or "license" or "splat://legal/eula" => AllDocuments[0],
            "liability" or "limited-liability" or "limited_liability" or "splat://legal/limited-liability" => AllDocuments[1],
            "terms" or "terms-of-use" or "terms_of_use" or "tou" or "splat://legal/terms-of-use" => AllDocuments[2],
            "privacy" or "privacy-policy" or "privacy_policy" or "splat://legal/privacy-policy" => AllDocuments[3],
            _ => AllDocuments.FirstOrDefault(d =>
                string.Equals(d.Key, normalized, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(d.Uri, normalized, StringComparison.OrdinalIgnoreCase))
        };
    }

    public static string FormatAll()
    {
        var sb = new StringBuilder();
        sb.AppendLine("================================================================================");
        sb.AppendLine("SPLAT — LEGAL AGREEMENTS & POLICIES (PLATTEN INDUSTRIES LLC)");
        sb.AppendLine("================================================================================");
        sb.AppendLine(ShortNotice);
        sb.AppendLine();

        for (int i = 0; i < AllDocuments.Count; i++)
        {
            var doc = AllDocuments[i];
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine($"[{i + 1}/{AllDocuments.Count}] {doc.Title} ({doc.Uri})");
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine(doc.FullText);
            sb.AppendLine();
        }

        return sb.ToString().TrimEnd();
    }
}
