using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace MissionController.Core;

/// <summary>One legal document as the console, the onboarding wizard and splat-mcp show it.</summary>
public sealed record LegalDocumentSection(
    string Key,
    string Uri,
    string ShortTitle,
    string Title,
    string Summary,
    string FullText);

/// <summary>
/// The SPLAT Community legal documents: the EULA, the Terms of Use and the Privacy Policy, owned and
/// published by Platten Industries LLC. Written for this product, not adapted from another vendor's
/// licence. Community is licensed under the AGPL-3.0, so each document is built to sit beside that
/// licence rather than over it: none restricts or conditions an AGPL right, and each says the AGPL
/// controls where they differ. The warranty disclaimer and liability limit are the additional terms
/// AGPL section 7(a) permits. Corporate extensions carry their own commercial terms.
/// </summary>
public static class SplatLegalTerms
{
    public const string OwnerEntity = "Platten Industries LLC";
    // The address the company publishes on rareresources.net/contact. Pinned by a test: an earlier
    // draft of these documents shipped a near miss that belongs to nobody we know.
    public const string ContactEmail = "platten.industries@gmail.com";

    public const string ShortNotice =
        "SPLAT Community is free software under the GNU AGPL-3.0. The EULA, Terms of Use and Privacy Policy " +
        "below add a warranty disclaimer and a limit on indirect damages, explain your responsibilities, and " +
        "state that SPLAT sends Platten Industries nothing. They never restrict a right the AGPL gives you.";

    public const string EulaTitle = "SPLAT End-User License Agreement";
    public const string TermsOfUseTitle = "SPLAT Terms of Use";
    public const string PrivacyPolicyTitle = "SPLAT Privacy Policy";

    public const string EulaText = """
        SPLAT END-USER LICENSE AGREEMENT
        Platten Industries LLC, LaFayette, Georgia, United States

        This agreement is between you and Platten Industries LLC ("Platten Industries"). It covers SPLAT
        Community: the Windows console, the splat-mcp server, the splat-agent lease daemon, the
        verification tools and their documentation.

        1. YOUR LICENCE IS THE AGPL
        SPLAT Community is licensed to you under the GNU Affero General Public License, version 3
        ("AGPL"). That licence, not this agreement, gives you the right to run, study, change and share
        the software. Nothing in this agreement restricts or conditions those rights. Where this
        agreement and the AGPL differ, the AGPL controls. Sections 4 and 5 are additional terms of the
        kind AGPL section 7(a) allows.

        2. CORPORATE EXTENSIONS
        SPLAT Corporate extensions are separate software, licensed only under a written commercial
        agreement with Platten Industries. This agreement grants no rights to them, and their
        availability takes nothing away from the AGPL rights in section 1.

        3. WHAT SPLAT RECORDS
        SPLAT runs diagnostics and contains processes on your computer. Its local audit ledger, memory
        index, run records and crash log can therefore contain usernames, Windows security identifiers,
        command lines, file and registry paths and network addresses. SPLAT masks common secrets before
        text is sent to an AI provider, but pattern matching cannot catch everything. You are
        responsible for what you send to the AI providers you configure and for what you share.
        What SPLAT does and does not enforce is listed in native/splat-agent/SUPPORTED_POLICY.md.

        4. NO WARRANTY
        The software is provided "as is", without warranty of any kind, express or implied, including
        merchantability, fitness for a particular purpose and non-infringement, to the extent the law
        allows. You bear the risk of using it.

        5. LIMIT OF LIABILITY
        To the extent the law allows, Platten Industries and its members, managers and contributors
        are not liable for indirect, incidental, special, consequential or punitive damages, including
        lost profits, lost data, downtime, terminated workloads or third-party AI charges, however
        caused. If you have a signed commercial agreement with Platten Industries, its liability terms
        apply instead. Some places do not allow these limits, and they do not take away consumer
        rights the law gives you.

        6. HIGH-RISK USE
        SPLAT is not designed for systems where a failure could cause death, injury or serious damage,
        such as life support, aviation, nuclear or medical device control. Do not rely on it there.

        7. EXPORT LAW
        You are responsible for complying with the export laws that apply to you and the software.

        8. CONTACT
        platten.industries@gmail.com
        """;

    public const string TermsOfUseText = """
        SPLAT TERMS OF USE
        Platten Industries LLC, LaFayette, Georgia, United States

        These terms describe how SPLAT is meant to be used and who is responsible for what. They sit
        beside the GNU AGPL-3.0, which is the licence for SPLAT Community; where they differ, the AGPL
        controls, and nothing here restricts a right it gives you.

        1. YOUR SYSTEMS
        SPLAT runs programs, applies operating-system sandboxes and loads kernel lease programs. Use it
        only on computers and networks you own or are authorized to administer. Before relying on the
        Linux kernel lease, check that the host enforces it (splat-mcp doctor).

        2. YOUR KEYS
        You keep your ledger key, run-record key and the AI provider keys SPLAT stores in the Windows
        credential vault. Whoever holds a key holds what it protects.

        3. AI PROVIDERS ARE YOURS
        Platten Industries does not supply or proxy AI provider keys. When you connect an Anthropic or
        Google key, that provider's terms, privacy policy and billing apply, and its charges are yours.

        4. YOUR OUTPUT IS YOURS
        Ledgers, run records, reports and mission output produced on your computer belong to you.
        Platten Industries claims no rights in them.

        5. HONEST RECORDS
        SPLAT labels unsigned run records and unkeyed ledgers as such. Presenting them as signed or
        attested is a misrepresentation by whoever makes it.

        6. NAMES
        "SPLAT" and "Platten Industries" are trade names of Platten Industries LLC. The AGPL grants no
        trademark rights (AGPL section 7(e)); a modified version should not be presented as ours.

        7. THE EULA
        The warranty disclaimer and the limit of liability in the EULA apply to your use.
        Contact: platten.industries@gmail.com.
        """;

    public const string PrivacyPolicyText = """
        SPLAT PRIVACY POLICY
        Platten Industries LLC, LaFayette, Georgia, United States

        In short: SPLAT runs on your computer and sends Platten Industries nothing.

        1. NOTHING COMES TO US
        SPLAT has no usage analytics, no tracking, no automatic crash reporting and no licence or seat
        server. Platten Industries receives no data from your installation.

        2. WHAT STAYS ON YOUR COMPUTER
        - The audit ledger and memory index: SQLite files in SPLAT's data folder (for the console,
          %LOCALAPPDATA%\SPLAT), or wherever SPLAT_DB_PATH points.
        - AI provider keys: encrypted with Windows DPAPI for your user account.
        - The crash log: crash.log in the same data folder.
        - In the WSL2 guest: the daemon's token, lease ceiling and signing key under /etc/splat.
        - Run records and compliance exports: written only where you choose.
        These can contain host details such as usernames, command lines and paths. You control them,
        and you can delete them at any time.

        3. WHEN DATA LEAVES YOUR COMPUTER
        Only when you make it:
        - An AI-assisted mission sends the masked evidence and prompt to the provider whose key you
          added, under that provider's privacy policy.
        - A template whose tool reads a public source contacts the address written in that template.
        - SIEM or EDR forwarding sends events to the endpoints you configure.
        - splat-mcp sends results to the agent client you connected it to.

        4. EMAIL
        If you write to platten.industries@gmail.com, we use your address to reply and keep a record of
        the conversation. We do not sell or rent it.

        5. CHANGES
        A change to this policy ships with the software and shows in its source history.
        """;

    public static IReadOnlyList<LegalDocumentSection> AllDocuments { get; } = new[]
    {
        new LegalDocumentSection(
            Key: "eula",
            Uri: "splat://legal/eula",
            ShortTitle: "EULA",
            Title: EulaTitle,
            Summary: "Your licence is the AGPL-3.0; this adds the warranty disclaimer and a limit on indirect damages.",
            FullText: EulaText),
        new LegalDocumentSection(
            Key: "terms",
            Uri: "splat://legal/terms-of-use",
            ShortTitle: "Terms of Use",
            Title: TermsOfUseTitle,
            Summary: "Authorized systems only, your keys, your AI providers' terms, and your output stays yours.",
            FullText: TermsOfUseText),
        new LegalDocumentSection(
            Key: "privacy",
            Uri: "splat://legal/privacy-policy",
            ShortTitle: "Privacy Policy",
            Title: PrivacyPolicyTitle,
            Summary: "SPLAT sends Platten Industries nothing; data leaves your computer only through what you configure.",
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
            "eula" or "license" or "licence" => AllDocuments[0],
            "terms" or "terms-of-use" or "tou" => AllDocuments[1],
            "privacy" or "privacy-policy" => AllDocuments[2],
            _ => AllDocuments.FirstOrDefault(d => string.Equals(d.Uri, normalized, StringComparison.OrdinalIgnoreCase))
        };
    }

    public static string FormatAll()
    {
        var sb = new StringBuilder();
        sb.AppendLine(ShortNotice);
        foreach (var doc in AllDocuments)
        {
            sb.AppendLine();
            sb.AppendLine(doc.FullText);
        }

        return sb.ToString().TrimEnd();
    }
}
