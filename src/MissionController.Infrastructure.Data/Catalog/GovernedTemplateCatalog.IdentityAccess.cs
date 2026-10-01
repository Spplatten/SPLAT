using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static partial class GovernedTemplateCatalog
{
    private static IEnumerable<SingleToolTemplate> IdentityAccessTemplates() => new[]
    {
        // --- 4624/4625 brute-force detector -------------------------------------------------
        // The Security channel is ACL'd, but the restricted token is deliberately KEPT: the
        // product's zero-local-admin pillar means the correct access path is the non-admin
        // "Event Log Readers" (S-1-5-32-573) delegation, and CreateRestrictedToken only drops the
        // ADMINISTRATORS SID (S-1-5-32-544) - a delegated Event Log Readers membership survives
        // the restriction intact. An operator without that delegation gets 0x5 and empty stdout,
        // so the prompt below is required to report the access failure as a delegation gap rather
        // than as "zero failed logons", which would be a silent false-negative on a detector.
        Template(
            "secops-auth-inspector",
            "Auth Inspector (4624/4625 Brute-Force)",
            "Extracts successful and failed logon events from the Windows Security channel to surface password-spray and brute-force patterns.",
            CatIdentity,
            ModelPro,
            new SingleToolDefinition(
                "wevtutil_security_tool",
                "Windows Event Log Security Channel Query",
                WevtutilExe,
                // /rd:true reads newest-first so /c: caps the set at the MOST RECENT events rather
                // than truncating at the oldest; the timediff predicate bounds the window
                // server-side to keep the payload inside the memory clamp on busy controllers.
                "qe Security /q:\"*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= {LookbackWindowMs}]]]\" /c:{MaxEventCount} /rd:true /f:text",
                // Access-denied is a legitimate, expected outcome for an under-delegated operator,
                // so 0x5 is admitted as a result the model must interpret rather than a crash.
                new[] { 0, 5 },
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(384),
                MaxCpuPercent: 60),
            Reasoned("You are a Tier-2 SecOps Identity Analyst. FIRST: if the output is empty or contains an access-denied error, report exactly that the operator lacks 'Event Log Readers' delegation on this host and that the audit was NOT performed - never state or imply that no failed logons were found, because an unreadable log and a clean log are not the same result. Otherwise, correlate 4625 failures by Account Name, Source Network Address and Logon Type. Flag password-spray (many distinct accounts from one source), brute-force (one account, many attempts), and any 4625 burst immediately followed by a 4624 success from the same source. Decode Status/Sub Status codes (0xC000006A bad password, 0xC0000064 unknown user, 0xC0000234 locked out, 0xC0000072 disabled). Treat Logon Type 3 (network) and 10 (RDP) from external addresses as higher severity than Type 2 (console). State the recommended containment action. Beyond decoding the events, say what the actor is doing: a spray, credential stuffing, a targeted brute force, or a service or scheduled task retrying a stale password - and which of those the timing, the account mix and the sub-status codes actually support. Map it as knowledge with its ATT&CK id: T1110.003 spray, T1110.004 stuffing, T1110.001 brute force, T1078 when a success follows the failures."),
            new Dictionary<string, string>
            {
                { "LookbackWindowMs", "86400000" }, // 24h rolling window
                { "MaxEventCount", "400" }
            }),

        // --- Domain controller locator & SRV health ------------------------------------------
        Template(
            "sysops-ad-dc-health",
            "AD / Domain Controller Locator & DNS SRV Health",
            "Verifies domain controller discovery, the machine secure channel, and the _ldap/_kerberos DNS SRV records required for domain logon.",
            CatIdentity,
            ModelPro,
            new SingleToolDefinition(
                "ad_dc_health_tool",
                "NLTest DC Locator & NSLookup SRV Verifier",
                CmdExe,
                // Stages are joined with a single '&' rather than '&&': a non-domain-joined or
                // partitioned host fails nltest immediately, and '&&' would suppress the DNS SRV
                // evidence that decides whether the fault is secure-channel breakage or name
                // resolution failure - the single most useful discriminator in this diagnostic.
                "/c nltest /dsgetdc:{DomainFqdn} & echo --- SECURE CHANNEL --- & nltest /sc_query:{DomainFqdn} & echo --- LDAP SRV RECORDS --- & nslookup -type=SRV _ldap._tcp.dc._msdcs.{DomainFqdn} & echo --- KERBEROS SRV RECORDS --- & nslookup -type=SRV _kerberos._tcp.dc._msdcs.{DomainFqdn} & echo --- SITE-AWARE DC LIST --- & nltest /dclist:{DomainFqdn}",
                // cmd /c surfaces only the final stage's code and nltest returns raw Win32 status,
                // so 1311 (ERROR_NO_LOGON_SERVERS) and 1355 (ERROR_NO_SUCH_DOMAIN) are diagnostic
                // findings for the model to explain, not harness-level execution failures.
                new[] { 0, 1, 1311, 1355 },
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 50),
            Reasoned("You are an Active Directory Infrastructure Engineer. Determine whether DC location succeeded, whether the returned DC sits in the client's own site (a cross-site referral implies a subnet-to-site mapping gap), and whether the secure channel is intact. Cross-check that every DC named by /dclist has matching _ldap and _kerberos SRV records; missing or stale records indicate DNS scavenging or a failed dynamic registration. Decode nltest status codes (1355 no such domain, 1311 no logon servers, 1787 broken secure channel) and give the exact remediation command."),
            new Dictionary<string, string>
            {
                { "DomainFqdn", "corp.contoso.com" }
            }),

        // --- Kerberos ticket & SPN hygiene ------------------------------------------------------
        // Restricted token is KEPT here: klist reads the caller's own ticket cache and setspn
        // performs an authenticated LDAP read, both of which work correctly at Medium integrity.
        // 'klist tgt' is deliberately excluded - it requires elevation and its only unique output
        // is the TGT itself, which is credential material that must never enter the egress stream.
        // 'klist sessions' is excluded too: listing other logon sessions needs elevation, and under
        // this token it answered nine of eleven sessions with access-denied errors.
        // The network is not denied. setspn's duplicate scan is an LDAP query to a domain
        // controller, so on a domain member - the only machine where this template has anything to
        // find - the container would blind it. Denial measured harmless only on a workgroup machine,
        // where there is no controller to reach from either side.
        Template(
            "identity-kerberos-spn",
            "Kerberos Ticket & Duplicate SPN Auditor",
            "Inspects the Kerberos ticket cache, encryption types in use, and scans the domain for duplicate Service Principal Names.",
            CatIdentity,
            ModelPro,
            new SingleToolDefinition(
                "kerberos_spn_tool",
                "KList Cache & SetSPN Duplicate Scanner",
                CmdExe,
                "/c klist & echo --- DOMAIN DUPLICATE SPN SCAN --- & setspn -X -P & echo --- COMPUTER ACCOUNT SPNs --- & setspn -L %COMPUTERNAME%",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 50),
            Reasoned("You are a Kerberos Authentication Specialist. Report the encryption types negotiated on cached tickets and flag any RC4-HMAC (etype 23) or DES usage as downgrade risk requiring AES enforcement. Every duplicate SPN reported by setspn -X breaks Kerberos authentication for ALL services sharing it and forces an NTLM fallback - list each duplicate with the accounts holding it and state which registration should be removed. Flag tickets whose renew-until window has lapsed. Do not reproduce any ticket, key, or hash material in your analysis."),
            null),

        // --- Local privileged group drift ---------------------------------------------------------
        Template(
            "identity-local-admin-drift",
            "Local Administrator & Privileged Group Drift",
            "Enumerates local Administrators, Remote Desktop Users, and local account state to detect privilege drift from the approved baseline.",
            CatIdentity,
            ModelPro,
            new SingleToolDefinition(
                "local_privilege_tool",
                "Local Privileged Group Enumerator",
                PowerShellExe,
                // Groups are addressed by well-known SID rather than by name: on a non-English
                // campus image 'Administrators' is localised (Administratoren, Administrateurs)
                // and a name lookup would throw, producing an empty result that reads as a clean
                // machine. SID S-1-5-32-544 / S-1-5-32-555 are locale-invariant.
                Ps(@"Write-Output '--- LOCAL ADMINISTRATORS (S-1-5-32-544) ---'; Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass,PrincipalSource | Format-Table -AutoSize; Write-Output '--- REMOTE DESKTOP USERS (S-1-5-32-555) ---'; Get-LocalGroupMember -SID S-1-5-32-555 -ErrorAction SilentlyContinue | Select-Object Name,ObjectClass,PrincipalSource | Format-Table -AutoSize; Write-Output '--- LOCAL ACCOUNTS ---'; Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name,Enabled,PasswordRequired,PasswordExpires,PasswordLastSet,LastLogon,SID | Format-Table -AutoSize; Write-Output '--- LAPS POLICY STATE ---'; Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction SilentlyContinue | Select-Object BackupDirectory,PasswordAgeDays,PasswordComplexity,PasswordLength,ADPasswordEncryptionEnabled | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            Reasoned("You are an Identity Governance Analyst. Flag every local Administrators member that is not the built-in Administrator, an approved domain admin group, or the endpoint management account. Direct user SIDs (rather than group membership) indicate manual grants that bypass access review and must be called out individually. Report enabled local accounts with PasswordRequired false or PasswordExpires null as standing risk. Confirm LAPS is configured with a BackupDirectory - an unmanaged built-in Administrator password shared across a campus image enables lateral movement across every machine at once. Never request or display any password value."),
            null),

        // --- Domain group membership & orphan account hygiene -------------------------------------------
        // Every stage here is an ordinary authenticated LDAP read, so this runs cleanly for a
        // Tier-1 technician under the restricted token with no delegation beyond domain user.
        Template(
            "identity-ad-group-hygiene",
            "AD Group Membership & Orphan Account Hygiene",
            "Audits effective token group membership and enumerates privileged domain groups for access review and orphan detection.",
            CatIdentity,
            ModelPro,
            new SingleToolDefinition(
                "ad_group_hygiene_tool",
                "Token Group & Privileged Group Enumerator",
                CmdExe,
                // 'whoami /groups' reports the groups actually present in the access token, which
                // is what authorisation decisions use. It differs from directory membership after
                // a group change until the user re-authenticates, and that gap is the usual reason
                // a freshly granted permission "does not work" - capturing both sides makes the
                // discrepancy visible in a single mission rather than two escalations.
                "/c whoami /upn & echo --- TOKEN GROUP MEMBERSHIP --- & whoami /groups & echo --- PRIVILEGES IN TOKEN --- & whoami /priv & echo --- DOMAIN ADMINS --- & net group \"Domain Admins\" /domain & echo --- ENTERPRISE ADMINS --- & net group \"Enterprise Admins\" /domain & echo --- DOMAIN ACCOUNT POLICY --- & net accounts /domain",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 120,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            Reasoned("You are an Identity Governance Analyst performing access review. Distinguish the operator's TOKEN groups from current directory membership and state that a recent group change will not appear in the token until the next logon - this single fact explains most 'permission granted but still denied' tickets. Flag any privileged group present in the token (Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators) as standing privilege that violates least-privilege for a Tier-1 role. In the privileged group listings, call out service accounts, disabled-looking naming conventions, and any account whose name suggests it is a shared or generic credential, since these are the usual orphans in a long-lived campus domain. Report the domain password and lockout policy against the organisation's standard. Never request or display any password."),
            null),

        // --- Entra ID / hybrid join state -----------------------------------------------------------
        Template(
            "identity-entra-hybrid-join",
            "Entra ID Join & Hybrid Device Registration State",
            "Reports device join type, Entra ID registration, PRT status, and tenant details for hybrid-joined fleet troubleshooting.",
            CatIdentity,
            ModelPro,
            new SingleToolDefinition(
                "dsregcmd_join_tool",
                "DSRegCmd Device Registration Status",
                CmdExe,
                "/c dsregcmd /status",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(128),
                MaxCpuPercent: 40),
            Reasoned("You are a Modern Device Management Engineer. State the device's join posture from AzureAdJoined, EnterpriseJoined and DomainJoined. Explain the SSO State block: AzureAdPrt No with DomainJoined Yes on a hybrid device means the sync join has not completed and every Entra-backed resource will prompt for credentials. Flag PRT acquisition errors, an expired PrtUpdateTime, failed device authentication, and any certificate validity that has lapsed. Confirm the tenant name and device id match the expected campus tenant, and give the exact remediation sequence."),
            null)
    };
}
