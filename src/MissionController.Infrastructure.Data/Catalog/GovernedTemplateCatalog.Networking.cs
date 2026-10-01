using MissionController.Core.Enums;
using MissionController.Core.Models;

namespace MissionController.Infrastructure.Data.Catalog;

public static partial class GovernedTemplateCatalog
{
    private static IEnumerable<SingleToolTemplate> NetworkingTemplates() => new[]
    {
        // --- Baseline connectivity ---------------------------------------------------------------
        Template(
            "net-dns-audit",
            "DNS & Network Connectivity Diagnostic",
            "Performs DNS resolution tests, gateway ping latency analysis, and active socket inspection.",
            CatNetwork,
            ModelPro,
            new SingleToolDefinition(
                "netstat_tool",
                "Netstat & Ping Diagnostic",
                CmdExe,
                "/c ping -n 2 {TargetHost} && netstat -ano",
                new[] { 0, 1 },
                TimeoutSeconds: 30,
                MaxMemoryBytes: Mb(128),
                MaxCpuPercent: 50),
            Reasoned("You are an expert Enterprise Network Engineer. Read the ping and netstat output together rather than section by section: latency and loss to the gateway, set against the resolvers and the public target, tells you whether the fault is the local link, the resolver, or the path beyond it. Flag high or variable latency, packet loss, listening ports that do not belong on a workstation, and established connections to unexpected remote ports. Say what the pattern means - a healthy gateway with a slow public target is upstream, loss to the gateway is local, resolution failing while raw addresses answer is DNS - and name the next measurement that would confirm it."),
            new Dictionary<string, string> { { "TargetHost", "8.8.8.8" } }),

        // --- TLS / SChannel posture ----------------------------------------------------------------
        Template(
            "secops-tls-cipher-audit",
            "TLS & SChannel Cipher Suite Auditor",
            "Enumerates active TLS cipher suites, SChannel protocol enablement keys, and LocalMachine certificate expiration windows.",
            CatNetwork,
            ModelPro,
            new SingleToolDefinition(
                "schannel_tls_tool",
                "SChannel Protocol & Certificate Store Scanner",
                PowerShellExe,
                // Registry keys are piped through Get-ItemProperty instead of a scriptblock: the
                // engine performs literal {Token} substitution over this string, so keeping the
                // command free of curly braces removes any chance of a PowerShell block colliding
                // with a parameter name.
                Ps(@"Get-TlsCipherSuite -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name; Write-Output '--- SCHANNEL PROTOCOL KEYS ---'; Get-ChildItem -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Recurse -ErrorAction SilentlyContinue | Get-ItemProperty -ErrorAction SilentlyContinue | Select-Object PSPath,Enabled,DisabledByDefault | Format-List; Write-Output '--- LOCALMACHINE CERTIFICATE EXPIRY ---'; Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Select-Object Subject,Issuer,Thumbprint,NotBefore,NotAfter,SignatureAlgorithm,HasPrivateKey | Format-List"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            Plain("An enabled-protocol and cipher inventory supports baseline checks; no negotiated handshake history is available.",
                "You are a Cryptographic Compliance Auditor. Flag every enabled legacy protocol (SSL 2.0/3.0, TLS 1.0/1.1) and any cipher suite using NULL, RC4, DES, 3DES, EXPORT, MD5, or non-forward-secret (non-ECDHE/DHE) key exchange. Note that an ABSENT Enabled value means the protocol falls back to the OS default rather than being disabled - never report a missing key as remediated. For certificates, list anything expired, expiring within 45 days, or signed with SHA-1/MD5, ordered by urgency."),
            null),

        // --- Corporate proxy / TLS break-and-inspect --------------------------------------------------
        Template(
            "network-proxy-config",
            "Corporate Proxy, PAC & TLS Inspection Chain",
            "Resolves the effective WinHTTP and WinINET proxy configuration, PAC/WPAD source, and the TLS break-and-inspect root in use.",
            CatNetwork,
            ModelPro,
            new SingleToolDefinition(
                "proxy_chain_tool",
                "WinHTTP & WinINET Proxy Resolver",
                CmdExe,
                // WinHTTP (machine/service context) and WinINET (per-user context) are separate
                // stacks that routinely disagree. Reading only one produces the classic false
                // diagnosis where a browser works but every service-context agent fails, so both
                // are captured in the same mission for side-by-side comparison.
                "/c netsh winhttp show proxy & echo --- WININET USER PROXY --- & reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" & echo --- MACHINE PROXY POLICY --- & reg query \"HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" & echo --- WPAD SERVICE --- & sc query WinHttpAutoProxySvc & echo --- WPAD DNS RESOLUTION --- & nslookup wpad.{DomainFqdn}",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(128),
                MaxCpuPercent: 40),
            Reasoned("You are an Enterprise Network Integration Engineer. Compare the WinHTTP proxy against the WinINET per-user proxy and call out any divergence, because a machine-context service will use WinHTTP while the technician's browser uses WinINET - this single mismatch explains most 'works in the browser, fails in the agent' escalations. Report whether configuration is by explicit proxy, PAC URL, or WPAD auto-detect, and note that WPAD resolving via DNS on an untrusted network is a credential-relay risk. Identify the ProxyOverride bypass list and flag whether the Vertex AI endpoint would traverse or bypass the inspection proxy."),
            new Dictionary<string, string>
            {
                { "DomainFqdn", "corp.contoso.com" }
            }),

        // --- SMB posture --------------------------------------------------------------------------------
        Template(
            "network-smb-posture",
            "SMB Signing, Encryption & Dialect Posture",
            "Reports SMB client and server signing requirements, encryption state, and the dialects negotiated on live connections.",
            CatNetwork,
            ModelPro,
            new SingleToolDefinition(
                "smb_posture_tool",
                "SMB Client & Server Configuration Probe",
                PowerShellExe,
                Ps(@"Write-Output '--- SMB CLIENT CONFIGURATION ---'; Get-SmbClientConfiguration -ErrorAction SilentlyContinue | Select-Object RequireSecuritySignature,EnableSecuritySignature,EnableMultiChannel,EnableInsecureGuestLogons,DirectoryCacheLifetime | Format-List; Write-Output '--- SMB SERVER CONFIGURATION ---'; Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,EncryptData,RejectUnencryptedAccess,AuditSmb1Access | Format-List; Write-Output '--- LIVE SMB CONNECTIONS ---'; Get-SmbConnection -ErrorAction SilentlyContinue | Select-Object ServerName,ShareName,Dialect,Encrypted,Signed,NumOpens | Format-Table -AutoSize; Write-Output '--- MAPPED DRIVES ---'; Get-SmbMapping -ErrorAction SilentlyContinue | Select-Object LocalPath,RemotePath,Status | Format-Table -AutoSize"),
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            Reasoned("You are a Network Security Engineer. RequireSecuritySignature False on the client is the precondition for SMB relay attacks across a flat campus subnet - treat it as high severity. EnableSMB1Protocol True is a critical finding regardless of context. EnableInsecureGuestLogons True allows silent fallback to unauthenticated access against a rogue share. In live connections, flag any Dialect below 3.0.0 and any connection with Signed False. Note that a mapped drive in Disconnected status is the most common cause of the logon delays and lockouts reported alongside this symptom."),
            null),

        // --- Campus wireless / 802.1X ------------------------------------------------------------------------
        Template(
            "network-wifi-8021x",
            "Campus Wi-Fi & 802.1X Supplicant Diagnostic",
            "Reports the associated SSID, signal quality, radio capabilities, and configured 802.1X profiles for campus wireless triage.",
            CatNetwork,
            ModelPro,
            new SingleToolDefinition(
                "wlan_supplicant_tool",
                "NetSh WLAN Interface & Profile Reporter",
                CmdExe,
                // 'key=clear' is deliberately ABSENT from every stage. It would print the PSK or
                // stored 802.1X credential in plaintext, and this output is transmitted to an
                // external model - the entire product exists to stop credentials leaving the
                // endpoint, so profile secrets are structurally excluded rather than filtered later.
                "/c netsh wlan show interfaces & echo --- CONFIGURED PROFILES --- & netsh wlan show profiles & echo --- RADIO CAPABILITIES --- & netsh wlan show wirelesscapabilities & echo --- DRIVER --- & netsh wlan show drivers",
                ExitOkOrToolAbsent,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(128),
                MaxCpuPercent: 40),
            Reasoned("You are a Campus Wireless Engineer. Report the associated SSID, BSSID, radio type, channel, and signal percentage. Signal below 40 percent or a 2.4GHz association where the adapter supports 5/6GHz indicates a roaming or band-steering problem rather than a client fault. Confirm the authentication and cipher are WPA2-Enterprise or WPA3 rather than a pre-shared key on a campus SSID. From the profile list, flag any open or WEP profile and any duplicate campus SSID profile that could cause association flapping. You will not be given any key material and must not ask for it."),
            null),

        // --- Adapter & DHCP lease ------------------------------------------------------------------------------
        Template(
            "network-adapter-dhcp",
            "Adapter, DHCP Lease & DNS Client Diagnostic",
            "Captures per-interface IP configuration, DHCP lease timing, DNS server assignment, and the resolver cache state.",
            CatNetwork,
            ModelFlash,
            new SingleToolDefinition(
                "adapter_dhcp_tool",
                "IPConfig & DNS Client Cache Reporter",
                CmdExe,
                "/c ipconfig /all & echo --- INTERFACE CONFIG --- & netsh interface ipv4 show config & echo --- DNS SERVERS --- & netsh interface ipv4 show dnsservers & echo --- RESOLVER CACHE --- & ipconfig /displaydns",
                ExitOkOrPartial,
                TimeoutSeconds: 60,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            Reasoned("You are a Tier-1 Field Support Technician's assistant. Identify the active adapter and state whether the address is DHCP-assigned or static. A 169.254.x.x APIPA address means DHCP failed entirely - say so first and plainly. Compare lease obtained and expiry times against the current time and flag a lease past half-life that has not renewed. Verify the DNS servers are the expected campus resolvers rather than a public resolver, since a public resolver cannot resolve internal domain records and breaks domain logon. In the resolver cache, flag stale entries for internal hosts. Give the operator a plain-language next step."),
            null),

        // --- Ephemeral port exhaustion -------------------------------------------------------------------------
        Template(
            "network-port-exhaustion",
            "TCP Port Exhaustion & Socket State Analysis",
            "Analyses TCP connection state distribution against the configured ephemeral port range to detect socket exhaustion.",
            CatNetwork,
            ModelPro,
            new SingleToolDefinition(
                "port_exhaustion_tool",
                "Netstat State & Dynamic Port Range Probe",
                CmdExe,
                "/c netstat -ano -p tcp & echo --- IPV4 DYNAMIC PORT RANGE --- & netsh int ipv4 show dynamicport tcp & echo --- IPV6 DYNAMIC PORT RANGE --- & netsh int ipv6 show dynamicport tcp & echo --- TCP GLOBAL PARAMETERS --- & netsh int tcp show global",
                ExitOkOrPartial,
                TimeoutSeconds: 90,
                MaxMemoryBytes: Mb(256),
                MaxCpuPercent: 50),
            Reasoned("You are a Windows Networking Performance Engineer. Count connections by state and by owning PID. A large TIME_WAIT population approaching the dynamic port range size is classic ephemeral port exhaustion and presents to users as intermittent connection failures with no error in the application log. Identify the PID holding the most sockets and whether they target a single remote endpoint, which indicates a connection leak rather than legitimate load. Report the dynamic port range start and count, and state how close the current usage is to the ceiling as a percentage."),
            null),

        // --- Path / MTU ----------------------------------------------------------------------------------------
        Template(
            "network-path-mtu-route",
            "Inter-Building Path, Route & MTU Probe",
            "Traces the routed path to a target, dumps the local routing table, and probes for MTU black holes across campus links.",
            CatNetwork,
            ModelPro,
            new SingleToolDefinition(
                "path_mtu_tool",
                "Route Print & Traceroute MTU Probe",
                CmdExe,
                // The MTU probe sets DF and a fixed payload: a VPN or inter-building tunnel that
                // silently drops oversized packets without returning ICMP fragmentation-needed
                // presents as "large file transfers hang while ping works", which no latency test
                // reproduces. Pairing the trace with a DF-bit probe distinguishes the two directly.
                "/c route print & echo --- PATH TRACE --- & tracert -d -h {MaxHops} -w {ProbeTimeoutMs} {TargetHost} & echo --- MTU BLACK HOLE PROBE --- & ping -f -l {ProbeMtuBytes} -n 2 {TargetHost}",
                ExitOkOrPartial,
                TimeoutSeconds: 180,
                MaxMemoryBytes: Mb(192),
                MaxCpuPercent: 40),
            Reasoned("You are a Campus Network Architect. Identify the hop where latency steps up materially and state whether it is the local gateway, the building distribution layer, or an upstream transit hop, since only the first two are actionable by campus staff. Distinguish a hop that does not answer (ICMP deprioritised, harmless) from a hop after which all replies stop (a genuine break). If the DF-bit probe reports that packets need to be fragmented, report an MTU black hole and give the exact payload size that succeeds. Cross-reference the route table for an unexpected persistent route or a metric that steers traffic away from the intended interface."),
            new Dictionary<string, string>
            {
                { "TargetHost", "8.8.8.8" },
                { "MaxHops", "20" },
                { "ProbeTimeoutMs", "1500" },
                { "ProbeMtuBytes", "1472" } // 1472 + 28 byte IP/ICMP header = 1500 standard Ethernet MTU
            })
    };
}
