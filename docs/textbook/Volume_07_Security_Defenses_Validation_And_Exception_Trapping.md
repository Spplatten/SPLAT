# Volume 07: Security Defenses, Validation & Exception Trapping

## Master Table of Contents
1. [The Defense-in-Depth Spectrum: Blast-Radius vs. Detection](#1-the-defense-in-depth-spectrum-blast-radius-vs-detection)
2. [Command Injection Mitigation: Single-Pass Regex Binding](#2-command-injection-mitigation-single-pass-regex-binding)
3. [Pre-Egress Data Loss Prevention (DLP) & Credential Sanitization](#3-pre-egress-data-loss-prevention-dlp--credential-sanitization)
4. [In-Kernel LSM Enforcement: Intercepting Syscalls Before Hardware Dispatch](#4-in-kernel-lsm-enforcement-intercepting-syscalls-before-hardware-dispatch)
5. [Tamper-Evident Audit Ledgers & Merkle Tree Proof Engines](#5-tamper-evident-audit-ledgers--merkle-tree-proof-engines)
6. [Line-by-Line Code Breakdown: Security Subsystems](#6-line-by-line-code-breakdown-security-subsystems)
7. [Step-by-Step Numerical Walkthrough: Merkle Proof Generation & Validation](#7-step-by-step-numerical-walkthrough-merkle-proof-generation--validation)
8. [Interactive University Checkpoints & Debugging Puzzles](#8-interactive-university-checkpoints--debugging-puzzles)

---

## 1. The Defense-in-Depth Spectrum: Blast-Radius vs. Detection

In agent security architecture, defensive mitigations fall into two distinct philosophical categories:
1. **Heuristic Detection (Probabilistic)**: Attempting to analyze natural language prompt strings or system call patterns to classify behavior as "malicious" or "benign". This includes prompt injection filters, anomaly detectors, and semantic intent scanners.
2. **Blast-Radius Containment (Deterministic)**: Assuming that the agent *is already compromised* or *has already been subverted*, and mathematically clamping the system resources, filesystem paths, network endpoints, and system calls the workload is physically capable of invoking.

```
THE DEFENSE-IN-DEPTH SPECTRUM:
+─────────────────────────────────────────────────────────────────────────────+
| TIER 1: USER INPUT & ARGUMENT BINDING (SPLAT Process)                       |
|   • GovernedArgumentBinder: Single-pass regex with context-aware allow-lists|
|   • Refuses metacharacters (', ", `, ;, |, &, $) before spawn              |
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
| TIER 2: PRE-EGRESS DATA LOSS PREVENTION (SPLAT Process)                     |
|   • RegexDataLossPreventionSanitizer & PromptCredentialSanitizer           |
|   • In-memory redaction of private keys, NTLM hashes, API tokens, passwords |
|   • Zero raw unscrubbed telemetry leaves the process or reaches LLMs        |
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
| TIER 3: OS HARDWARE & OBJECT MANAGER SANDBOXING (Kernel Space)              |
|   • Windows: Job Objects (RAM/CPU/PID), Restricted Token, AppContainer      |
|   • Linux: Cgroup v2 controllers, UID drop to nobody (65534)                |
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
| TIER 4: IN-KERNEL SYSCALL POLICY ENFORCEMENT (eBPF-LSM)                     |
|   • bprm_check_security: Only allow-listed executable inodes may exec       |
|   • file_open: Protected inodes (/etc/shadow) denied with -EPERM            |
|   • socket_connect: IPv4 /32 destination + port clamp; IPv6 blocked outright|
+─────────────────────────────────────────────────────────────────────────────+
                                     │
                                     ▼
+─────────────────────────────────────────────────────────────────────────────+
| TIER 5: TAMPER-EVIDENT CRYPTOGRAPHIC LEDGER (Persistence)                   |
|   • SHA-256 sequential hash chaining over salted commitments                |
|   • Merkle tree root verification for compliance notarization               |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 2. Command Injection Mitigation: Single-Pass Regex Binding

A ubiquitous vulnerability in operational tools is command injection through string concatenation:

```csharp
// FATAL FLAW IN TRADITIONAL RUNTIMES:
string cmd = $"powershell.exe -Command \"Get-Process {userInput}\"";
```
If `userInput` contains `calc.exe; Stop-Service`, the shell executes both commands.

### The Second-Order Injection Flaw
Many frameworks attempt to sanitize arguments by looping over replacement pairs:
```csharp
foreach (var (k, v) in parameters) {
    template = template.Replace("{" + k + "}", v);
}
```
This is vulnerable to **second-order parameter injection**: if parameter `A` has value `{B}`, and parameter `B` has value `malicious_payload`, the second iteration evaluates and substitutes `{B}`, executing unintended code!

### SPLAT Single-Pass Architecture (`GovernedArgumentBinder.cs`)
SPLAT eliminates second-order injection by executing a **single-pass regex substitution** (`PlaceholderPattern.Replace`) over author-controlled text:

```csharp
final_arguments = Regex.Replace(template, pattern, matchEvaluator);
```

Because substitution occurs in a single pass over original offsets, a substituted value containing `{OtherKey}` is treated as inert string content and is never re-evaluated.

```
+─────────────────────────────────────────────────────────────────────────────+
| CONTEXT-AWARE CHARACTER ALLOW-LISTS                                         |
+─────────────────────────────────────────────────────────────────────────────+
| 1. Bare (Unquoted) Positions (BarePolicy):                                  |
|    - Pattern: ^[A-Za-z0-9][A-Za-z0-9._:/\\@-]{0,252}$                      |
|    - Strict alphanumeric start (prevents switch injection: -p, /s).         |
|    - Zero spaces, semicolons, pipes, ampersands, or backticks permitted.     |
|                                                                             |
| 2. Numeric Fields (NumberPolicy):                                           |
|    - Pattern: ^-?\d{1,18}(\.\d{1,6})?$                                      |
|                                                                             |
| 3. Hostnames & IP Literals (HostPolicy):                                    |
|    - Pattern: ^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,252}|\[[0-9A-Fa-f:]{2,45}\])$ |
|                                                                             |
| 4. PowerShell Quoted Literals:                                              |
|    - Explicitly rejects: [ '\'', '"', '`' ]                                 |
|    - Refuses rather than attempts escaping: an unexpected quote is an       |
|      unauthored command!                                                    |
+─────────────────────────────────────────────────────────────────────────────+
```

---

## 3. Pre-Egress Data Loss Prevention (DLP) & Credential Sanitization

In `src/MissionController.Infrastructure.Network/Dlp/RegexDataLossPreventionSanitizer.cs`, SPLAT implements in-memory redaction before any telemetry is emitted to standard output streams or passed to cloud model providers.

### Targeted Sensitive Data Patterns
```csharp
// Private Key Blocks (RSA, EC, OPENSSH, PGP)
@"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----"

// NTLM Password Hash Pairs
@"(?i)\b[a-f0-9]{32}:[a-f0-9]{32}\b"

// Cloud & API Provider Tokens
@"(?i)\b(?:sk-[a-zA-Z0-9]{20,48}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})\b"

// Passwords in CLI Strings
@"(?i)(?:-p|-password|--password)\s+([^\s""']+)"
```

### In-Memory Opaque Mapping
When a secret is detected, it is replaced with a cryptographic placeholder:

```
Placeholder = "[REDACTED_SECRET_" + CRC32(secret) + "]"
```

The raw secret is stored in a volatile, short-lived dictionary within SPLAT's process memory and is never written to disk, never committed to SQLite, and never transmitted over network sockets.

---

## 4. In-Kernel LSM Enforcement: Intercepting Syscalls Before Hardware Dispatch

On the Linux guest substrate, `lease_lsm.bpf.c` intercepts security-sensitive operations inside the Linux Security Module (LSM) framework.

```
SYSCALL INVOCATION PIPELINE:
  User Process executes: execve("/usr/bin/python3", argv, envp)
         │
         ▼ Kernel Space Transition (Syscall Handler)
  sys_execve -> do_execveat_common -> bprm_execve
         │
         ▼ LSM Security Check Hook
  security_bprm_check(bprm)
         │
         ▼ SPLAT BPF-LSM Hook Invoked:
  BPF_PROG(splat_bprm_check, struct linux_binprm *bprm, int ret)
         │
         ├─► Step 1: Check existing verdict (if ret != 0, return ret)
         ├─► Step 2: Read current cgroup ID: cgid = bpf_get_current_cgroup_id()
         ├─► Step 3: Is cgroup leased? (!is_leased(cgid) -> return 0 [Allow])
         ├─► Step 4: Extract inode & device: k = lease_inode_key_of(cgid, inode)
         ├─► Step 5: Query allowed_exec_inodes map:
         │           if (bpf_map_lookup_elem(&allowed_exec_inodes, &k)) -> return 0 [Allow]
         │
         └─► Step 6: MISMATCH DETECTED!
                     report(cgid, HOOK_EXEC, k.ino);
                     return -EPERM; ──► KERNEL ABORTS EXECUTION!
```

### The IPv6 Security Boundary
In `lease_lsm.bpf.c`:
```c
if (family == AF_INET6) {
    report(cgid, HOOK_CONNECT, 0);
    return -EPERM;
}
```
*Architectural Rationale:* SPLAT capability leases currently define egress allow-lists in terms of IPv4 `/32` addresses. If IPv6 packets were allowed to pass unchecked, an agent could bypass network isolation simply by resolving an endpoint's IPv6 `AAAA` DNS record. Denying IPv6 unconditionally ensures that network egress cannot occur outside declared IPv4 leases.

---

## 5. Tamper-Evident Audit Ledgers & Merkle Tree Proof Engines

In `src/MissionController.Infrastructure.Data/Audit/SqliteChainedAuditLedger.cs`, every action is committed to an append-only cryptographic ledger.

```
THE SHA-256 SEQUENTIAL HASH CHAIN:
+-----------------------------------------------------------------------------+
| Entry N-1:                                                                  |
|   EntryHash = 0x8F3A...                                                     |
+-----------------------------------------------------------------------------+
                                     │
                                     ▼
+-----------------------------------------------------------------------------+
| Entry N:                                                                    |
|   PreviousHash = 0x8F3A...                                                  |
|   TimestampUtc = 2026-09-11T21:00:00.000Z                                   |
|   MissionId    = a1b2c3d4-e5f6-7890-abcd-ef1234567890                       |
|   TemplateId   = net-ping-01                                                |
|   Action       = SENSOR_TOOL_EXECUTION                                      |
|   DetailsSalt  = 0x4B21... (32 Bytes Random)                                |
|   DetailsCommitment = SHA-256(DetailsSalt || RawDetails)                    |
|                                                                             |
|   EntryHash = SHA-256(PreviousHash || Timestamp || MissionId ||             |
|                       TemplateId || Action || DetailsCommitment)            |
+-----------------------------------------------------------------------------+
```

### Merkle Tree Verification Engine
For enterprise compliance audits, SPLAT builds a balanced binary **Merkle Tree** over all audit entries:

```
                      [ Merkle Root Hash ]
                           (RootNode)
                            /      \
               [ Hash 0-1 ]          [ Hash 2-3 ]
                 /      \              /      \
            [ Leaf 0 ] [ Leaf 1 ] [ Leaf 2 ] [ Leaf 3 ]
```

A **Merkle Proof** allows an external compliance auditor to verify that a specific audit entry `E` exists within a historical dataset of `N` entries using only `log2(N)` sibling hashes:

```
Proof Complexity = O(log2 N)
```

---

## 6. Line-by-Line Code Breakdown: Security Subsystems

### 6.1 Context-Aware Argument Validation (`GovernedArgumentBinder.cs`)

```csharp
// Lines 240-275: Strict Character Allow-List Validation
private static void Validate(
    string key,
    string value,
    bool insideQuotedLiteral,
    TemplateParameterField? field)
{
    if (value.Length > (insideQuotedLiteral ? QuotedMaxLength : 256))
    {
        throw new TemplateParameterRejectedException(
            key, $"Value length ({value.Length}) exceeds maximum permitted length.");
    }

    // Bare position: enforce strict character set
    if (!insideQuotedLiteral)
    {
        if (field?.ValueType == TemplateParameterType.Number)
        {
            if (!NumberPolicy.IsMatch(value))
                throw new TemplateParameterRejectedException(key, $"Value '{value}' is not a valid number.");
            return;
        }

        if (field?.ValueType == TemplateParameterType.Host)
        {
            if (!HostPolicy.IsMatch(value))
                throw new TemplateParameterRejectedException(key, $"Value '{value}' is not a valid hostname or IP.");
            return;
        }

        if (!BarePolicy.IsMatch(value))
        {
            throw new TemplateParameterRejectedException(
                key, $"Value '{value}' contains characters outside the governed bare-parameter allowlist.");
        }
    }
    else
    {
        // Quoted literal: reject characters that escape quotes
        int idx = value.IndexOfAny(QuotedForbidden);
        if (idx >= 0)
        {
            throw new TemplateParameterRejectedException(
                key, $"Value contains forbidden quote-breaking character '{value[idx]}'.");
        }
    }
}
```
*Architectural Rationale:* The validator differentiates between bare tokens and quoted parameters. A bare token (e.g. `ping {Host}`) must match `^[A-Za-z0-9][A-Za-z0-9._:/\\@-]*$`. It cannot contain whitespace or shell delimiters. In quoted literals, quotes and backticks are rejected. If any character fails validation, the mission is aborted immediately.

---

## 7. Step-by-Step Numerical Walkthrough: Merkle Proof Generation & Validation

Consider a 4-leaf Merkle Tree built over four audit entries with leaf hashes `H0, H1, H2, H3`:

- `H0 = SHA-256(Entry 0) = "A0"`
- `H1 = SHA-256(Entry 1) = "B1"`
- `H2 = SHA-256(Entry 2) = "C2"`
- `H3 = SHA-256(Entry 3) = "D3"`

### Step 1: Intermediate Node Computation
```
H_01 = SHA-256(H_0 || H_1) = SHA-256("A0B1") = "E4"
H_23 = SHA-256(H_2 || H_3) = SHA-256("C2D3") = "F5"
```

### Step 2: Root Hash Computation
```
Root = SHA-256(H_01 || H_23) = SHA-256("E4F5") = "99AA"
```

### Step 3: Merkle Proof for Entry 2 (`H2`)
To prove $H_2$ is present in Root `"99AA"`, the prover supplies:
1. Sibling 1: `H3 = "D3"` (`IsLeftSibling = false`)
2. Sibling 2: `H_01 = "E4"` (`IsLeftSibling = true`)

### Step 4: Auditor Verification Algorithm
1. Compute parent of `H2`: `Parent = SHA-256(H2 || H3) = SHA-256("C2D3") = "F5"`.
2. Compute root: `CalculatedRoot = SHA-256(H_01 || Parent) = SHA-256("E4F5") = "99AA"`.
3. Compare: `CalculatedRoot == Root` (`"99AA" == "99AA"` -> **VALIDATED**).

---

## 8. Interactive University Checkpoints & Debugging Puzzles

### Checkpoint 7.1: The Delayed Expansion Vulnerability in cmd.exe
**Scenario:** A developer uses a single-pass regex replacement to substitute a user parameter into `cmd.exe /c "echo !MY_VAR!"`.
- **Question:** If delayed variable expansion is enabled in Windows (`cmd.exe /v:on`), what vulnerability exists when an attacker provides an exclamation point in their input?
- **Solution:** In `cmd.exe`, when delayed expansion is active, the command interpreter performs a secondary expansion pass on any string enclosed in exclamation points `!variable!`. If an attacker inputs `!PATH!`, `cmd.exe` expands the system path variable. If the attacker inputs `!evil_command!`, arbitrary environment variables or command tokens can be evaluated. SPLAT mitigates this by restricting bare parameters to `^[A-Za-z0-9][A-Za-z0-9._:/\\@-]*$`, which explicitly excludes exclamation marks (`!`), percents (`%`), carets (`^`), and quotes.

### Checkpoint 7.2: The Unsalted Hash Chain Truncation Attack
**Scenario:** A company operates a blockchain-style audit ledger where `EntryHash = SHA256(PrevHash || Details)`. An employee with local administrator access wants to delete an embarrassing mistake from entry 500 without triggering a hash chain error.
- **Question:** Can the administrator delete rows 500 to 1000 undetected? What if SPLAT uses an HMAC key stored in a secure DPAPI vault?
- **Solution:** Without an HMAC key, an attacker who can write to the SQLite database can delete rows 500 through 1000 and the surviving chain (rows 1 to 499) remains perfectly valid because every preceding hash matches. Furthermore, an administrator could recompute hashes from row 500 onwards. However, if SPLAT is configured with an **HMAC key stored in the DPAPI Credential Vault**, computing valid hashes requires a secret key held inside the DPAPI subsystem. An attacker cannot forge valid entry hashes without the DPAPI secret, making tampering immediately detectable.
