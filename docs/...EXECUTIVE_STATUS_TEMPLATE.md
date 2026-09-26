<!-- Track B governance template, added 2026-09-23 with the status-gate record
     (audits/2026-09-23-status-gate-and-gap-analysis.md). Copy it to
     docs/status/<YYYY-MM-DD>-executive-status.md per reporting period. Every number in a filled
     copy carries a source and an attestation level; a cell with neither is a defect, not a
     placeholder. The claims audit of 2026-09-19 is the record of what happens when an executive
     document outruns the code, and this template's shape is the answer to it. DocumentationDriftTests
     reads every .md at the top of docs/: relative links must resolve, and no latency may be promised
     that src/splat-bench did not record. -->

# SPLAT — Executive Readiness and Operational Governance Report

| | |
| --- | --- |
| Reporting period | <from> – <to> |
| Prepared by | <name, role> |
| Tree and evidence cut | <commit hash> on <date>; evidence files as committed on that date |
| Distribution | <CISO · compliance · procurement · executive sponsor · OEM licensee> |
| Classification | <internal · under NDA · public> |
| Previous report | <link, or "first"> |

**How to read this report.** Every claim carries one of five attestation levels, and the level is
part of the claim. A number without one has not been earned.

| Level | Meaning | Who can raise it |
| --- | --- | --- |
| **Measured** | A recorded run on named hardware, committed as an evidence file with the hash of the code it exercised | engineering, by running it |
| **Tested** | Held by an automated test that fails the build when it stops being true | engineering |
| **Designed** | Built and read out of the code, but not yet observed holding under the conditions claimed | engineering |
| **Planned** | A roadmap row with an owner and a "done when" | product |
| **Assessed** | Examined by an independent auditor against a named framework, with a report | the auditor only |

---

## 1. Executive summary

<One paragraph an executive can repeat in a meeting: what SPLAT is (a substrate that contains an
AI agent below the agent — a time-boxed, resource-clamped, kernel-enforced lease per task, with
every action sealed into a tamper-evident ledger), what changed this period, the one decision this
report needs, and the one risk it wants known.>

### 1.1 Business value

| Value | What the buyer gets | Attestation | Source |
| --- | --- | --- | --- |
| Blast-radius containment, not detection | Whatever an agent has become — injected, hallucinating, compromised — it cannot act outside the lease it was granted; the kernel refuses the action before it happens | <Measured on Linux for exec, open, connect · Designed for the datagram hook until re-proved> | <evidence file, hash> |
| Data stays on the host | Execution never leaves the machine that issued it; only scrubbed tool output reaches a model provider, through one pinned host | <Tested> | <`EgressFirewallHandler`, DLP tests> |
| Evidence a third party can check | A per-mission run record with Merkle proofs and a signature, verifiable on another machine with two scripts | <Measured 2026-09-20 on a live mission> | <`LiveMissionTests`> |
| No custom kernel, no cloud sandbox | Stock WSL2 kernel, native BTF; nothing to fork, patch or subscribe to | <Measured on 6.18.33.2 only> | <canary evidence> |

### 1.2 Cost-of-engineering displacement

Only **Measured** rows move outside this document. Formulas are hypotheses until a period's
numbers fill them; label them so.

| Metric | Baseline (without) | With SPLAT | Period value | How measured | Attestation |
| --- | --- | --- | --- | --- | --- |
| Governed missions run per operator-hour | <n/a> | <count ÷ operator hours> | | ledger rows with `MISSION_INITIATED` per period | |
| Team-scale amplification: technician-hours displaced per month | — | tickets deflected × average handle time | | ticket system export × ledger | Hypothesis until measured |
| Containment assessments delivered per engineer-month | — | <count> | | engagement log | |
| Mean time to a verified diagnosis (MTTD) | <minutes, from the ticket system> | <minutes, `MISSION_INITIATED` → `AI_ANALYSIS_COMPLETED`> | | ledger timestamps | |
| Engineer-hours to produce a reachability report by hand vs from the run record | <hours> | <minutes> | | timed, once, on a named host | |
| Net annual savings (the ROI hypothesis in [`IDEAS.md`](../IDEAS.md)) | — | (tickets deflected × cost per ticket) − licence | | | Hypothesis |

### 1.3 Risk mitigation, and what it does not cover

| Risk the buyer carries | Mitigation | Enforced by | Not covered — say it here, not in the appendix |
| --- | --- | --- | --- |
| An injected agent runs a destructive command | Exec allow-list per lease, in the kernel | kernel LSM hook (Linux) · fixed command + argument binder (Windows tier A) | The operator; a malicious template; a tool binary already compromised |
| Credentials or PII reach a model provider | Credential scrub then regex DLP before the first byte leaves the process | a transform in SPLAT's process | Secrets the patterns do not describe; the provider itself once scrubbed text arrives |
| Nobody can prove what the agent did | Hash-chained ledger, keyed by the operator; signed run records | tamper evidence in SPLAT's process | Whoever holds the key file; deletion of the newest rows without a saved anchor |
| The agent exfiltrates over the network | Endpoint allow-list per lease, connects and datagrams, in the kernel; no network stack at all for the Windows sensors measured safe under it | kernel LSM hook (Linux) · AppContainer (Windows) | Windows destination pinning (an AppContainer is network-or-none); local sockets (AF_UNIX, AF_NETLINK) |

---

## 2. Auditability and non-repudiation scorecard

### 2.1 Controls

| Control | Mechanism | Status | Attestation | Evidence | Gap |
| --- | --- | --- | --- | --- | --- |
| Tamper-evident ledger | SHA-256 chain over salted commitments; each row names its chain kind | <Enforced in SPLAT's process> | Tested | `LedgerKeyingTests`, `AuditAndSecurityTests` | Unkeyed by default |
| Keyed chain (HMAC-SHA256 under the operator's key file) | Refuses extension without its key or with another; records the switch | <Available · Default on · Default off> | Tested | | Whoever reads the key file can rewrite |
| Per-mission run record, six evidence groups, assembled from the ledger alone | `MISSION_RUN_FACTS` sealed on every exit path | | Measured (a live mission) | `LiveMissionTests` | A Linux lease leaves no record (roadmap 2.5) |
| Signed bundles with independent verification scripts | RSA signature over every file's SHA-256; scripts exit 2 when unsigned | | Measured | `verify_proofs.py` / `.ps1` | Key custody: the signing key is the operator's |
| Audit anchor on every agent call | The ledger head hash returned with each MCP result; external trace ids correlated | | Tested | `McpTraceAnchorTests` | Anchors are not published off-host |
| Independent checkpoint / anchor publication | <RFC 3161 timestamp · external append-only log · none> | <Not built> | Planned | — | Truncation of the newest rows is undetectable without it |
| Principal attribution | Windows logon session, or a validated JWT / API key; never a caller-supplied name | | Tested | `OperatorAttributionTests` | Agents run as the operator, not under an identity of their own |
| Revocation before any effect, surviving restart | `SqliteRevocationStore`; an unreadable list refuses the call | | Tested (F19) | `RevocationDurabilityTests` | |
| Retention and cryptographic erasure | Payload and salt destroyed, commitment kept; WAL truncated; vacuum | <Built, scheduled by no host> | Tested | `DataRetentionTests` | No host runs it (roadmap F23) |
| SIEM forwarding | Sentinel (HMAC), CEF, RFC 5424 syslog | <Console only> | Tested | `SiemAndEdrIntegrationTests` | Not on the MCP host |
| Kernel-denial telemetry | Ring-buffer records with the kernel's clock, a sequence number and a drop counter | | Designed (pending the root re-proof) | `SCHEMA.md` | Daemon frames are unproven (roadmap 2.6); Windows containment emits no events |

### 2.2 Regulatory alignment

> These are the controls the architecture is **built against**. They are not an attestation.
> Until the *Assessor* column carries a name and a date, the attestation level of every row is at
> most **Designed** or **Tested**, and the report says so wherever a row is quoted.

| Framework | Control | SPLAT mapping | Attestation | Assessor / date |
| --- | --- | --- | --- | --- |
| SOC 2 Type II | CC6.1 logical access | Restricted tokens, privilege separation, AppContainer, the Linux lease | Tested / Designed | — |
| SOC 2 Type II | CC6.8 unauthorized software / egress | Exec allow-list, endpoint allow-list, egress firewall | Measured (Linux) / Tested (Windows) | — |
| SOC 2 Type II | CC7.2 monitoring and audit | Chained ledger, run records, SIEM forwarding | Tested | — |
| ISO/IEC 27001:2022 | A.8.15 logging · A.8.16 monitoring | Ledger, anchors, kernel-denial records | Tested / Designed | — |
| ISO/IEC 27001:2022 | A.5.15 access control · A.8.9 configuration management | Lease ceiling, keyed ledger, `doctor`'s capability manifest bound to `SUPPORTED_POLICY.md` | Tested | — |
| HIPAA Security Rule | § 164.312(b) audit controls · § 164.312(e)(1) transmission security | Chained ledger; DLP before egress; one pinned host | Tested | — |
| NIST SP 800-171 / CMMC 2.0 | AU.2.041–042 attributed, chained logs · SC.3.177 egress isolation | Attribution + keyed chain (half complete: see gap) · lease and AppContainer | Tested / Designed | — |

### 2.3 Policy isolation guarantees

| Guarantee | Tier | Enforced by | Proven by | Not covered |
| --- | --- | --- | --- | --- |
| A leased process executes only the binaries its lease names, root included | B | kernel LSM hook | `daemon-probe.json` (`unleased_second_exec_blocked`) | — |
| A leased process cannot open the files its lease protects | B | kernel LSM hook | `daemon-probe.json` (`protected_inode_violation`, with a control that could read it) | Files outside the deny-list and inside the jail's read-only system directories are readable |
| A leased process reaches only the endpoints its lease names, by connect or datagram | B | kernel LSM hook | `daemon-probe.json`, `last-hop-probe.json` (datagram hook pending) | AF_UNIX, AF_NETLINK, inherited descriptors |
| Two concurrent leases never lend each other permissions | B | kernel map keys carry the lease | `daemon-probe.json` (`concurrent_lease_isolation_held`) | — |
| A lease ends: the workload is killed inside its policy, then the policy is withdrawn | B | the daemon's reaper | `daemon-probe.json` (`expiry_killed_the_workload`, 5.5 s) | The restart window when the daemon itself dies (roadmap 2.7) |
| The most any lease may name is bounded by a root-owned file in the guest | B | the daemon, at request time | `ceiling.rs` tests (needs no root) | — |
| A Windows sensor runs one fixed command with bound scalar parameters, under job clamps and a restricted token | A | fixed command + binder · kernel objects | `GovernedArgumentBinderTests`, `HardeningSubsystemTests` | UI restrictions, disk and I/O quotas, the operator's own SID |
| A Windows sensor measured safe under network denial has no network stack | A | kernel object (AppContainer) | `NetworkToolsUnderDenialTests`, `SensorNetworkContainmentTests` | Which host a sensor-scoped template reaches |

---

## 3. Operational reliability and SLA tracking

### 3.1 Self-healing loops and MTTR

| Loop | Detects | Recovers by | MTTR | Attestation | Source | Residual exposure during recovery |
| --- | --- | --- | --- | --- | --- | --- |
| Daemon crash or stop | systemd unit state; orphan cgroups at next start | Unit restart; orphaned leases killed before the daemon serves | <seconds, measured> | <Designed until measured> | `main.rs`, unit file | Live leases run **unpoliced** until the restart and drain (roadmap 2.7 closes it) |
| Overrunning workload | Reaper tick every 1 s | Kill inside the policy, then withdraw it; a survivor is held and retried | 5.5 s on a 60 s sleep | Measured 2026-09-15 | `daemon-probe.json` | — |
| WSL stops the guest while idle | Refused connection | The bridge holds an idle `wsl.exe` session for the length of the lease; starts the installed unit on a refused connect | <seconds> | Designed; the 75 s run on the second machine is unverified | roadmap | A lease that outlives the window is cut off |
| Bridge deadline expiry | Local deadline | Closing the connection makes the daemon kill the workload | | Tested | `WslLeasedExecutorWireTests` | — |
| Ledger integrity failure | `VerifyLedgerIntegrityAsync` at console start; `doctor` | Reported as FAILED; nothing self-heals a rewritten chain by design | n/a | Tested | claims audit 2026-09-19 | — |
| Remediation postconditions | A declared probe after a fix | Rollback, where the action declares one | <not measured: the catalog ships no fixes> | Tested (engine) | `RemediationEngineTests` | — |

### 3.2 Resource overhead and headroom

| Metric | Value | Condition | Attestation | Source |
| --- | --- | --- | --- | --- |
| Governed launch overhead, Windows | 4.12 ms p50 · 9.88 ms p95 over the same tool run bare, of which the locks are about 2.4 ms | Windows 10.0.26200, 16 cores, 50 alternating iterations, `cmd /c exit 0` | Measured 2026-09-04 | `src/splat-bench/evidence` |
| Linux lease overhead | <not measured> | — | — | a `splat-bench` for the lease path is open work |
| Lease clamps | 256 MiB · 50 % CPU · 100 PIDs, ceilings the request can only lower; **read back** after the write | per lease | Tested; Measured 2026-09-15 that a clamp that did not take refuses | `cgroup.rs`, `daemon-probe.json` |
| Windows job clamps | job and process memory cap from the template; CPU hard cap; 32 active processes; kill on close; **read back** | per mission | Tested | `Win32JobSandbox.cs` |
| Concurrent leases | 256 (`leased_cgroups` capacity); 8,192 inode entries; 4,096 endpoint entries | per daemon | Designed | `SCHEMA.md` map capacities |
| Kernel denial records | 1 MiB ring buffer; a full buffer drops the record, keeps the refusal, and counts the drop | per daemon | Designed (pending re-proof) | `SCHEMA.md` |
| Output bounds | 64 KiB frames; 1 MiB request cap both ways; 4 MiB transcript per stream | per lease | Tested | `WslLeasedExecutor.cs` |
| Peak-load behaviour | <not measured: no load test exists> | — | — | open |

### 3.3 Service objectives

| Objective | Target | This period | Measurement | Attestation |
| --- | --- | --- | --- | --- |
| A lease reaches the kernel on a provisioned host (`doctor` exit 0) | <100 % of provisioned hosts> | | `doctor` run per host per period | |
| Denials recorded vs denials counted | <0 dropped> | | `violationsDropped` in `EXIT` frames, summed | |
| Ledger verification at start | <PASS on every host> | | console self-check; `doctor` | |
| Run records verifiable off-host | <100 % of exported bundles> | | `verify_proofs.py` on a second machine | |
| Substrate proof currency | <evidence hash equals shipping BPF source> | | `DocumentationDriftTests` | Tested |

---

## 4. Milestone delivery and risk heatmap

### 4.1 Deliverables

Impact: **H** changes what an evaluator can be shown · **M** closes a stated gap · **L** hygiene.
Dependencies use the roadmap's owner vocabulary: *agent* · *operator* (root, install, signature,
money) · *decision*.

| Milestone | Deliverable | Impact | Timeline | Dependencies | Status | Attestation when done |
| --- | --- | --- | --- | --- | --- | --- |
| <P2 · 2.3> | Root re-proof of the shipping kernel program; re-proof as one command | H | <date> | operator (root) · agent (script) | <Pending> | Measured |
| <P2 · 2.5 / 2.6> | Signed run record for a Linux lease; proofs on the daemon's frames | H | | agent, after 2.3 | | Measured |
| <P2 · 2.7> | Hooks and maps pinned under bpffs, outliving the daemon | M | | agent, after 2.3 | | Measured |
| <P2 · 2.4> | Caller identity on the bridge, with the threat model written first | M | | decision, then agent | | Tested |
| <P4 · 4.7> | Signed release and a cloud bootstrap | H | | operator (certificate, accounts) | | Tested |
| <P4 · 4.2 / 4.6> | Unmount from a manifest; SPLAT's own WSL distro | M | | decision, then agent | | Tested |
| <decision> | Keyed ledger and one chain per host by default | M | | decision | | Tested |
| <decision> | Windows destination pinning (WFP filter that keeps DNS closed) | M | | decision, then agent | | Measured |

### 4.2 Risk heatmap

Rows are likelihood, columns are impact; cells hold risk ids from 4.3.

| | Low impact | Medium impact | High impact |
| --- | --- | --- | --- |
| **Likely** | | <R6> | <R1, R4> |
| **Possible** | <R10> | <R3, R5> | <R2, R7> |
| **Unlikely** | | <R9> | <R8> |

### 4.3 Risk register

| Id | Risk | Likelihood | Impact | Owner | Mitigation | Trigger to escalate |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | Kernel claims withdrawn while the shipping program is unproven | Likely (it is the state today) | High | operator | Run the re-proof; then the one-command script | Any kernel-side change without a re-run |
| R2 | Unsigned distribution: SmartScreen interrupts the first download an evaluator makes | Possible | High | operator | Code-signing certificate; signed release | First external evaluator |
| R3 | A same-user Windows process can read the daemon's token | Possible | Medium | decision | The guest-side ceiling bounds what the token buys; the threat model says this is where the boundary is | A multi-user host |
| R4 | Two unkeyed ledgers per host by default; `doctor` says a rewrite is undetectable | Likely | High | decision | Generate the key at provision; one `SPLAT_DB_PATH` | Any evaluator running `doctor` |
| R5 | A Windows sensor-scoped destination is a declaration, not a wall | Possible | Medium | decision | WFP filter keyed to the tool's SID, with the DNS condition | A template that presents a credential |
| R6 | WSL stops the guest under a long lease | Likely | Medium | agent | The idle-session hold; verify the 75 s run on the second machine | A lease over 60 s |
| R7 | Key custody: ledger and signing keys beside the data they protect | Possible | High | decision | Second device or hardware key; the drive model in `END-GOAL.md` | The first drive that leaves the building |
| R8 | Single contributor; bus factor of one | Unlikely per period, certain over time | High | executive sponsor | Templates, runbooks and drift tests are the mitigation; a second engineer is the fix | Any period with no commits |
| R9 | Reasoning depends on a cloud model provider | Unlikely | Medium | product | Execution is local; a local-model client is not built | An air-gapped buyer |
| R10 | Runtime support cadence (.NET LTS windows, Windows App SDK) | Possible | Low | agent | On .NET 10 and Windows App SDK 2.5.1 since 2026-09-18 | The next end-of-support date |

---

## 5. Decisions requested this period

| Decision | Options | Recommendation | Blocks | Needed by |
| --- | --- | --- | --- | --- |
| <e.g. keyed ledger by default> | <on at provision · opt-in> | <on> | <R4, the demonstration> | <date> |

## 6. Appendix

### 6.1 Evidence index

| File | Proves | Bound to source by |
| --- | --- | --- |
| `native/splat-canary/evidence/canary-*.json` | Standalone: exec, open and connect outside the lease refused by the kernel | the canary's BPF hash |
| `native/splat-agent/evidence/daemon-probe.json` | Through the daemon, under root: every row of the enforced tables | the daemon's BPF hash |
| `native/splat-agent/evidence/last-hop-probe.json` | An MCP client's command refused in the kernel, with controls | the daemon's BPF hash |
| `src/splat-bench/evidence/bench-*.json` | The launch overhead of the governed Windows path | the drift test's latency guard |
| `native/splat-agent/evidence/clean-machine/` | Provisioning and the probe on a second machine that had never seen SPLAT | — |

### 6.2 Glossary

| Term | Meaning |
| --- | --- |
| Lease | A per-task grant the kernel enforces: these executables, not these files, these endpoints, these clamps, for this many seconds |
| Mission | One governed execution on Windows: one template, one tool run, one analysis, one set of ledger rows |
| `doctor` | The command that prints what this host will and will not enforce, and exits 0 only when a lease reaches the kernel |
| Run record | The per-mission bundle a third party verifies: the record, the entries, a proof for each, and a signature |
| Anchor | The ledger's head hash, returned with every agent call; a saved one is what catches a truncated ledger |
| Ceiling | The root-owned policy in the guest that every lease is cut down to |

### 6.3 Documents this report draws on

[`README.md`](../README.md) status table · [`ROADMAP.md`](ROADMAP.md) ·
[`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) ·
[`THREAT-MODEL.md`](THREAT-MODEL.md) · [`SCHEMA.md`](SCHEMA.md) ·
[`BRIEF-technical-one-pager.md`](BRIEF-technical-one-pager.md) ·
[the status-gate record](audits/2026-09-23-status-gate-and-gap-analysis.md).
