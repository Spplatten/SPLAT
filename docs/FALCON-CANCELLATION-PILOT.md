# Options B and C: cancellation proof and Falcon pilot

An alert acknowledgment is not a termination proof. This runner requires a durable mailbox
record, a daemon receipt signed by an independently pinned key, observed native workload drain,
and progress by an unrelated control workload after cancellation.

## What is implemented, and what has actually run

| Deliverable | Implementation | Evidence boundary |
| --- | --- | --- |
| Independent receipt verification | [CancellationReceiptProof.cs](../src/splat-alert-sidecar/CancellationReceiptProof.cs) | Real RSA signature tests against synthetic receipt fixtures; not a native execution result. |
| Live cancellation/pilot runner | [FalconPilot.cs](../src/splat-alert-sidecar/FalconPilot.cs) | Compiled; no live HTTP/native run in this environment. Requires real deployment inputs. |
| Native observer | [witness.py](../native/experiments/alert-cancellation/witness.py) | Python syntax and portable contract/parser tests passed. On the real kernel (2026-11-06), the [native witness check](#native-witness-check) saw it accept both drains and refuse every constructible bypass. Not yet run inside a SPLAT lease. |
| Harmless workload fixture | [workload_fixture.py](../native/experiments/alert-cancellation/workload_fixture.py) | Bounded target/descendant/control roles supplied; not executed under a lease here. |
| Regression evidence | [Current closure manifest](audits/evidence/2026-11-06-falcon-closure/verification.json); [initial harness manifest](audits/evidence/falcon-cancellation-pilot/verification.json) | Names exact source/log hashes and actual gate counts. Initial evidence is historical, not proof of later bytes. |

Option A (`d334e5e`, `65c2e40`) and this B/C work (`c385cf9`) were written in a session that
could not commit. They were committed verbatim and merged to `main` with PRs #28 and #29 on
2026-11-06. The Option A deployment limits are unchanged: the CLI still uses a manually
supplied root-process binding, not an automatic native registrar.

**B is implemented as a proof harness, not yet demonstrated end to end. C is prepared for a live
pilot, not completed.** The writing session saw `Wsl/E_ACCESSDENIED` and loopback socket error
10013. On a machine without those limits, the local gates and the focused tests pass (see the
[closure audit](audits/2026-11-06-falcon-closure.md)). No Falcon/LogScale credentials are
configured, and the connector registry offers no CrowdStrike connector, so C needs an operator
with an authorized tenant. No tenant event, detection rule, subscription or vendor connection was
fabricated or modified.

## B: proof sequence and failure semantics

1. Parse bounded, duplicate-key-checked input files. Pin their actual bytes in the run directory.
   Require a fresh event matching the approved Falcon profile and fixed root-task binding.
2. Inspect the sidecar mailbox through a separate **read-only** SQLite connection. It must exist,
   match the binding fingerprint, and be idle. Inspection never creates a missing database.
3. Read the target and control through A2A `GetTask`, using normal TLS validation plus explicit
   certificate pins. Both must be dispatched, working, uncanceled and context-matched.
4. Start a read-only guest witness through direct `wsl.exe -e /usr/bin/python3 -I` arguments.
   It retains the original target/control pidfds and cgroup directory descriptors across delivery.
5. Deliver wrong-tenant and wrong-process variants. Each must return HTTP 409 and leave the
   real mailbox idle. Recheck that both original native processes remain alive.
6. Deliver the original event without changing its bytes. Discard the intake response body and
   replay the exact event. Both responses must be 202; the durable row must identify that event.
7. Poll `GetTask`. A canceled state without retained receipt artifacts remains unresolved until
   timeout; a malformed or invalid available receipt fails verification. Natural completion,
   failure or rejection cannot count as a successful cancellation demonstration.
8. Verify native receipt v2 under the pre-pinned key, matching mission, cgroup, execution context,
   requested/effective policy hashes, enforcement, cancellation acceptance and workload drain.
9. Tell the witness to observe the post-cancellation interval. The original target pidfd must
   report exit and its cgroup must be empty or removed while the original directory handle remains
   held. The control's original process/cgroup identity must remain live, and CPU accounting must
   advance **after this post-cancellation barrier**, not merely during setup.
10. Read the control again through A2A. Only then write `PASS_CANCELLATION_CHAIN` to the manifest.

The harness never sends `CancelTask` itself. The alert sidecar must cause the cancellation
through its existing authenticated path. The harness cannot pass by directly killing the target.
It never signals workload PIDs; observer cleanup affects only its own read-only WSL observer.

The host sends bounded UTF-8 frames with an explicit LF delimiter on every platform. Truncated
EOF, CRLF response frames and oversized frames fail closed; a background reader drains stderr
without storing it so diagnostics cannot block the witness. The local wire gate exercises real
C#/Python process pipes, including the guest's command parser and a 256 KiB stderr burst.

A missing cgroup pathname alone is insufficient drain evidence. The observer reads `populated`
relative to the retained directory descriptor. If kernfs has removed the interface, it requires
an ENOENT/ENODEV result, the retained descriptor's original pathname marked deleted by procfs,
and a still-absent original pathname. Permission errors, renamed handles and replacement paths
fail closed. These branches have injected-OS regression tests. On kernel
6.18.33.2-microsoft-standard-WSL2, the [native witness check](#native-witness-check) observed two
things:
- **Removal:** once the cgroup is removed, reading `cgroup.events` through the held descriptor
  returns ENOENT, and procfs marks the descriptor's path `(deleted)`.
- **Rename:** cgroup v2 refuses to rename the directory (EPERM). So a renamed handle that still
  has survivors cannot arise there, and the witness's rename defense is depth, not the main barrier.

Redeploy the updated observer and repin its actual bytes before a pilot run.

### Native witness check

```powershell
& .\packaging\run-native-witness.ps1 -DryRun
& .\packaging\run-native-witness.ps1
```

- `-DryRun` stages the committed `witness.py` and `workload_fixture.py`, proves each staged file
  is the committed blob, and maps every path in the guest. Nothing runs as root.
- Without it, the script runs
  [native_witness_run.py](../native/experiments/alert-cancellation/native_witness_run.py) as root
  in a WSL guest. The default guest is `Ubuntu`: every WSL2 distribution shares the SPLAT Guest's
  kernel, and `-Distro` selects another.
- The fixture runs as uid 65534, born inside disposable mission cgroups. The harness drives the
  witness through its real stdin protocol.
  - The witness must accept a killed cgroup, and a killed cgroup that was then removed.
  - It must refuse all of these:
    - a surviving descendant
    - a rename that would hide a survivor (cgroup v2 refuses the rename, so the survivor stays
      visible and must still be refused)
    - a pathname replaced by a new cgroup
    - a stalled control
    - a recycled start time
- It records what this kernel serves through a held descriptor once its cgroup is removed, and
  whether it allows a rename. It writes `private/native-witness-<time>/evidence.json`, under the
  ignored `private/`, so a run leaves nothing in `docs/` to collide with a later pull. Commit
  evidence worth keeping under `docs/audits/evidence/`. The harness touches no cgroup it did not
  create.
- Root is needed only to create, kill and remove those cgroups.
- This check covers the observer alone. A SPLAT lease, A2A cancellation, a signed receipt and a
  sensor event remain the B pilot's.

**First two runs, 2026-11-06**, on separate boots ([first](audits/evidence/2026-11-06-native-witness/first-run.json),
[second](audits/evidence/2026-11-06-native-witness/second-run.json): Ubuntu 26.04.1, kernel
6.18.33.2-microsoft-standard-WSL2, Python 3.14.4). Both runs gave the same result, and six of seven
scenarios passed:
- The witness accepted both drains.
- It refused the surviving descendant, the replaced pathname, the stalled control and the recycled
  start time.
- The seventh failed in the harness, not the witness: cgroup v2 refused the rename with EPERM.

The harness now records that refusal and still requires the visible survivor to be refused.

**Corrected harness, 2026-11-06: PASS, 7 of 7**
([evidence](audits/evidence/2026-11-06-native-witness/third-run.json), a third boot):
- The kernel again refused the rename (EPERM), and the witness refused the visible survivor.
- The removed cgroup again showed ENOENT through the held descriptor, with procfs marking it
  `(deleted)`.

The witness bytes were the committed blob, pinned by SHA-256 `d33c1c6f…`. This proves the
observer on the real kernel. It is not the B chain: no SPLAT lease, A2A cancellation, signed
receipt or sensor event was involved.

This exercises loss of the **intake response body**, duplicate intake and durable admission.
It does not claim a sidecar-crash, power-loss or lost-`CancelTask`-response experiment. Those
remain separate fault-injection runs, with before/after process and receipt evidence required.

## C: authorized Falcon pilot setup

Use one authorized deployment and a benign detection confined to the public fixture. Prepare
the guest, sidecar, certificates, profile, two admitted workloads and identity records before
capturing the event. The existing freshness contract is 30 seconds old / 2 seconds future;
do not rewrite vendor timestamps to make an old exported event pass.

The test target should run the fixture's `target` role through SPLAT. It spawns a descendant,
so exiting only the root cannot satisfy the cgroup-drain check. The independently admitted
control should run the `control` role, which performs bounded CPU work so post-cancellation
progress can be observed. The lease must permit the reviewed interpreter, script and runtime
dependencies. The harness does not bypass the policy compiler or create broad test leases.
Both leases must last beyond the planned pilot window. The fixture's own duration is bounded
to 10–300 seconds and defaults to 120 seconds.

Deploy the reviewed observer bytes into the guest under operator-controlled ownership, readable
by its root observer process and not writable by workloads. Deploy the workload fixture read-only
and readable by the workload UID. Record the SHA-256 of the **actual deployed observer bytes**;
line-ending conversion changes this pin. The observer refuses a mismatched source hash.

The Falcon profile explicitly maps tenant/customer ID, agent ID, the appropriate opaque process
identifier, rule, event identifier and observation time. A ProcessRollup2 `TargetProcessId` and
another event's `ContextProcessId` can be vendor-correlated, but neither is an OS PID or a SPLAT
task identity. Use the reviewed mapping for the actual event type. No generic fallback was added.

For `operator-captured-falcon`, retain the original tenant event and a tenant-side evidence
reference establishing its origin and authorization. A JSON file alone cannot authenticate its
vendor origin. The manifest deliberately reports `vendorOriginIndependentlyVerified: false`.
Even `PASS_CANCELLATION_CHAIN` does not by itself close the live-vendor provenance gate.

## Required plan fields

`plan.json` is a JSON object using these exact camel-case names. Unknown properties are rejected.
These are deployment inputs, not example credentials or fabricated measured identities.

| Field | Required source / meaning |
| --- | --- |
| `version` | Integer `1`. |
| `target.taskId` | The admitted target's 32-character UUID without hyphens. |
| `target.missionId` | The same UUID with hyphens, matching the native mission wire format. |
| `target.cgroup` | Native cgroup inode ID established by the trusted admission owner. |
| `target.daemonKeySha256` | Lowercase SHA-256 of the daemon's **PKCS#1 RSAPublicKey DER** bytes, pinned through an independent provisioning channel before the test. Do not copy a key ID from the receipt under test. |
| `target.executionContext` | Exact native-bound execution-context JSON **as a string**, including original field order/nulls. Obtain it from the admission owner before execution; never reconstruct it from the terminal receipt. |
| `target.executionPolicySha256` | Pre-admitted requested execution-policy hash, or `none` for the actual unfiltered contract. |
| `target.effectivePolicySha256` | Expected installed policy digest from trusted admission evidence. No inference from the receipt being verified. |
| `controlTaskId` | Different, independently admitted control task UUID. |
| `controlExecutionContextSha256` | Identity hash generated by `--inspect-pilot-context` from the independently pinned control context. This is not a raw JSON-text hash. |
| `witness.boot` | Current guest boot UUID, matching the root binding. |
| `witness.target` / `witness.control` | Each contains `taskId`, `cgroup`, `pid`, `startTicks`. Target fields must match the binding; control task/PID/cgroup must be disjoint. |
| `distribution` | Authorized WSL guest name. No implicit default guest selection. |
| `guestWitnessPath` | Absolute guest path to the deployed reviewed observer. Passed as a process argument, never shell text. |
| `guestWitnessSha256` | SHA-256 of the actual deployed observer file. |
| `sidecarCertificateSha256` / `a2aCertificateSha256` | SHA-256 of each endpoint's DER leaf certificate. Normal chain/name/expiry validation must also succeed. Certificates must validate for `127.0.0.1`. |
| `timeoutSeconds` | Integer 5–120; a deadline produces an incomplete result, never a successful proof. |
| `eventOrigin` | `synthetic-control` for B's contract experiment, or `operator-captured-falcon` for C's authorized event. |
| `operatorEvidenceReference` | Bounded, nonempty reference to the operator's authorization/source record. It is provenance supplied by the operator, not independently verified by the runner. |
| `mailboxPath` | Absolute Windows path to the sidecar's existing task mailbox. Read-only access is required. |

`binding.json` and `profile.json` use the existing [Falcon operator contract](FALCON-SIDECAR.md).
`event.json` contains the original fresh vendor event, or a clearly labeled synthetic B control.
Configure `SPLAT_ALERT_TOKEN` and `SPLAT_A2A_CALLER_TOKEN` in each process's environment; they
are not plan fields and are never copied into evidence.
- Give the sidecar the token that `splat/RegisterSensor` returns for the target task
  ([sensor registration](A2A-TEMPLATE-BRIDGE.md#sensor-registration)). That token reads and
  cancels that one task only.
- `--run-falcon-pilot` reads both the target and the control task, which a target-scoped token
  cannot do, so run it with the owner's credential. It calls only `GetTask`.

## Commands

```powershell
$sdk = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
& .\packaging\test-falcon-pilot.ps1 -DotNetPath $sdk
$sidecar = '.\src\splat-alert-sidecar\bin\Release\net10.0\splat-alert-sidecar.dll'
& $sdk $sidecar --inspect-pilot-context .\control-context.json
```

- `$sdk` selects .NET 10 explicitly; the system PATH SDK is unsuitable.
- The gate builds with normal warning checks, then runs sidecar checks, Python witness contracts,
  real C#/Python process-pipe checks, and the offline native audit suite. It writes a new evidence
  directory with counts derived from test output and source/log hashes. It never claims a live pilot.
- The Python tests inject kernel outcomes; they do not test Linux enforcement.
- `--inspect-pilot-context` validates the known context schema, sorts non-null fields and hashes
  their JSON encoding. Null optional fields and omitted optional fields compare equally for A2A
  metadata. The receipt's signed execution-context bytes remain exact and are never normalized.

Once the deployment inputs and fresh event exist, run from the authorized operator shell:

```powershell
& $sdk $sidecar --check-falcon-pilot .\plan.json .\binding.json .\profile.json .\event.json
& $sdk $sidecar --run-falcon-pilot .\plan.json .\binding.json .\profile.json .\event.json .\pilot-run-001
```

- The five positional paths supply the plan, binding, reviewed schema, original event and new
  evidence directory. The directory must not already exist; existing evidence is never overwritten.
- `--check-falcon-pilot` takes only the four input paths. It uses the live runner's exact bounded
  parsing, identity, timestamp and profile-pin validation without credentials, network access,
  mailbox access or native execution. Its `VALIDATED_INPUTS_ONLY` output is not an admission lease
  or a cached authorization: the live command revalidates freshness when it starts.
- All network requests stay on the binding's explicit HTTPS loopback ports, with redirects disabled.
- HTTP 202 means durable intake only. Final success requires the independently checked receipt
  and post-cancellation native/control observations described above.
- `pilot-run-001` retains original inputs, HTTP result summaries, read-only mailbox observations,
  task snapshots, native samples, verified receipt details and a manifest with file hashes.
  Protect it as an operator evidence directory; vendor events and task artifacts may contain
  organization data. No auth headers or tokens are recorded.

To reverify a retained canceled task without issuing any network request:

```powershell
& $sdk $sidecar --verify-cancellation .\receipt-expectation.json .\retained-task.json
```

- `receipt-expectation.json` contains only the `target` object's fields from the trusted plan.
- `retained-task.json` is the A2A task object (for example a retained `target-poll-*.json`), not a
  JSON-RPC wrapper. A host flag, missing signature, wrong signer, changed context, legacy receipt,
  natural completion or ambiguous artifacts returns nonzero.
- Offline success attests the pinned daemon's signed statement. It does not reproduce the
  independent native observations or establish vendor delivery by itself.

## Boundaries and acceptance matrix

| Condition | Required result |
| --- | --- |
| Wrong tenant or opaque process instance | HTTP 409; durable mailbox remains idle; native target/control remain alive. |
| Positive delivery and exact replay | Two HTTP 202 responses; one expected durable cancellation record. |
| Host merely reports termination | Insufficient; no signed expected receipt means unresolved/failure. |
| Valid signature under another key | Rejected, even when its self-described key ID is internally consistent. |
| Target root exits but descendants remain | Native witness refuses cgroup drain. |
| Control advances only before cancellation | Refused; new CPU progress after the post-cancellation barrier is required. |
| PID reuse, boot mismatch or cgroup replacement | Refused; original kernel handles and expected birth identities must agree. |
| Native or network prerequisite unavailable | Nonzero failure/incomplete manifest, never a successful live result. |
| Successful B chain with synthetic input | Scoped cancellation-chain result; no claim of Falcon interoperability. |
| Successful C chain plus independently retained tenant evidence | Candidate live pilot evidence, still subject to operator review and deployment scope. |

The RSA signature is an attestation by the holder of the guest's private key, not a proof that
guest root is honest. The read-only observer shares that privileged guest boundary. The v2
receipt does not itself include a boot ID or freshness timestamp; unique, non-reused task/context
identities and the held-handle before/after experiment are essential. Do not reuse an old task UUID
to manufacture a new test. Observer snapshots establish a finite observation interval, not
permanent control-workload survival.

The evidence manifest is unsigned and locally writable by the operator. Hashes establish file
consistency, not off-host anchoring. SIEM durability, credential-scope hardening, process-crash
recovery, sustained operation, latency distributions and SOC 2 examination remain separate gates.
No shipping daemon/BPF source or kernel proof file was changed for this harness.

Primary references: [pidfd lifetime/poll behavior](https://www.man7.org/linux/man-pages/man2/pidfd_open.2.html),
[cgroup v2 populated/removal semantics](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html),
and [CrowdStrike's vendor process-ID joins](https://library.humio.com/integrations/integrations-crowdstrike-fdr-crowdstrike-fdr.html).
