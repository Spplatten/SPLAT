# Falcon reconciliation closure: local fixes and remaining execution gates

The host now sends explicit LF-terminated UTF-8 commands, and the observer requires retained
cgroup evidence before accepting drain. The earlier Windows default CRLF framing would have
prevented the Linux witness from accepting `check` and `after`. A missing pathname previously
allowed a rename to be mistaken for deletion. Both defects are fixed in the candidate harness.

## Evidence from this checkout

[Local gate manifest](evidence/2026-11-06-falcon-closure/verification.json) records the exact
source, assembly and log hashes. [Prerequisite record](evidence/2026-11-06-falcon-closure/prerequisites.json)
names the blocked runtime checks. Earlier evidence directories are retained unchanged as history.

| Check | Observed result | Boundary |
| --- | --- | --- |
| Release sidecar build | 0 warnings, 0 errors | .NET 10; normal warning policy. |
| Sidecar contracts | 189 passed: original 74, registrar 64, proof/pilot 51 | Real RSA/SQLite and in-process HTTP handler tests; synthetic identities. |
| Witness contracts | 17 passed | Parser/schema and injected OS outcomes; no kernel execution. |
| C# to Python wire | 11 passed | Real redirected process pipes, UTF-8/LF, EOF/size/cancellation rejection, stderr backpressure. |
| Offline native audit | 33 passed | Existing simulated kernel-observation suite; no native reproof. |
| Focused VSTest | Blocked before execution | Loopback TCP socket error 10013. No new TRX or passing test claim. |
| WSL status | Blocked | `Wsl/E_ACCESSDENIED`; pidfd/cgroup experiment did not run. |
| Live Falcon pilot | Not run | Authorized deployment and fresh tenant event unavailable. |
| Git commit | Not created | Branch/ref metadata writes denied. Working changes remain uncommitted. |

## Rerun and closure

```powershell
$ErrorActionPreference = 'Stop'
$sdk = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
& .\packaging\test-falcon-pilot.ps1 -DotNetPath $sdk
& .\packaging\test-focused-regressions.ps1 -DotNetPath $sdk
```

- `$ErrorActionPreference` stops the sequence if a gate throws.
- `$sdk` selects the installed .NET 10 SDK, because PATH's SDK 9 cannot build this repository.
  Where a sandbox redirects `LOCALAPPDATA`, set it to that executable's real path.
- `test-falcon-pilot.ps1` separates build from execution, derives counts from summaries, and
  creates a new evidence directory. A failed command cannot produce its PASS manifest.
- `test-focused-regressions.ps1` tests VSTest's loopback prerequisite, then builds serially and
  runs focused tests with `--no-build`. Run it on a runner that permits loopback. Raising timeouts
  or disabling security controls does not resolve the observed denial.

**Closure, 2026-11-06.** The session that wrote this record could not commit.
- Its changes were committed verbatim as `peer/falcon-closure` (`c385cf9`), parented on its
  restored registrar commit `65c2e40`. The two ignored TRX files were not added.
- That branch was merged with the Falco binding and registrar work (PR #29).
- Its commit helper and file manifest were removed after use. They could only ever commit on top
  of `35258c5`.
- On a machine that permits loopback, the local gates pass: 256 sidecar checks, 17 witness
  contract tests, 11 process-pipe checks and 33 offline audit tests. The four focused VSTest
  classes pass 77 tests.
- No shipping daemon/BPF source or enforcement proof was changed.
- Native pidfd/cgroup execution and the live Falcon pilot have not been run.

## Mapping to the reconciliation gaps

| Identifier or primitive | Mechanical role | Gap closed or still open |
| --- | --- | --- |
| `WitnessWire.WriteAsync` | Strict UTF-8, no BOM, explicit LF, bounded single frame | Makes the Windows host obey the guest protocol; does not establish caller identity. |
| `WitnessWire.ReadAsync` | Requires a delimiter, rejects CR/overflow/truncated EOF, honors cancellation | Prevents partial output from being treated as a complete observation. |
| `WitnessWire.DrainAsync` | Continuously consumes stderr with bounded memory | Prevents a witness diagnostic burst from deadlocking the proof path. |
| Retained `pidfd` and `cgroup_fd` | Keep original process and cgroup kernel objects referenced | Gap 1: a numeric PID or missing pathname never becomes authority. |
| `startTicks`, boot UUID, cgroup inode, task UUID | Cross-check expected process birth and workload association | Gap 1: reuse/mismatch fails closed; automatic trusted collection remains a deployment prerequisite. |
| `populated` relative to `cgroup_fd` | Reads the original cgroup despite pathname disappearance | Gap 1 descendant drain: surviving members cannot be hidden by a rename. |
| ENOENT/ENODEV plus procfs deleted handle plus absent path | Restricted removal fallback | Permission failures, renamed handles and path replacement refuse proof; deployed-kernel behavior remains unproven. |
| `FalconPilot.LoadInputs` | Shared bounded parsing, profile hash, identity and freshness validation | Gap 1: offline preparation cannot weaken the actual live check. |
| `--check-falcon-pilot` | Validates input files without credentials, network or witness | Closes configuration triage; never grants admission or verifies vendor origin. |
| Signed v2 receipt and independent native samples | Match expected invocation and separately observe drain/control progress | Option B evidence contract implemented; end-to-end run remains required. |
| Unmodified tenant event and external provenance record | Preserve original sensor content and independently review origin | Option C still requires an authorized live event and deployment. |

These changes address the identity and evidence boundaries described in
[2026-11-05-reconciliation-follow-up.md](2026-11-05-reconciliation-follow-up.md).
The live CLI still uses a supplied root binding: automatic trusted registrar/native descendant
enrollment is not newly claimed. Follow the [pilot runbook](../FALCON-CANCELLATION-PILOT.md) to
deploy and pin the updated observer, admit separate target/control workloads, validate fresh
inputs and capture the actual cancellation chain. Vendor provenance, process-crash recovery
and lost-CancelTask-response fault injection remain separate acceptance gates.
