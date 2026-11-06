# Reconciliation follow-up: SPLAT and Falcon sidecar

The sidecar's cancellation authority remains separate from the kernel enforcement path. This
follow-up closes the adapter's documentation and build-reproduction gaps after reconciliation;
it does not qualify a live Falcon integration or establish SOC 2 compliance.

Base inspected: SPLAT `35258c5`, on `main`, matching the local `origin/main` tracking reference.
The checkout was clean when inspection began, and `git worktree list` showed only the primary
checkout. No remote fetch or push was performed, so this is not a fresh remote-state assertion.

## Changes and evidence

| Item | Result and evidence |
| --- | --- |
| Sidecar build entry point | Added `-DotNetPath` to `packaging/test-alert-sidecar.ps1`. This sandbox redirects `LOCALAPPDATA`, so its default path could not locate the installed SDK. The explicit path still enforces .NET 10 and the normal warning gate. |
| Sidecar validation | Normal Release build: zero warnings/errors; all 74 checks passed. [Build and check output](evidence/2026-11-05-reconciliation/sidecar-gate.txt). No NU1900 suppression was used. |
| Falcon operator handoff | Added [FALCON-SIDECAR.md](../FALCON-SIDECAR.md): admission identity, profile fields/hash, offline commands, authenticated route, retry semantics, relay boundary, acceptance criteria and rollback. |
| Architecture status | Updated [DECOUPLED-SENSOR-ENFORCEMENT.md](../DECOUPLED-SENSOR-ENFORCEMENT.md) to describe the adapter and distinguish the historical 28-check run from the current 74-check gate. |
| Test project compilation | Separate Debug build passed with zero warnings/errors. [Output](evidence/2026-11-05-reconciliation/tests-build.txt). |
| Focused .NET regression rerun | **Aborted before tests executed.** VSTest could not connect to testhost within 90 seconds. [Output](evidence/2026-11-05-reconciliation/focused-tests.txt), [TRX](evidence/2026-11-05-reconciliation/focused-tests.trx). No passing regression-suite claim is made for this invocation. |
| Offline native audit checks | `python -I native/splat-agent/validation/test_audit_gaps.py`: 33 tests passed. These simulate kernel observations; they are not a kernel reproof. |
| Shipping native proof | Both committed proof records say PASS and name the current LF-normalized BPF source hash, `d5bb4cad4c3397f1e12c0ca7952b10c1b2a2694b777ec84d30266d21b2b0af80`. The records were inspected, not rerun. |

Machine-readable provenance, source and assembly hashes, log hashes and check outcomes are in
[verification.json](evidence/2026-11-05-reconciliation/verification.json). Source hashes there use
the exact worktree bytes; the BPF proof comparison separately uses LF normalization to match
the repository's proof convention. No files under `src`, `native` or `tests` were changed by
this follow-up.

## What the reconciliation report establishes

The original reconciliation ledger is the `task.md` under the local Antigravity task
`acfdd997-59c6-4fb2-8ff5-7f1b857f51ac`. It reports SPLAT's full suite as 1,175 passed and six
skipped (1,181 total), a clean ten-project solution build, and RARE's 130 Python plus 46
browser/contract checks passing. Those are prior-run reports, not fresh results from this session.

The [daemon record](../../native/splat-agent/evidence/daemon-probe.json) contains 90 Boolean
observations: 84 true and six false. The false observations are the protected-file leak and five
cross-lease access attempts, where false is the desired outcome. Thus ΓÇ£90/90ΓÇ¥ in the handoff must
not be read as ΓÇ£all 90 values are true.ΓÇ¥ The probe's verdict and its diagnostic observations also
have distinct gating semantics; see `native/splat-agent/probe-daemon.sh`.

The [last-hop record](../../native/splat-agent/evidence/last-hop-probe.json) records PASS for the
MCP-to-kernel path. Both records were captured on 2026-11-05 against the shipped Debian 13 guest.
These proofs support that tested path; they do not prove the experimental `lease-open` hook,
Falcon delivery, or the sidecar-to-native cancellation chain.

RARE's checkout resolves to `C:\Users\s_pla\OneDrive\Desktop\RARE`, which this sandbox denies
access to. Its reported `cabb978` tip, clean status, worktree retirement and test results were
therefore not independently reverified here. No RARE file was changed.

## Remaining gates

1. Run the focused .NET checks in a runner where VSTest can connect to its test host. The current
   abort cannot establish whether the SIEM TLS, DNS cache, WSL wire or documentation tests pass.
2. Validate a customer-authorized Falcon event profile and its trusted task/process-generation
   mapping. The checked-in fixtures are synthetic; automatic admission registration is still absent.
3. Exercise live relay/TLS delivery through A2A cancellation to independently observed native drain.
   Retain installed hashes and receipts; test restart, disk failure, retry and wrong-identity controls.
4. Measure sensor coexistence and end-to-end latency distributions before making a performance
   claim. The 25 ms control poll alone precludes a sub-millisecond reaction claim for this prototype.

Git denied creation of a follow-up branch because its metadata is read-only in this sandbox.
The prepared changes remain uncommitted on the existing `main` working tree. No branch switch,
merge, commit, push or new worktree succeeded during this follow-up.
