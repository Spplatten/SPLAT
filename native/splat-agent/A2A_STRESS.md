# Bounded A2A stress evidence — 2026-10-20

**Overall: FAIL.** The [live report](evidence/a2a-stress-probe.json) records 75 passing checks and
two failing checks: the worker's admission-audit check, and the aggregate client-result check.
They reflect one reproduced defect: **16 rejected delegation replays left `A2A_TASK_AUTHORIZED`
rows without retained tasks or execution records.** No duplicate execution was observed.

The run used actual packaged Windows HTTPS A2A hosts, a temporary enforcing WSL daemon, and
read-only guest-identity template leases. It made no model API or external HTTP requests. The
original installed daemon was restored and authenticated enforcing health was verified.

## Categories exercised

| Category | Measured result |
| :--- | :--- |
| Retry races | 16 simultaneous requests with the same message ID returned one task and the same receipt. A changed request was refused. Restart preserved the original task. |
| Delegation replay | Of 16 simultaneous distinct requests using one signed grant, one was accepted and 15 returned HTTP 403. Replay after restart also returned 403. The audit defect below remained. |
| Caller, tenant and authority boundaries | Wrong callers and tenants could not use a fresh, unspent grant; its intended caller could subsequently use it. Sixteen cross-principal task-read/cancel attempts were refused. Altered signed authority, bare parent IDs and the generic `run_command` tool were refused. |
| Narrowed file authority | Removing `/proc/meminfo` from the tool's file grants caused the real read to fail with `Permission denied`; the failed task still carried a verified guest receipt. |
| HTTPS and request validation | Invalid bearer: 401; browser Origin: 403; 65,537-byte body: 413; duplicate JSON properties: JSON-RPC `-32602`. The client pinned the exact ephemeral certificate before sending credentials. |
| Sustained delegation | Four callers in two tenants completed 221 parent-to-worker pairs in 60.768 seconds: 56, 56, 54 and 55 pairs. No legitimate request in this phase was refused. |
| Cancellation races | 24 attempts: six confirmed canceled with signed drain evidence, 16 canceled without individual signed drain confirmation, two completed before cancellation. |
| Running quotas | A 16-request burst produced two successful tasks and 14 HTTP 429 responses; the other caller progressed. Across 24 observations at a requested 5 ms interval, maxima were one task per caller and two overall. Sampling can miss short transitions. |
| Retained-task quotas | The six-slot test host refused excess work with 429 while an unrelated caller still had room. Once all six slots filled, completion and restart did not free them. Original-message retries still worked. |
| Revocation reload | Eight requests from the revoked principal returned 403 while eight from the other tenant returned 200; refusal persisted after restart. The operator change was made only in the private test database. Active-workload revocation and the administration UI were not tested. |
| Receipts and recovery | All 467 collected guest signatures verified independently. Their signed principal, contract, policy and delegation bindings matched the requests; receipted cgroups and workspaces were absent afterward. Health remained enforcing, and the original service was restored. |

The sustained phase was deliberately paced: at least 0.5 seconds per iteration and at most 128
pairs per caller. These results establish bounded four-caller behavior, not maximum throughput,
a large fleet capacity rating, or model reasoning quality. Restarts in this run occurred between
completed operations; recovery from a host crash during an active task remains outside its scope.

## Reproduced audit defect

The worker retained **224 tasks and 224 execution-facts records**, but its ledger contained
**240 authorization rows**. The 16 extra mission IDs are recorded under
`observations.client.workerPersistence.authorizedWithoutRetainedTask` in the live report.
An independent database read confirmed that those IDs had only authorization entries and no
execution-facts records. They correspond to the 15 rejected concurrent uses and the rejected
post-restart reuse of the consumed delegation.

In [A2aBridge.cs](../../src/splat-mcp/A2aBridge.cs), `SendAsync` writes `A2A_TASK_AUTHORIZED` before
calling `_store.Save`. In [A2aTaskStore.cs](../../src/splat-mcp/A2aTaskStore.cs), `Save` then rejects
an already-consumed delegation nonce. The request is refused, but its earlier authorization row
remains. This is misleading admission evidence, not an observed containment escape.

The new probe deliberately fails `client_worker_admission_audit_matches_tasks`. It does not
relabel the rows or discard the failing result. Admission auditing and durable task/nonce
acceptance still need a failure-consistent implementation and a new live proof. This test round
does not modify production admission code.

The earlier local 60-second run reported PASS because it did not yet check orphan authorization
rows. Its ledger already contained the same 16-row defect. The report committed here comes from
the subsequent full rerun with that check enabled and a fresh-token caller/tenant control.

## Cancellation and capacity limits

Of the 16 unconfirmed cancellations, **15 had no `MISSION_RUN_FACTS` record**. The remaining one
had `ExitCode: -3`, `TerminalReason: CallerCancelled`, and no guest-signed outcome. These facts
cannot establish whether each canceled workload was never admitted or was drained. The endpoint
correctly left `workloadTerminationConfirmed` false; it did not fabricate a successful drain.
End-of-run authenticated health showed no active leases, but that does not supply the missing
individual cancellation evidence.

Retained-task quotas failed closed as configured. The six-slot host stayed full after all tasks
completed and after restart. A long-running deployment therefore needs an explicit retention and
capacity-management procedure that preserves retry and consumed-nonce protections. This run did
not implement or test archival or eviction.

## Load and evidence accounting

Across all phases and startup probes, the client observed 847 local HTTPS responses:
782 HTTP 200, 32 HTTP 403, one HTTP 401, one HTTP 413 and 31 HTTP 429. HTTP 200 can contain a
JSON-RPC refusal; protocol-level outcomes were checked separately. Request latency across these
mixed operations was p50 291.93 ms, p95 862.37 ms, maximum 3,030.56 ms. These are not kernel-only
overhead measurements or an unloaded baseline.

| Host | Retained tasks | Execution-facts records | Authorization rows | Database bytes |
| :--- | ---: | ---: | ---: | ---: |
| Parent | 251 | 236 | 251 | 5,570,560 |
| Worker | 224 | 224 | 240 | 4,829,184 |
| Running-quota test | 2 | 2 | 2 | 69,632 |
| Retained-quota test | 6 | 6 | 6 | 69,632 |

There were 468 execution-facts records and 467 signed receipts; the unsigned cancellation record
accounts for the difference. No duplicate mission ID occurred among execution-facts records.
The health monitor recorded 840 successful observations, zero errors, all enforcing, and at most
two active leases in its samples. The source and idle checks completed before the aggregate
failure was raised, and service restoration completed afterward.

## Artifact identity and verification

| Input | SHA-256 |
| :--- | :--- |
| Packaged daemon | `1a340b116c7b90b441058bd8e201fa22592860f8d559bbf1efafba0c1ad67743` |
| Packaged Windows MCP | `d35b71b9e35170edbf1dfd76a27af1e499d837c2689c6452a928c84de7a6fbe1` |
| BPF source | `6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1` |
| Build manifest | `0af582efe40a5f4f8789d39e7a0db37f11a9d0151b2fd10e4d927c6379f7eec6` |
| Live report | `82a35b36cc8a0f2b30c2fb5bdf58d339dfc8b58769d75024c08e4e767fbce022` |
| Full local receipt archive | `3e4cd9998f47e88d00dd8a3890439b82200c8ac00808adbd62723142f85db29a` |

The report began at `2026-10-20T22:37:24Z` on kernel `6.18.33.2-microsoft-standard-WSL2`.
All 261 compiled source inputs matched the package before and after the run. The report also
records the native sources, shared runner, Windows client and root probe hashes. These checks
bind this result to the tested artifact and checkout; they do not attest a future binary.

[Post-run verification](evidence/a2a-stress-verification.json) matched the committed report
byte-for-byte to the live output, rechecked source hashes, verified all 467 signatures again,
and rejected all 467 deliberately altered canonical outcomes. It independently reproduced the
orphan authorization and cancellation counts, and verified the restored service remained active,
enforcing and idle. These verification checks passing do not change the live report's FAIL.

The report includes eight complete receipt samples and the hash/size of the full 1,236,287-byte
local archive. The full archive and private ledgers remain in the directory named by
`observations.clientArtifacts`; they are not included in this public evidence file. Guest
signatures authenticate canonical outcomes using the supplied guest key, not this whole report,
remote attestation, or the default unkeyed host audit chain.

The build manifest labels the tested package **AGPL-3.0-only community**. This test does not
establish a separately licensed Corporate package or change licensing terms. It does not close
the separate DNS observation, stale published Field Guide, or [native flood telemetry](STRESS.md)
limitations. No WinUI responsiveness, host-wide memory exhaustion or external A2A interoperability
claim follows from this local run.

## Reproduction

Use the matching local package and Python installation. This command temporarily turns over the
installed service and verified idle pins, so it requires the operator's approval. The shared
runner refuses active leases and restores the original binary/service on probe failure. No
permanent deployment or provider request occurs. A failure exit is expected while the admission
audit defect remains.

```powershell
wsl.exe -d Ubuntu -u root -- python3 /mnt/c/C_AGENT_BUILDER/native/splat-agent/probe-a2a-stress.py `
  --daemon /mnt/c/C_AGENT_BUILDER/dist/rare-a2a-break-proof-20261017/splat-agent `
  --mcp-exe /mnt/c/C_AGENT_BUILDER/dist/rare-a2a-break-proof-20261017/splat-mcp.exe `
  --build-manifest /mnt/c/C_AGENT_BUILDER/dist/rare-a2a-break-proof-20261017/MCP-BUILD-MANIFEST.json `
  --windows-python /mnt/c/Users/s_pla/AppData/Local/Programs/Python/Python314/python.exe `
  --contract /mnt/c/C_AGENT_BUILDER/examples/agent-manifests/guest-identity.contract.json `
  --client-root /mnt/c/C_AGENT_BUILDER/private/a2a-stress `
  --seconds 60 --output /mnt/c/C_AGENT_BUILDER/private/a2a-stress/new-run.json `
  --retire-idle-pins 6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1
```

The root [probe](probe-a2a-stress.py) verifies artifact/source identity, monitors guest health and
independently verifies receipts. The Windows [client](a2a-stress-client.py) creates private test
contracts, callers, HTTPS hosts and ledgers. Its 240-second watchdog stops its own hosts; the root
runner also bounds client execution. Generated certificate and delegation private-key files are
removed afterward. Private logs and ledgers are retained for investigation.
