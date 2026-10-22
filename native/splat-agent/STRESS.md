# Bounded stress evidence — 2026-10-20

**Containment, receipt integrity and cleanup: PASS, 321/321 checks. Lossless telemetry under the
tested floods: FAIL.** The [recorded run](evidence/stress-probe.json) contains independent workload
counts, kernel counters, authenticated frame counts, signed receipts, source hashes and restoration
checks. Its `verdict` covers the checks, not a throughput or lossless-delivery guarantee.

Across this run, **7,404,420 unauthorized opens/execs were denied**, with no unauthorized marker
execution observed. This is a bounded workload result, not proof that arbitrary workloads cannot
escape. No model API or external network request was made.

## What was exercised

| Phase | Observed result |
| :--- | :--- |
| Positive control | 1,000 permitted opens of `/etc/hostname`; the same file was protected in the floods. No file contents were collected. |
| Concurrent denial flood | Four private-UID leases, each opening the protected file for two seconds. Every attempt returned `EPERM`. |
| Slow readers | Four leases with each receiver paused for one second after the workload's ready marker. Every protected open remained denied. |
| Paused consumer | Only the temporary test daemon received `SIGSTOP` for 500 ms, then `SIGCONT`; installed BPF policy kept denying. |
| Deep OverlayFS path | 64 directories, 3,986-byte path: 100 permitted execs and 100 denied execs through distinct same-prefix symlinks. |
| Inode exchange race | 272,360 atomic exchanges during 1,000 exec attempts: 458 benign executions, 542 denials, zero unauthorized exit-73 markers and zero other errors. |
| Lease churn | 16 additional leases completed and drained; request-to-exit p50 48.46 ms, p95 75.23 ms, excluding the connection handshake. |
| Windows MCP bridge | Actual packaged `splat-mcp.exe` → WSL daemon: 50,000/50,000 unauthorized execs denied and all 50,000 events received; signed count verified against the host's sealed run facts. |
| Recovery | All lease cgroups drained; original installed daemon binary restored and authenticated enforcing health verified. No permanent deployment occurred. |

The native workload limits were 128 MiB, 50% of one CPU and 16 PIDs per lease, with at most four
concurrent leases. The separate Windows call used generic MCP limits (256 MiB, 50%, 100 PIDs) and
a 20-second lease timeout. No global memory-pressure workload or installed-daemon throttling ran.

## Telemetry is the measured bottleneck

| Native phase | Kernel denials | Ring reservation drops | Frames received | Additional undelivered records |
| :--- | ---: | ---: | ---: | ---: |
| Denial flood | 2,209,892 | 1,605,534 | 218,857 | 385,501 |
| Slow readers | 2,672,872 | 1,849,709 | 182,081 | 641,082 |
| Paused consumer | 2,471,014 | 1,942,459 | 186,468 | 342,087 |
| **Total** | **7,353,778** | **5,397,702** | **587,406** | **1,368,670** |

**92.01% of native flood event details did not reach the clients.** Kernel ring reservation failures
accounted for 73.40% of denials; the remaining shortfall is computed as
`kernelDenials - ringBufferDrops - framesReceived`. This run does not isolate every later loss stage.
Global before/after counter deltas are used: the per-lease dropped field covers overlapping global
intervals and must not be summed across concurrent leases.

All twelve flood receipts correctly declared incomplete evidence, their signatures verified, and
each per-cgroup denial count matched the independent workload counter. A ring reservation failure
does not change the hook's denial decision. Successful permitted operations do not emit denial
records, so a permitted-exec-only benchmark would not exercise this telemetry bottleneck.

The Windows workload took 2.256 seconds; the entire MCP process took 6.403 seconds and returned
**6,251,391 bytes** for 50,000 events. This measured run was lossless, but the MCP handler retains a
list and formats each event into its response
([source](../../src/splat-mcp/McpServerHandler.cs)). This demonstrates response growth, not a
measured WinUI hang or an unlimited-load guarantee.

Health checks succeeded 221 times with zero errors: p50 1.32 ms, p95 145.76 ms, maximum 438.91 ms.
Sampled daemon peak RSS was 12,984 KiB; sampling can miss transient peaks. These latencies include
scheduling and protocol work, and do not measure BPF-only syscall overhead.

## Identity, reproducibility and scope

| Input | SHA-256 |
| :--- | :--- |
| Packaged daemon | `1a340b116c7b90b441058bd8e201fa22592860f8d559bbf1efafba0c1ad67743` |
| Packaged Windows MCP | `d35b71b9e35170edbf1dfd76a27af1e499d837c2689c6452a928c84de7a6fbe1` |
| BPF source | `6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1` |
| Build manifest | `0af582efe40a5f4f8789d39e7a0db37f11a9d0151b2fd10e4d927c6379f7eec6` |

Kernel: `6.18.33.2-microsoft-standard-WSL2`. The runner verified the packaged artifact hashes and
manifest source inputs before execution, and unchanged compiled/native inputs afterward. The
evidence also records the runner, probe, C source and compiled workload hashes. Guest signatures
authenticate their canonical outcomes with the supplied guest key; they are not remote attestation
or a signature over this entire report. The temporary host ledger used its default unkeyed chain.

The tested manifest identifies an **AGPL-3.0-only community package**. These public probes do not
establish a separately licensed Corporate distribution or change its licensing terms.

From the repository root, after approval for temporary service/pin turnover, with the named package
available locally:

```powershell
wsl.exe -d Ubuntu -u root -- python3 /mnt/c/C_AGENT_BUILDER/native/splat-agent/probe-stress.py `
  --daemon /mnt/c/C_AGENT_BUILDER/dist/rare-a2a-break-proof-20261017/splat-agent `
  --manifest /mnt/c/C_AGENT_BUILDER/dist/rare-a2a-break-proof-20261017/MCP-BUILD-MANIFEST.json `
  --output /mnt/c/C_AGENT_BUILDER/private/stress/new-run.json `
  --retire-idle-pins 6fc637d8e30f375e7b64a51a2438202515cf12cf008fff78b2f8b719a9a8b4f1 `
  --workers 4 --milliseconds 2000 --pause-ms 500 --churn-rounds 4 `
  --mcp-exe /mnt/c/C_AGENT_BUILDER/dist/rare-a2a-break-proof-20261017/splat-mcp.exe `
  --client-root /mnt/c/C_AGENT_BUILDER/private/stress
```

Requires Python 3, a C compiler, OpenSSL and bpftool in the guest. The shared proof runner refuses
active leases, checks pin identity before retirement, and restores the installed service even on
probe failure. It does not install the tested package. Its helper library and marker binaries live
only in temporary synthetic workspaces.

The first Windows attempt produced valid MCP JSON but its synthetic floating-point duration was
partly replaced by the privacy filter's card-number redaction. The probe could not parse that inner
JSON and recorded FAIL; restoration still passed. Integer-millisecond output fixed the probe, and
the complete run above was repeated. The failed diagnostic remains in
`private/review-2026-10-14/stress-20261020-windows.json`.

**Still unproven:** 150,000 events/second for 60 seconds with zero loss; less than 15% syscall
overhead against an unloaded baseline; a million-iteration inode race; CPU affinity/cache-counter
claims; host-wide OOM behavior; WinUI frame time; sustained A2A fleet load; content-hash integrity;
and new per-tool Landlock/seccomp behavior. The new stress result does not close the separate DNS
observation or published Field Guide gates.

Post-run validation matched the committed evidence byte-for-byte to the live output, rechecked
current source hashes, verified all 32 guest signatures and rejected all 32 altered receipts.
The .NET 10 test-project build finished with zero warnings/errors. Documentation checks recorded
18 passed, one failed: `ThePublishedFieldGuide_IsTheSourceAsItStandsToday`, still reporting the
stale published page. The test result is retained locally at
`tests/MissionController.Tests/TestResults/stress-documentation-20261020.trx`.

The next measured improvements should target bounded event aggregation and response size while
preserving exact kernel totals and explicit loss reporting. Those improvements are not implemented
by this probe.

The subsequent [bounded A2A round](A2A_STRESS.md) exercises four callers, delegation/retry races,
quotas, revocation and cancellation. Its overall result is FAIL because rejected delegation
replays leave misleading authorization rows; it does not change this native telemetry result.
