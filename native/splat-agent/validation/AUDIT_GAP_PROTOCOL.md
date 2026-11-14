# Audit-gap candidate: contract and native acceptance

Status: integrated into the shared working tree; offline checks do not establish native enforcement.
Research commit `06d2665788f6de588439c4b5a53402fa0d431216` supplied the apparatus; the audit candidate
supplied the fixes. The merge retains the working tree's 16-byte deadline/epoch map value. It also
adds the research expiry-denial flag to the working BPF program so the lifecycle probe can distinguish
expiry from ordinary denial. This is a new BPF source and needs new native evidence.

## Authority and installation

The trusted harness fixes `approvedAtBootNs` and `deadlineBootNs` before submitting the request,
with `clock: guest-boottime`. The deadline equals start plus the approved duration (5..300 seconds).
Installation and validation consume that budget. Re-reading or reinstalling an approval cannot
renew it; renewal requires a newly minted approval. This is guest BOOTTIME, not elapsed host wall
time across standby or a VM pause.

With `--admission-gate`, the daemon reads a root-owned, non-group/world-writable regular approval
file through a no-follow descriptor, with bounded size. Nonblocking open avoids hanging on a FIFO.
It checks mission, boot, clock, lifetime arithmetic and freshness before allocating resources.
The harness-created approval directory and its ancestors are trusted. This is not protection
against an administrator changing the authority or the kernel.

The exact deadline reaches `leased_cgroups`; the reaper uses the remaining budget. B3 compares
the installed deadline for exact equality with the independently read approval. B2 and B2W retain
their writer-byte comparisons. All gated variants share the revised installation path and the
daemon's final expiry check; B3 additionally checks expiry when validation finishes. The ungated
baseline retains duration-based leases. Report this difference when comparing baseline cost.

The frozen 2026-10-27 apparatus had exec tag `debffec9428e2ccf` and open tag `1caf221233c125e0`.
Those are historical evidence, not expected tags for this merged build. Step 2 below set the shipped
profile's tags on 2026-11-13, for BPF `5e218eb1`; until then both were null and the gate refused.
Names, hook attachment, daemon ownership and map layouts remain necessary. A missing, malformed or
unequal tag refuses admission. Do not auto-update the
profile from an unreviewed loaded program. BPF tags are limited program fingerprints, not signatures
or a proof that the semantic interpreter matches the machine code. Build/source hashes and the
independent correspondence argument remain necessary.

## Reproduction before a native claim

1. Review the integrated diff, including peer changes, and commit the reviewed integrated build.
   Run `python3 -I validation/test_audit_gaps.py` and `cargo test --locked` in the build guest. The
   latter includes three new lease-installation tests that have not been run on Windows.
2. Build and run the no-gate lifecycle probe to collect the new programs for independent review.
   Review the program/source correspondence and set the two expected tags explicitly; commit and
   rebuild the staged apparatus. Never learn-and-accept tags from an arbitrary live program.
   Build using `build_842.sh`; retain the new commit, compiler versions, binary and BPF hashes,
   staged profile, protocol and complete SHA256SUMS. Use a fresh bundle for `run_unified.sh` with
   the registered repetitions. Retain the initial BPF-LSM link inventory and raw per-CPU trace
   statistics in addition to the existing records. Keep the no-gate lifecycle probe in this build.
3. Before claiming closure, implement and run the additional native mutation cases below. The
   offline suite contains these predicates; the existing 8.4.2/8.4.3 drivers do not yet automate
   these new native conditions. Pre-register repetitions before observing native outcomes.

| Additional native condition | Required observation |
| --- | --- |
| Reviewed exec and open tags, exact live deadline | B3 admits and approved executable succeeds |
| Actual same-name exec or open program with a different tag, same layout | Indeterminate; no workload image executes |
| Missing or wrong expected tag in profile | Indeterminate; no workload image executes |
| Installed deadline extended by 1 ns or 457,044,676 ns, writer record extended too | B3 rejects; ordinary B2 can match writer bytes |
| Installed deadline shortened by 1 ns | B3 rejects the mismatched contract |
| Delayed installation within the budget | Original absolute deadline remains in kernel map |
| Approval already expired when request arrives | Refusal before allocation; no residual state |
| Approval expires during collection or before gate returns | Refusal; no workload image executes |
| Wrong boot, wrong mission, future start, malformed or overflowed lifetime | Refusal; no residual state |

Do not count setup failures as detections. Save approvals, writer bytes, live program/map metadata,
gate records, daemon frames and successful-exec traces together. No historical bundle is rewritten.
Post-decision external map writes remain an acknowledged failure boundary. This candidate does not
provide immutable policy generations, stable executable identity through exec, or Windows last-hop
reproduction. Those require separate changes and experiments.
