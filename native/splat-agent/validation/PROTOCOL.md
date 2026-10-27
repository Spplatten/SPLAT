# Milestone run 1: protocol

Fixed before the run. The commit that adds this file is its timestamp; `build_842.sh` stages it, so
the bundle's `SHA256SUMS` binds the run to it. A change after the run is a protocol revision and
produces a separately labelled dataset.

**Scope.** One invocation of `run_unified.sh`: the root lifecycle probe with an expiry series, then
8.4.2 and 8.4.3, on one staged binary, in `SplatGuestCheck` (a plain import of guest archive
`9c5fab83`, with nothing changed by hand). The run is also the root proof of that archive.

**Repetitions.**

| Part | Unit | n |
| :--- | :--- | :--- |
| Expiry series (probe steps 21-22) | one lease killed mid-lease, expired, restarted; then one reaped lease | 30 |
| 8.4.2 | randomized block of its 8 conditions | 20 blocks (160 runs) |
| 8.4.3 | randomized block of its 16 conditions, per daemon phase | 20 blocks (320 runs) |
| 8.4.3 baseline | correct lease, no gate | 60 |

Thirty expiries with none failing bounds a per-run failure rate below 10 % (95 %, one-sided). Twenty
runs per condition bound it below 14 %. Both bounds hold only for this guest, this kernel and these
policies. Expiry repeats are separate leases (a fresh cgroup each time, and the daemon killed and
restarted) within one boot and one pin set. They are not independent boots.

**Warmup and timeouts.** No run is discarded as warmup. Cost is reported twice: once over every
run, and once without the first run of each daemon phase. The timeouts are the ones in the committed
code. None is changed for this run.

**Exclusions.**

1. A refusal before any experiment starts is not a run. That covers a staged hash mismatch, an LSM
   program already attached, and existing pins. Clear the cause and start again.
2. No individual run is removed. Invalid-setup and indeterminate runs stay in every denominator and
   are reported as their own classes. They fail the verdict and are never relabelled as detections
   or misses.
3. An abort mid-run leaves a partial bundle. Causes include a guest or WSL restart, host sleep and
   out-of-memory. Keep that bundle, labelled aborted, and repeat the whole run once in a fresh one.
   Report both.
4. No repetitions are added after results are seen. An unexpected result is a finding. A fix means
   a new commit and a new, separately labelled run.

**Pass.** `unified.json` verdict PASS: probe PASS, including `expiry_series_every_run_held`; 8.4.2
and 8.4.3 every run as registered; zero residual policy entries; and one binary and one BPF source
hash across all three parts.

**Reported.**

- Expiry: every run's row, plus min, median and max of the bracket, the per-hook kernel refusal
  latency, the reaper delay and restart-to-drain. Drained denials are compared with counted denials,
  and ring drops are reported. No quantile is claimed beyond the observed maximum.
- 8.4.2 and 8.4.3: classification and effect counts for each condition. False acceptance and false
  rejection follow §8.4.3. A B2W catch is credited to the collector.
- Cost: gate time per variant, and request time with and without a gate, each as median and range.
  This is a pilot. It sizes any later confirmatory cost study.

**Environment.** Ubuntu's `splat-agent.service` shares the kernel. It is stopped and its pins are
removed for the run, then it is restarted. The host stays awake and runs no test suite during the run.
