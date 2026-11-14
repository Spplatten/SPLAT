# Live-state validation experiment 8.4.2

**Integration status, 2026-10-28:** the audit fixes and research apparatus are now integrated with
the working tree's 16-byte `lease_state { deadline_ns, epoch }` ABI. Step 2's native run is milestone
run 2 (2026-11-14, PASS, below); the additional native cases of step 3 are still pending.
Since 2026-11-13 `profile.json` names reviewed tags for BPF `5e218eb1`: exec `c748f2896421d7e6` and
open `deb61f797da89f40`, the programs the no-gate lifecycle probe loaded in the 2026-11-09 root run.
Its `reviewStatus` says what was reviewed, by whom, and what was not. The historical 8-byte-build
tags certify nothing here, and `test_audit_gaps.py` fails while the profile names a source other
than the one in this tree, so a kernel change needs a new review before the gate admits. The epoch is retained but not used by the current kernel as a generation guarantee.
See `AUDIT_GAP_PROTOCOL.md` for the authority contract and remaining validation.

**Research harness, not a product feature.** It runs one experiment: does semantic validation of the
kernel's installed exec policy catch an unauthorized grant that byte readback accepts? The daemon's
`--admission-gate` flag exists for it; without the flag the daemon admits as before.

| File | Role |
| :--- | :--- |
| `gate.py` | Run by the daemon between its last map write and the fork, under its map-write lock. Identifies the exec program the daemon holds open, captures the maps that program references (twice, must agree), then decides: `OFF` admit, `B2` compare with the writer's bytes, `B3` interpret and compare with the approval. |
| `profile.json` | The interpretation profile: program, hook, map names and layouts for the BPF source it names. |
| `workload_a.c`, `workload_x.c` | A is approved and tries to exec X; X is harmless and never approved. Static. |
| `build_842.sh` | Builds daemon and workloads from a clean tree into a staging directory, with hashes. |
| `run_842.py` | Runs every condition in randomized blocks in the run guest and writes the evidence bundle. |
| `run_843.py`, `workload_p.c` | 8.4.3: a missing protection (P opens a file the approval protects), a wrong identity and a decoy map binding (daemon `--research-fault`, which needs a refusing check: the gate, or the native validator enforcing), a write that ignores the daemon's lock, and a no-gate cost baseline. Variant `B2W` reads back through the writer's own map ids. |
| `run_unified.sh` | The probe (optionally `N` expiry repeats), 8.4.2 and 8.4.3 on one staged binary. |
| `PROTOCOL.md` | Repetitions, exclusions and pass criteria for milestone run 1, fixed before it. |

Conditions: the approval always names A only. The writer's intent is `[A]` (correct), `[A, X]`
(mutated before serialization) or `[A]` with X's key inserted after the writer recorded its bytes
(corrupted). Launch is observed by an ftrace instance on `sched_process_fork`/`sched_process_exec`,
which the kernel emits outside the BPF-LSM program and only for an exec that succeeded.

What B3 shares with the writer, and therefore cannot be independent of: the kernel's `MKDEV`
encoding (`major << 20 | minor`), the assumption that the jail's bind mounts preserve inode identity,
the approval file's integrity (root-owned, not signed), and the profile's reading of the BPF source.
The profile is written from the source, not derived from the loaded bytecode. The bundle records the
kernel's program tag, which was the same across separate loads of the historical build (`debffec9428e2ccf`);
the translated-dump hashes it also keeps change per load, because the dump embeds map ids.

A gate run is indeterminate, and refuses, when any program other than the daemon's own decides
`bprm_check_security`. WSL distros share one kernel, so another distro's orphaned SPLAT pins are such
a program.

## Variant B3N: the same check inside the daemon (implemented, not yet run under root)

`--admission-validator {off,audit,enforce}`, default `off`, runs B3's semantic comparison in the
daemon itself (`src/admission.rs` decides, `src/admission_collect.rs` reads the kernel), after the
gate and under the same lock. Beyond what `gate.py` checks, it verifies:
- the program tag and attach target on all ten hooks, not only `bprm_check_security`;
- that no foreign LSM program sits on any of them;
- that each program's maps are the ones the writer writes, so the decoy fault is caught as a binding;
- the deadline against the approved duration;
- for protected files, that a host submount does not hide them from the jail.

It derives keys independently of the writer: devices from statx's separate major and minor, and
keys decoded by byte offset. A unit test fails if it imports the writer's encoders.

v1 cannot observe a scratch-execution grant, because the child writes it after the check, so
`enforce` refuses every lease that asks for one.

**First root run: 2026-11-08T07:02:35Z**, as section 23 of `probe-daemon.sh`, in Ubuntu 26.04.1
(kernel 6.18.33.2, BPF `d5bb4cad`, daemon from `dfeed53`). All 8 checks held. The run is recorded
under `admission_validator` in
[2026-11-08-ubuntu/daemon-probe.json](../evidence/2026-11-08-ubuntu/daemon-probe.json), outside the
verdict.
- `enforce` admitted a correct lease, which then ran. The frame named all four programs by tag.
- `enforce` refused a scratch-execution lease as indeterminate.
- `enforce` with `--research-fault dev-encoding` refused in both directions: the exec grant, and the
  three default protections. The probe's own protected file sat on an anonymous-device filesystem,
  where the two encodings agree, so the fault was invisible there.
- `enforce` with `--research-fault decoy-exec-map` refused on `mapBinding` (`allowedExec`), plus the
  exec grant the decoy left missing.
- `audit` admitted, recorded and ran the lease.
- Each check took about 0.4 ms, against a few map entries.

**Second root run: 2026-11-09T18:44:27Z**, the same section, against BPF `5e218eb1` and the daemon
from `3e044a8`, which attaches ten programs. All 8 checks held again, and the frame named all ten
programs by tag. It is recorded under `admission_validator` in
[daemon-probe.json](../evidence/daemon-probe.json), outside the verdict.

**Third root run: 2026-11-14T00:51:08Z**, the same section, inside the shipped SPLAT Guest
(`SplatGuestCheck`, Debian 13), against BPF `5e218eb1` and the daemon from `00c1eae`. All 8 checks
held, and the frame named all ten programs by tag
([2026-11-14-splat-guest/daemon-probe.json](../evidence/2026-11-14-splat-guest/daemon-probe.json)).

## Milestone run 2: 2026-11-14, PASS

One `run_unified.sh` in `SplatGuestCheck` on the build of `00c1eae`, as registered in `PROTOCOL.md`:
- The lifecycle probe passed, including all 30 registered expiry repeats.
- 8.4.2 classified all 160 runs as expected. A mutated grant passed B2 in 20 of 20 and was refused by B3 in 20 of 20.
- 8.4.3 classified all 320 runs as expected, plus 60 no-gate baselines.
- No policy entry was left behind, and all three parts ran one binary on one BPF source.

The gate admitted every correct lease under B3, which it does only when both reviewed tags match.
The bundle is kept with the thesis evidence, outside this repository. The run does not close the
audit, because step 3's cases have no driver yet.

Not yet done:
- an audit-mode census of the catalog;
- a foreign-program run against the `splat-canary` object;
- the scratch handshake;
- `run_842.py` and `run_843.py` driving B3N.
