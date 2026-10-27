# Live-state validation experiment 8.4.2

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
| `run_843.py`, `workload_p.c` | 8.4.3: a missing protection (P opens a file the approval protects), a wrong identity and a decoy map binding (daemon `--research-fault`, gate-only), a write that ignores the daemon's lock, and a no-gate cost baseline. Variant `B2W` reads back through the writer's own map ids. |
| `run_unified.sh` | The probe (optionally `N` expiry repeats), 8.4.2 and 8.4.3 on one staged binary. |

Conditions: the approval always names A only. The writer's intent is `[A]` (correct), `[A, X]`
(mutated before serialization) or `[A]` with X's key inserted after the writer recorded its bytes
(corrupted). Launch is observed by an ftrace instance on `sched_process_fork`/`sched_process_exec`,
which the kernel emits outside the BPF-LSM program and only for an exec that succeeded.

What B3 shares with the writer, and therefore cannot be independent of: the kernel's `MKDEV`
encoding (`major << 20 | minor`), the assumption that the jail's bind mounts preserve inode identity,
the approval file's integrity (root-owned, not signed), and the profile's reading of the BPF source.
The profile is written from the source, not derived from the loaded bytecode. The bundle records the
kernel's program tag, which was the same across separate loads of this build (`debffec9428e2ccf`);
the translated-dump hashes it also keeps change per load, because the dump embeds map ids.

A gate run is indeterminate, and refuses, when any program other than the daemon's own decides
`bprm_check_security`. WSL distros share one kernel, so another distro's orphaned SPLAT pins are such
a program.
