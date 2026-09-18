# The stranger's path on a second machine — 2026-09-18

P1's last step: the published `splat-mcp.exe` run on a machine that had never seen SPLAT, following
only what the executable itself prints. It was driven over SSH from the build machine; the second
machine's keyboard was used once, to install the SSH key.

**The machine.** Windows 11 Home 10.0.26200; WSL 2.7.14.0 with the stock kernel
`6.18.33.2-microsoft-standard-WSL2`; Ubuntu 26.04.1 LTS with glibc 2.43 and systemd already on.
No Rust toolchain, no git, no checkout of this repository, and no `.wslconfig`.

**The artifact.** `packaging/publish-splat-mcp.ps1`, run in a clean worktree of `7e3a8c8`: 77.5 MB,
SHA-256 `2ea2336f174af9d4ec5a323f129a8e02c217176285e345c6fdbd104ac74ccc60`, carrying `splat-agent`
build ID `ab27214dd0ae43a9a4fa9dfa602986adab84b3f3`, which needs glibc 2.39 or newer. Copied with
`scp`; its hash matched on arrival. `probe-last-hop.ps1` and `src/bpf/lease_lsm.bpf.c` went beside
it, both matching the tree.

**The path**, with each exit status. Every command's output is in [transcript.txt](transcript.txt).

1. `splat-mcp doctor` — **1**. BPF-LSM and the daemon FAIL; NOT enforcing. Its first line also read
   `FAIL workspace` for the default folder, which the server creates on first start. That false alarm
   is fixed in the change that committed this record.
2. `splat-mcp provision` — **1**. WSL and systemd ok. The one `todo`, BPF-LSM, quoted the line it
   would add to `.wslconfig`.
3. `splat-mcp provision --apply` — **1**. Wrote that line and handed over `wsl --shutdown`.
4. `wsl --shutdown`, the operator's step, then `splat-mcp provision --apply` — **0**, in 6 s. It
   installed the daemon built into the executable with no toolchain, enabled the service, had the
   token accepted, and saw a lease reach the kernel.
5. `splat-mcp doctor` — **0**, enforcing.
6. `probe-last-hop.ps1 -Exe splat-mcp.exe` — **0**, PASS on all six checks:
   [last-hop-probe.json](last-hop-probe.json). The permitted command ran as `nobody`; the kernel
   refused `sh`'s undeclared exec of `dpkg` and a `connect()` to 1.1.1.1.
7. `wsl --shutdown` again, then `splat-mcp doctor` — **0**. The unit brought the daemon back on the
   first WSL call after the restart.

**The suite from source**, same machine, from `git archive` of `7e3a8c8`. The cold build had
0 warnings and 0 errors and took 17 s.

- **In the SSH session:** 564 of 568. The session was elevated, but it was a network logon, with no
  INTERACTIVE group. Four sensor-containment tests could not run their probes. Three PowerShell
  probes died at 0xC0000142 inside the AppContainer, where `cmd.exe` starts, and a restricted child
  could not reach WMI. The same four pass in the same machine's desktop session, so the logon type
  is the variable. It is an open item in [the roadmap](../../../../docs/ROADMAP.md).
- **In the desktop session:** run from a one-off scheduled task, removed afterwards. A standard token
  passed 568 of 568; an elevated one passed 567. The failing probe dials a listener, and the container
  drops a denied SYN rather than refusing it, so its unbounded connect waited out TCP's retries. The
  launcher killed it at the 30 s timeout, and the test reported that as "CONTAINMENT BREACH". That
  was a false alarm. The fix bounds the connect and reports a timeout as inconclusive. After it, both
  tokens passed everything except the advertised test count, which the same change then synced.

Before `d5b1f7d`, the operator's elevated run that morning lost seven tests to 0xC0000142. This is
that fix holding on a second machine.
