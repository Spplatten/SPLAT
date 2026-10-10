# Reporting a security problem in SPLAT

**Written 2026-10-09.** SPLAT is a containment substrate, so a defect in it is worth more to you
reported than published. This page says where to send one, what you get back, and — the part worth
reading first — which weaknesses are already known and documented, so you do not spend a weekend
rediscovering something that is on the roadmap.

## Where to send it

**info@plattenindustries.com**, with `SECURITY` in the subject.

Include the version or commit, the platform (Windows build, WSL version, kernel version), what you
expected the lease to prevent, and what happened instead. A reproduction beats a description. If you
have evidence files, say so and wait before sending them; do not attach anything you have not
cleared of your own secrets.

Please do **not** open a public issue for a security problem, and do not post it in a chat room where
the package was distributed. Those are the right places for a defect that is merely a defect.

## What you get back

One person maintains this project. The commitments are therefore modest and real:

| | |
| :--- | :--- |
| Acknowledgement | within 7 days |
| First assessment — is it a real finding, is it already known, is it in scope | within 14 days |
| Fix or a written reason there will not be one | within 90 days, or a date agreed with you |
| Credit | your name or handle in the commit and the record, unless you ask otherwise |

There is no bug bounty. Nothing on this page asks you to stay quiet: publish on your own schedule.
90 days before disclosure is the convention this project will try to meet, and if a finding is being
exploited or the fix is taking longer than that, saying so publicly is reasonable and expected.

## In scope

The containment claims, and the evidence behind them:

- A lease failing to hold — an exec, a file access or a network connection the lease declared
  forbidden that happens anyway.
- The host↔guest protocol: replay, forged frames, sequence manipulation, a listener that steals the
  port, anything that gets a workload launched or output returned without authorisation.
- The ledger and the run record: a chain that accepts an edited entry, a signature that verifies
  something it should not, an inclusion proof that passes for a row that was never there.
- The verifiers shipped in an export bundle (`verify_proofs.py`, `verify_proofs.ps1`), which a
  recipient runs on untrusted input by design.
- Secrets reaching somewhere they were promised not to: a model's context, the ledger, a run record,
  a log, or a command line.
- The installer and packaging scripts: anything that writes outside its declared paths, elevates
  without saying so, or trusts a file it did not verify.
- Templates that claim an effect they do not have, or claim containment they did not get. Two whole
  classes of this have been found and fixed already; a third would be welcome.

## Already known, already published — a confirmation, not a finding

These are measured, written down, and open. A report that rediscovers one is genuinely useful as
confirmation, and will be answered as such, but it is not news:

- **A Windows process running as the operator is root in the WSL guest it owns.** `wsl -u root` is
  by design, so the guest is not a boundary against the user who owns it. Measured, partial verdict
  recorded, and open as roadmap row 2.4. See
  [`docs/THREAT-MODEL.md`, *Who may drive the lease daemon*](docs/THREAT-MODEL.md#who-may-drive-the-lease-daemon).
- **Everything the lease does not police**, enumerated per row with the evidence behind each:
  [`native/splat-agent/SUPPORTED_POLICY.md`, *Not policed, and not claimed to be*](native/splat-agent/SUPPORTED_POLICY.md#not-policed-and-not-claimed-to-be).
- **What the Windows substrate does not do**, including that job-object UI limits are still open, so
  a tool runs on the operator's desktop without UI restrictions:
  [`docs/ARCHITECTURE-windows-substrate.md`](docs/ARCHITECTURE-windows-substrate.md#what-this-substrate-does-not-do).
- **A signed guest outcome proves the guest said it, not that it is true.** A root guest can sign a
  lie. Stated in `SUPPORTED_POLICY.md` and not claimed otherwise anywhere.
- **The community test candidate is unsigned.** A checksum is not publisher authentication, and that
  package has not passed its own acceptance matrix. See
  [`docs/COMMUNITY-TESTING.md`](docs/COMMUNITY-TESTING.md).

## Out of scope

- Anything requiring local administrator, or physical access, on the machine SPLAT runs on.
  Administrators are outside the boundary and the documents say so.
- Third-party dependencies, which keep their own licences and their own advisories — report those
  upstream, though telling us which version is affected is appreciated.
- Denial of service against your own machine by configuring a lease badly.
- Missing hardening that is already listed as open in [`docs/ROADMAP.md`](docs/ROADMAP.md).
- Reports produced by running a scanner and pasting its output, with no analysis of whether the
  finding applies.

## Testing it safely

Use a disposable machine. Do not import an export of someone's working WSL distro: it can carry
their tokens, shell history and keys. Keep real tokens and private signing material out of anything
you send. Test only systems you own or are authorised to test — this is a tool for running agents
against live platforms, and it will do what you tell it to.
