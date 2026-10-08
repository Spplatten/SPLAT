# Handoff — getting SPLAT ready for outside security review

**Written 2026-10-08.** For whichever agent picks this up next. Read [`AGENTS.md`](../AGENTS.md)
first; it holds the build commands and the traps, and this page does not repeat them.

The goal is not "ship the installer." It is to reach the point where a competent outside reviewer
can attack something real, and where whatever they find lands somewhere other than a public
timeline. Four tasks, in order. Each is independently landable; stopping between any two leaves the
tree green.

---

## State verified on 2026-10-08

- **922 of 923 tests pass.** The one failure is task 1 below.
- `main` is `9086eec`, pushed. Working tree is **not** clean — see *Out of scope*.
- Kernel evidence is current: `daemon-probe.json` records PASS over 74 checks against BPF source
  `6fc637d8`, at `2026-10-06T03:47:49Z`.
- `dist\App` is a self-contained publish of commit `00ae926`; nine of nine pages open in its
  self-test.
- Roadmap rows still open: 2.4 (caller identity), 3.7 (external checkpoint), 4.4–4.7 (distribution).

---

## Task 1 — make the suite green again

`DocumentationDriftTests.TheAdvertisedTestCount_MatchesTheSuite` fails: the suite holds 923 cases
and four documents still advertise 913. Ten cases arrived with `ManagedBridgeTests`.

**Do not edit the numbers.** Four documents state the count in four different spellings and
hand-editing is exactly what put them out of step before. Re-derive:

```
SPLAT_SYNC_TEST_COUNT=1 dotnet test --filter TheAdvertisedTestCount_MatchesTheSuite
```

**Done when:** the full suite passes and the count change is committed on its own, touching nothing
else.

---

## Task 2 — a disclosure channel

There is no `SECURITY.md` anywhere in the tree and no disclosure wording in any document. The
repository has been public since its first commit. Today the default destination for a finding is
wherever the finder feels like putting it.

Write `SECURITY.md` at the repository root covering: where to send a report, what response time is
promised, what is in scope, what is explicitly **out** of scope because it is already published as
not enforced, and the preferred disclosure window.

The out-of-scope section is the valuable half, and the material already exists — link it rather than
restating it:

- [`native/splat-agent/SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md), *Not policed*
- [`docs/THREAT-MODEL.md`](THREAT-MODEL.md), *Who may drive the lease daemon* — a Windows process
  running as the operator is root in the guest it owns, by WSL's design. This is published, measured
  and open as roadmap 2.4. A report that rediscovers it is a confirmation, not a finding, and saying
  so in advance is what keeps the signal useful.

**One operator decision is needed and must not be guessed:** the contact address. Ask for it; do not
put a personal address in a public file on your own initiative. GitHub private vulnerability
reporting is the lower-friction alternative if the operator prefers it — it needs enabling in the
repository settings, which is theirs to do.

**Done when:** `SECURITY.md` exists, every link in it resolves, and the suite is still green.

---

## Task 3 — the Windows counterpart to Exhibit A

`SUPPORTED_POLICY.md` enumerates what the Linux substrate does not enforce, with a probe file and a
source hash behind each row. It is the most commercially unusual document in this project and it is
attached to agreements as an exhibit.

**The Windows side has no equivalent in that form**, and the Windows side is the platform the
product actually ships on. The material exists but is scattered:

- [`docs/ARCHITECTURE-windows-substrate.md`](ARCHITECTURE-windows-substrate.md) §*What each
  primitive does not do* and §*What this substrate does not do* — four limits, no per-row evidence,
  not bound by any test.
- `docs/ROADMAP.md`, open questions: job-object **UI limits are still open**, so a tool runs on the
  operator's desktop with no UI restrictions and can read the clipboard or message the operator's
  other windows. That limit appears in neither section above.
- The census: 8 of 58 templates get network denial, 46 keep a connection whose destination Windows
  does not pin. Stated in the roadmap and the Field Guide, absent from the architecture document.

Consolidate these into one table in the same shape as the Linux one — gap, consequence, evidence —
in `ARCHITECTURE-windows-substrate.md`, cross-referenced from `SUPPORTED_POLICY.md` so a reader of
either finds both. Bind it with a test in `DocumentationDriftTests` the way the census is bound: at
minimum, that the section exists and names the UI-limits gap while the roadmap still lists it open.

**Why this is worth a day:** a reviewer's strongest move is to find the gap between what a project
claims and what it enforces. Every Linux gap here is pre-published, which costs them the finding.
The Windows asymmetry is the one opening left.

**Done when:** one table, per-row evidence, a test that fails if the UI-limits row disappears while
the roadmap row is still open.

---

## Task 4 — close roadmap 3.7 against a published checkpoint

Row 3.7's done-when, verbatim:

> A bundle and a published checkpoint, with no access to the host, show that every row the bundle
> carries was in the ledger at the checkpoint's date.

Everything needed is built. `LedgerCheckpointBuilder` issues the signed statement over the whole
chain; an export carries it as `checkpoint.json` with one inclusion proof per entry in
`chain_inclusion.json`; `ChainInclusionCheck` is what a recipient runs on the zip alone; the bundle
ships `verify_proofs.py` and `verify_proofs.ps1`, which check with their standard libraries and
nothing else. What has never happened is a **stranger** running it.

The steps:

1. Export a run record bundle (`export_run_record`), with a run-record signing key configured so the
   bundle is signed rather than honestly-unsigned.
2. Publish the checkpoint statement somewhere with a date attached that is not under the host's
   control — a repository commit is the cheapest honest option, since its timestamp is witnessed.
3. Verify the bundle against that published checkpoint **on a machine with no SPLAT install, no
   WSL, and no network access to the host**, using only the two scripts in the zip.
4. Record the run the way every other proof here is recorded: what was checked, where, against which
   checkpoint, and what the verifier printed.
5. Attempt the negative: edit one byte inside a signed region and confirm the verifier refuses.
   A proof that passes everything proves nothing.

**This is also the right first thing to put in front of outside reviewers.** It needs no install, no
WSL, no administrator, and the attack surface is format-and-crypto, which is what that audience is
best at. If it holds, a roadmap row closes and the credibility is earned from someone who was not
trying to sell it. If it breaks, that is much better learned now.

**Done when:** the roadmap row moves, with the record's path in its evidence column.

---

## Out of scope — do not touch

**The working tree is not clean, and the uncommitted work is not yours.** A second agent has an
in-flight community-installer track and a partial implementation of roadmap 2.4's option 1
(`ManagedBridgeHost`, `ManagedGuest`, the named-pipe client, `ManagedBridgeTests`,
`packaging/*community*`, `packaging/probe-*`, `docs/COMMUNITY-TESTING.md`). It builds clean and its
tests pass.

- Do not commit it, edit it, or refactor around it.
- Stage by explicit path on every commit. Never `git add -A`.
- If the tree genuinely has to be cleared, commit it verbatim on a `peer/` branch, unmodified, and
  say that is what you did.

**Do not distribute the community installer.** Its own document
([`docs/COMMUNITY-TESTING.md`](COMMUNITY-TESTING.md)) says it is unsigned and has not passed its
acceptance matrix, and that is the correct call. Packaging is not what is missing; the signature and
the matrix are.

**Do not close roadmap 2.4.** The measurement recorded on 2026-10-06 is partial: registration
isolation held, but the operator account was an unelevated administrator, port 50051 had no valid
owner-side control, and token exclusion and service authorization are unmeasured. See
[`HANDOFF-caller-identity.md`](HANDOFF-caller-identity.md), which is the live document for that row.
