# Working rules for agents in this repository

SPLAT is a Windows WinUI 3 / .NET 10 agent-execution substrate with a Rust BPF-LSM daemon in a WSL2
guest. Read `README.md` for what it is. This file is what an agent needs that it cannot guess, and
most of it exists because somebody already lost a day to it.

---

## The one rule

**Nothing is written as built unless it names the evidence that it is.** Everything else is marked
planned, decided, or unproven. This is not a style preference — the test suite enforces it, and a
document that claims more than the code does will fail the build rather than ship.

The corollary matters as much: **do not fix a failing claim by editing the claim.** If a test says a
number is wrong, the number is wrong in the code or in the document, and which one it is has to be
established before either is touched.

---

## Build and test

The machine-wide `dotnet` on PATH is **SDK 9** and fails this net10 tree with `NETSDK1045`. Always:

```
%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe
```

Build the test project, then run against it. Building and testing in one step on a loaded machine
produces `MSB4166` and test-host crashes that look like code defects and are memory:

```bash
dotnet build tests/MissionController.Tests/MissionController.Tests.csproj -c Debug -m:1 -p:UseSharedCompilation=false
dotnet test  tests/MissionController.Tests/MissionController.Tests.csproj -c Debug --no-build
```

A full run is roughly 3 minutes idle, 9 under load. `CatalogProducesEvidenceTests` spawns every
template unisolated, so suite contention makes it report "no evidence" — if it fails, run it alone
before believing it.

## Facts that are bound to the code — never hand-edit them

Four documents state numbers that are computed from the catalog or the suite. Each has a command
that re-derives it, and each has a test that fails if you type it instead:

| Fact | Re-derive with |
| :--- | :--- |
| Advertised test count (4 documents, 4 spellings) | `SPLAT_SYNC_TEST_COUNT=1 dotnet test --filter TheAdvertisedTestCount_MatchesTheSuite` |
| `docs/TUTORIAL.md` (generated from the Field Guide HTML) | `SPLAT_SYNC_TUTORIAL=1 dotnet test --filter FieldGuideTutorial` |
| Template census (ROADMAP + Field Guide) | Fix the catalog or the prose; `CapabilityManifestTests` counts it |
| Published Field Guide artifact hash | `packaging/build-field-guide-artifact.ps1`, publish, then `-RecordPublished` |

Other switches the suite honours: `SPLAT_EXPORT_MISSION_FIXTURES`, `SPLAT_BLESS_MISSION_FIXTURES`,
`SPLAT_DB_PATH`, `SPLAT_LEDGER_KEY_FILE`, `SPLAT_RUN_RECORD_KEY_FILE`.

## This is a shared working tree

A second agent works in this same checkout, and its work is frequently uncommitted.

- **Never `git add -A` or `git add .`** Stage by explicit path, always.
- **Never commit another agent's uncommitted files.** If the tree must be cleared, commit their work
  verbatim on a `peer/` branch and say so — do not edit it first, and do not publish it as reviewed.
- **No worktrees.** The operator decided this. Branch and commit in place.
- Before any push, run `git log origin/main..HEAD` **as its own command**, not chained to the push.
  A verification step downstream of the action it gates is decorative.

## Traps

- **The repository stores LF and the worktree is CRLF.** `git hash-object` will report every file as
  modified; use `git diff`, which applies git's own normalisation. Multi-line anchors in scripted
  edits need the line ending handled explicitly.
- **Shell heredocs mangle escapes.** The Bash tool halves doubled backslashes inside quoted
  heredocs, truncates past roughly 8 KB, and ignores `set -e`. Write files with the editor tools, or
  splice by checked line ranges.
- **PowerShell 5.1 here-strings need `@'` at end of line and `'@` at column 0.** For commit messages
  use `git commit -F <file>` rather than fighting the quoting.
- `packaging/build-client-dist.ps1` runs the whole suite before it publishes. A red tree produces no
  package, by design. Do not pass `-SkipTests` to get an artifact.

## What "proven" means here

Kernel claims are backed by `native/splat-agent/evidence/daemon-probe.json`, which carries the
SHA-256 of the BPF source it exercised. `DocumentationDriftTests` fails the build if the README
claims enforcement while that hash does not match what ships, so a proof cannot outlive the program
it proved. Re-run with `packaging/reprove-substrate.ps1`; `packaging/reprove-if-stale.ps1` fires it
when the BPF source or the daemon's own source has moved ahead of the evidence, and refuses to prove
over uncommitted work under `native/splat-agent` or `src`.

`native/splat-agent/SUPPORTED_POLICY.md` enumerates what SPLAT does **not** enforce. It is attached
to commercial agreements as an exhibit. Do not weaken, trim or soften a row in it without a
measurement that earns the change.

## Things that are retired and must not be proposed again

`DocumentationDriftTests` fails the build if any document goes back to promising that a different
socket closes caller identity. AF_VSOCK identifies a virtual machine; `SO_PEERCRED` in the guest
names whatever relay carried the bytes in. See `docs/THREAT-MODEL.md`, *Who may drive the lease
daemon*.
