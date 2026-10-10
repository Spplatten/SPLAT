# Contributing to SPLAT

Thanks for looking. Read this before you write code — not for etiquette, but because two of the
rules below will fail your build if you do not know them, and one of them is a legal prerequisite
that cannot be fixed after the fact.

If you are an AI agent working in this repository, read [`AGENTS.md`](AGENTS.md) instead; it is the
same ground in the form an agent needs.

---

## The one rule

**Nothing is written as built unless it names the evidence that it is.** Everything else is marked
planned, decided, or unproven. The test suite enforces this: a document that claims more than the
code does fails the build rather than shipping.

The corollary matters as much. **Do not fix a failing claim by editing the claim.** If a test says a
number is wrong, the number is wrong either in the code or in the document, and which one it is has
to be established before either is touched.

## Before you can contribute code

SPLAT is published under the [AGPL-3.0](LICENSE) and also offered under a separate commercial
licence ([COMMERCIAL.md](COMMERCIAL.md)). That dual offer only works if the project holds the
necessary rights in every line it ships, so:

- **Code and documentation contributions require a signed Contributor Licence Agreement**
  ([CLA.md](CLA.md)). It is short. It does not take your copyright away; it grants Platten
  Industries the right to license your contribution under other terms alongside the AGPL. Without
  it, your patch cannot be merged, however good it is.
- **Every commit needs a `Signed-off-by` line**, certifying the Developer Certificate of Origin —
  that you wrote it, or have the right to submit it. `git commit -s` adds the line.

Email **plattenindustries@gmail.com** to sign the CLA before opening a pull request for code. For
typo fixes, a `Signed-off-by` line alone is enough.

> The CLA is a draft pending review by counsel. If you would rather not sign one, bug reports,
> reproductions, measurements and security findings are all welcome without any agreement at all,
> and are frequently worth more than a patch.

## Security findings do not go through a pull request

See [SECURITY.md](SECURITY.md). Do not open a public issue or a PR for a vulnerability.

## Build and test

The machine-wide `dotnet` on `PATH` may be an older SDK and will fail this .NET 10 tree with
`NETSDK1045`. On Windows, use the user-local SDK:

```
%LOCALAPPDATA%\Microsoft\dotnet\dotnet.exe
```

Build the test project, then test against it. Doing both in one step on a loaded machine produces
`MSB4166` and test-host crashes that look exactly like code defects and are not:

```bash
dotnet build tests/MissionController.Tests/MissionController.Tests.csproj -c Debug -m:1 -p:UseSharedCompilation=false
dotnet test  tests/MissionController.Tests/MissionController.Tests.csproj -c Debug --no-build
```

A full run is roughly 3 minutes idle and 9 under load. `CatalogProducesEvidenceTests` spawns every
template unisolated, so suite contention makes it report "no evidence" — if it fails, run it alone
before believing it.

## Things that will fail your build

- **Warnings.** `src` and `tests` compile with `TreatWarningsAsErrors` and no project is exempt.
  `WarningGateTests` fails if an exemption appears.
- **Hand-edited computed facts.** Several documents state numbers derived from the catalogue or the
  suite — the advertised test count, the template census, the generated tutorial, the published
  Field Guide hash. Each has a command that re-derives it and a test that fails if you type it
  instead. `AGENTS.md` has the table. Re-derive; never retype.
- **A broken relative link in `README.md` or `docs/`.** Every path in those documents is a claim,
  and `DocumentationDriftTests` follows all of them.
- **Reviving a retired claim.** Some wordings are banned outright because they were measured false
  once. The clearest example: no document may go back to promising that a different socket closes
  caller identity. AF_VSOCK identifies a virtual machine; `SO_PEERCRED` in the guest names whatever
  relay carried the bytes in. See `docs/THREAT-MODEL.md`, *Who may drive the lease daemon*.
- **A template that claims an effect it does not have.** Two classes of this have been found and
  fixed, and tests now watch for both: fabricated containment, and an effect reported as performed
  that was not. A template's output may not describe work it did not do.

## Pull requests

- One concern per pull request. A commit that changes a computed number touches nothing else.
- Say what you measured, and how. "Should be faster" is not a claim this project can carry; a
  benchmark with the command that produced it is.
- New enforcement claims need evidence in the form the project already uses: a probe that records
  what it exercised, bound to the hash of the source it exercised, so the proof cannot outlive the
  program it proved.
- Do not weaken, trim or soften a row in
  [`native/splat-agent/SUPPORTED_POLICY.md`](native/splat-agent/SUPPORTED_POLICY.md) without a
  measurement that earns the change. It is attached to commercial agreements as an exhibit.
- Expect the response to be slow and specific. One person reviews these.

## What is most useful right now

- Attacking the export bundle and its two verifiers. It needs no install, no WSL and no
  administrator, and format-and-crypto is where the interesting failures are.
- Independent verification of anything in `native/splat-agent/evidence/` on hardware that is not
  this project's.
- Templates whose output overstates what they did.
- Measurements that contradict a document. Those are the most valuable contribution this project can
  receive, and they will be merged over the document.

## Code of conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). It is short, and it is enforced.
