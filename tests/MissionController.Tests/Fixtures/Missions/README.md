# Recorded missions

One file per real mission: the sensor's output as the model saw it, what the model answered, and the
verdict the pipeline reached. `MissionReplayTests` runs every file here again through the real
post-tool pipeline - credential and DLP scrub, prompt, quality island, extractor, grounder, ledger
rows, run facts - with no model and no sandbox, and fails when the verdict moves. A defect in how
those pieces fit is a regression test the moment the run that showed it is recorded here.

## Recording

Three recording routes; promotion must check that a live model answered. The engine can also
record a local simulation, which does not satisfy the corpus gate:

| Source | How |
| --- | --- |
| The console or `splat-mcp` | Set `SPLAT_RECORD_MISSIONS_DIR` to a directory before starting either. Every mission that reaches its analysis writes one file there. |
| Runs the console has already done | `SPLAT_EXPORT_MISSION_FIXTURES=1 dotnet test --filter FullyQualifiedName~MissionReplayTests` reads the console's database (or `SPLAT_DB_PATH`) and writes one fixture per accepted live-model mission indexed today; `SPLAT_EXPORT_MISSION_FIXTURES_SINCE=yyyy-MM-dd` reaches further back. The sealed facts must name a live provider/model and an accepted analysis. Exported fixtures carry the accepted answer as the first attempt and no parameters or prompt hash, because the index did not retain those inputs or a rejected first attempt. |
| The live canary | `LiveMissionTests` records its mission to `SPLAT_RECORD_MISSIONS_DIR` when set, and replays what it recorded before it passes. |

A recorded file is promoted by copying it here. Read it first: the telemetry is the machine's own,
after the scrub, and it is what a stranger to that machine will read in this tree. The `Note`
field is yours to say what the fixture guards.

`MissionCorpusTests.EveryShippedTemplate_HasALiveRecordingOfItsCurrentDefinition` evaluates the
shipped catalog and fails for every missing or stale recording. Simulations, rejected diagnoses,
timed-out or empty sensors, and files without a recorded answer do not cover a template. Rejected
runs can still guard regressions in the replay suite. A template change requires a fresh run, even if the old
answer still replays. This gate is **built, unproven** until the missing live runs are recorded;
neither a green sensor smoke test nor a replay of an old answer establishes diagnosis accuracy.

The catalog requires an explicit `Reasoned(...)` or `Plain(rationale, ...)` choice for every
prompt. The plain rationale is stored beside the template in source. Changing that choice does
not make an old recording evidence that the model obeyed the new prompt.

**Redact the operator's identity before promoting.** The DLP scrub removes secrets; it does not
remove the machine. A persistence, firewall or inventory sensor prints the host name, the local
account names and the machine's SID, and a template whose parameters carry the operator's own
details prints those too - together that is an attack-surface profile of the recording machine,
which is not what any of these fixtures guards. Replace each one with a synthetic value in **both**
the telemetry and the model's answer, because the grounder anchors a finding by locating its claims
in the output: an inconsistent swap turns a grounded finding unsupported, and a replacement that
drops a two-or-more-digit number drops the anchor that number provided. Keep the replacement the
same width as what it replaces so the sensor's column alignment survives, re-derive the expectations
once (`SPLAT_BLESS_MISSION_FIXTURES`), and say in the `Note` what was replaced - a reader comparing
this file to their own machine's output deserves to know the telemetry was altered and why. The six
fixtures redacted on 2026-09-30 carry that sentence and are the pattern to copy.

## When the test fails

The message names the fixture and each field that moved: the verdict, a finding, a grounding count,
the ledger's rows, or the bytes the model would be handed. If the pipeline is right and the
recording is what changed - identities were redacted, or the grounder was made stricter -
re-derive the expectations from the current pipeline rather than editing them:

```powershell
$env:SPLAT_BLESS_MISSION_FIXTURES = "1"
dotnet test --filter FullyQualifiedName~MissionReplayTests
Remove-Item Env:\SPLAT_BLESS_MISSION_FIXTURES
```

Then review the diff. Blessing keeps the model's answer and the original template and prompt
hashes, and rewrites only what the pipeline makes of that answer. It cannot renew stale coverage.
Older exports reconstructed the prompt hash during replay; that value is not evidence of the
historical prompt. New exports leave it empty when it was not recorded.

`MissionCorpusAdversarialTests` removes volume readings, substitutes a missing sensor, and plants
an instruction in an autorun filename using copies of the reviewed recordings. These checks prove
rejection of the old diagnosis without its evidence and confinement of injected text to the sensor
region. They do not prove a live model's response to a new attack; no mutated copy is promoted.

## What a file holds

`Schema` 1. `Sensor` is the scrubbed stdout and stderr, the exit, and what the live scrub removed by
count and category - the raw output is not kept, for the reason it is not sent anywhere. `Attempts`
is every model call the quality island made, in order, each answer after the island's scrub.
`Expected` is the verdict: accepted or rejected, the status, headline, findings and actions the
extractor produced, the grounder's counts, the SHA-256 of the published analysis, and the ledger's
actions in order. `TemplateSha256` and `SystemPromptSha256` bind the recording to the template and
prompt the model answered; a replay against either changed still runs and says so.
