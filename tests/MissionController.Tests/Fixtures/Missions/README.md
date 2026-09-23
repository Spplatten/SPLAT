# Recorded missions

One file per real mission: the sensor's output as the model saw it, what the model answered, and the
verdict the pipeline reached. `MissionReplayTests` runs every file here again through the real
post-tool pipeline - credential and DLP scrub, prompt, quality island, extractor, grounder, ledger
rows, run facts - with no model and no sandbox, and fails when the verdict moves. A defect in how
those pieces fit is a regression test the moment the run that showed it is recorded here.

## Recording

Three sources, all of them real runs:

| Source | How |
| --- | --- |
| The console or `splat-mcp` | Set `SPLAT_RECORD_MISSIONS_DIR` to a directory before starting either. Every mission that reaches its analysis writes one file there. |
| Runs the console has already done | `SPLAT_EXPORT_MISSION_FIXTURES=1 dotnet test --filter FullyQualifiedName~MissionReplayTests` reads the console's database (or `SPLAT_DB_PATH`) and writes one fixture per accepted mission indexed today; `SPLAT_EXPORT_MISSION_FIXTURES_SINCE=yyyy-MM-dd` reaches further back. Exported fixtures carry the accepted answer as the first attempt and no parameters, because the index holds neither the parameters nor a rejected first attempt. |
| The live canary | `LiveMissionTests` records its mission to `SPLAT_RECORD_MISSIONS_DIR` when set, and replays what it recorded before it passes. |

A recorded file is promoted by copying it here. Read it first: the telemetry is the machine's own,
after the scrub, and it is what a stranger to that machine will read in this tree. The `Note`
field is yours to say what the fixture guards.

## When the test fails

The message names the fixture and each field that moved: the verdict, a finding, a grounding count,
the ledger's rows, or the bytes the model would be handed. If the pipeline is right and the
recording is what changed - a template's prompt was rewritten, the grounder was made stricter -
re-derive the expectations from the current pipeline rather than editing them:

```powershell
$env:SPLAT_BLESS_MISSION_FIXTURES = "1"
dotnet test --filter FullyQualifiedName~MissionReplayTests
Remove-Item Env:\SPLAT_BLESS_MISSION_FIXTURES
```

Then review the diff. Blessing keeps the model's answer and rewrites only what the pipeline makes of
it, plus the template and prompt hashes it was read against.

## What a file holds

`Schema` 1. `Sensor` is the scrubbed stdout and stderr, the exit, and what the live scrub removed by
count and category - the raw output is not kept, for the reason it is not sent anywhere. `Attempts`
is every model call the quality island made, in order, each answer after the island's scrub.
`Expected` is the verdict: accepted or rejected, the status, headline, findings and actions the
extractor produced, the grounder's counts, the SHA-256 of the published analysis, and the ledger's
actions in order. `TemplateSha256` and `SystemPromptSha256` bind the recording to the template and
prompt the model answered; a replay against either changed still runs and says so.
