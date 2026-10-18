# Recorded missions

One file per real mission: the sensor's output as the model saw it, what the model answered, and the
verdict the pipeline reached. `MissionReplayTests` runs every file here again through the real
post-tool pipeline - credential and DLP scrub, prompt, quality island, extractor, grounder, ledger
rows, run facts - with no model and no sandbox, and fails when the verdict moves. A defect in how
those pieces fit is a regression test the moment the run that showed it is recorded here.

## Recording

Three recording routes; promotion must check that a live model answered. The engine can also
record a local simulation, which does not satisfy the corpus gate:

`LiveMissionTests` skips every external request by default, even with a funded key in the vault.
An operator must explicitly authorize the destination and payload before enabling a run:
`SPLAT_ALLOW_ANTHROPIC_TEST_REQUESTS=1` permits the fixed synthetic check to contact
`api.anthropic.com`. Real template tests additionally require
`SPLAT_ALLOW_HOST_TELEMETRY_TO_ANTHROPIC=1`. Their filtered telemetry can still include network
addresses, process paths/command lines, account names, scheduled tasks, services and DNS names.
A funded key, output directory or corpus switch alone does not authorize either transfer.
Set consent flags only for the approved test process; disabled tests are skipped, not passed.
`LiveAnthropicConsentTests` exercises these gates using synthetic environment values without
making requests. The guards recheck consent before vault access and live client construction.

| Source | How |
| --- | --- |
| The console or `splat-mcp` | Set `SPLAT_RECORD_MISSIONS_DIR` to a directory before starting either. Every mission that reaches its analysis writes one file there. |
| Runs the console has already done | `SPLAT_EXPORT_MISSION_FIXTURES=1 dotnet test --filter FullyQualifiedName~MissionReplayTests` reads the console's database (or `SPLAT_DB_PATH`) and writes one fixture per accepted live-model mission indexed today; `SPLAT_EXPORT_MISSION_FIXTURES_SINCE=yyyy-MM-dd` reaches further back. The sealed facts must name a live provider/model and an accepted analysis. Exported fixtures carry the accepted answer as the first attempt and no parameters or prompt hash, because the index did not retain those inputs or a rejected first attempt. |
| The live canary | With both Anthropic consent flags above explicitly enabled, `LiveMissionTests` records its mission to `SPLAT_RECORD_MISSIONS_DIR` when set, and replays what it recorded before it passes. |
| A full live sitting | With both Anthropic consent flags above explicitly enabled, also set `SPLAT_RECORD_CORPUS=1` and an absolute private `SPLAT_RECORD_MISSIONS_DIR`, then run only `LiveMissionTests.TheCorpus_RecordsCurrentTemplatesSequentially_AndReplaysEveryLiveAnswer`. It runs one sensor at a time, uses the real Linux substrate for guest templates, replays every answer, and resumes past current accepted recordings. It spends model credit; it never promotes recordings automatically. For an older installed app, point `SPLAT_DATA_DIR` at the data directory holding its vault. |

A recorded file is promoted by copying it here. Read it first: the telemetry is the machine's own,
after the scrub, and it is what a stranger to that machine will read in this tree. The `Note`
field is yours to say what the fixture guards.

For approval limited to particular templates, set `SPLAT_RECORD_CORPUS_TEMPLATES` to their
comma-separated IDs in the recording process. The corpus runner validates the complete selection
before vault access or sensor collection; empty, duplicate and unknown IDs fail instead of falling
back to the full catalog. Omitting this variable selects the full catalog and requires approval for
that full payload scope. This restriction does not enable the other live tests: filter to the corpus
test alone.

For parameterized sensors, `SPLAT_RECORD_CORPUS_PARAMETERS` accepts a JSON object mapping only
selected template IDs to their declared string parameters, for example
`{"source-consumer-reviews":{"AppId":"570060128"}}`. Validation happens before sensor collection;
it neither expands the selected templates nor grants consent to send their output.

`MissionCorpusTests.EveryShippedTemplate_HasALiveRecordingOfItsCurrentDefinition` evaluates the
shipped catalog and fails for every missing or stale recording. Simulations, rejected diagnoses,
timed-out or empty sensors, and files without a recorded answer do not cover a template. Rejected
runs can still guard regressions in the replay suite. A template change requires a fresh run, even if the old
answer still replays. The 2026-10-05 sitting recorded all 58 definitions then current, including
the four real guest leases. On 2026-10-14, nine changed definitions were renewed: the eight public
web probes now using real Linux leases, plus `sysops-time-sync` under the Windows sandbox. Their
new files retain the genuine mission IDs, template/prompt hashes, sensor output, model attempts
and verdicts. Both sensor and answer were reviewed; these nine required no identity redaction.
The coverage, privacy and offline replay gates pass. Review notes explicitly retain observed model
errors, including an invented partial-month flag and a response-format conflict. Passing these
gates holds the observed pipeline verdicts; it does not establish diagnostic accuracy, guarantee
compliance with every template-specific format, or cover other host conditions.

On 2026-10-18, separate explicit permission covered only the three RARE Linux templates:
`source-consumer-catalog`, `source-consumer-reviews` and `source-consumer-offers`. The scoped live
run recorded one real Anthropic `claude-haiku-4-5` answer for each, then replayed every live verdict.
The three reviewed files retain their genuine mission IDs and template/prompt hashes. One review
title's personal first name and school name were replaced with same-width synthetic text; neither
occurred in the answer. All model answers and verdicts remain unchanged, and no expectations were
blessed. Coverage, privacy, replay and corpus adversarial checks passed 9/9 in
`rare-corpus-validation-20261018.trx`.

Their notes retain observed model errors: the catalog answer miscounts 17 cohorts/157 apps as
16 topics/144 apps; the reviews answer miscounts rating groups and misattributes review IDs; the
offers answer infers billing variants and omits required exact offer citations. These are genuine
accepted pipeline outputs, not validated RARE publication drafts or evidence of resistance to a
new prompt injection. The original recordings remain private; the promoted review IDs are public
and retained for grounding, so title redaction is not a claim of anonymity.

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
