# Week 8 — contracts, orchestration and model evidence

## Lesson A: make invalid actions inexpressible where possible

**Outcome:** follow one typed template through a finite execution plan.

[SingleToolTemplate](../../src/MissionController.Core/Models.cs) describes a tool, parameters, egress, limits and output contract. [GovernedArgumentBinder](../../src/MissionController.Core/GovernedArgumentBinder.cs) turns parameter values into executable arguments. Template validation and safe binding happen before resources are provisioned; a template field by itself does not enforce its own promise.

[ProjectExecutionEngine](../../src/MissionController.Core/ProjectExecutionEngine.cs) executes ordered stages through IMissionExecutionEngine and bounds accumulated hand-off text. ContinueOnFailure controls whether later stages run; it must not relabel a failed stage as successful evidence.

Workflow graphs, crews and the brain add different sequencing rules over these lower seams. Read one caller from each in the [atlas](source-atlas.md). Record maximum steps, cycle handling, cancellation and result propagation rather than assuming all orchestrators share one state machine.

## Lesson B: useful language is not verified evidence

**Outcome:** explain the difference between sensor data, model analysis and accepted findings.

A model receives a prompt and emits proposed interpretation. Untrusted sensor text, repository content or recalled material may contain instructions, so generated plans must still pass the same governed action boundary. A model's confidence is not an OS permission.

The mission engine filters output before downstream analysis and indexing. [TelemetryGrounder](../../src/MissionController.Core/TelemetryGrounder.cs), structured diagnosis and [QualityIslandEngine](../../src/MissionController.Core/QualityIsland/QualityIslandEngine.cs) add acceptance checks. Inspect how unavailable models and rejected quality results reach callers.

Semantic memory uses vector similarity to rank prior material. Cosine similarity compares vector direction; a high score indicates representation similarity, not truth, authorization or current relevance. An accepted old incident can still be stale. Trace indexing in [SqliteSemanticMemoryIndex](../../src/MissionController.Infrastructure.Data/Vector/SqliteSemanticMemoryIndex.cs).

## Lab: failure must not become evidence

~~~powershell
.\coursework\Run-Course.ps1 -Gate Regression
rg -n 'ContinueOnFailure|MaxHandoff|IndexMissionDocumentAsync' src/MissionController.Core
~~~

1. Read [ProjectExecutionEngineTests](../../tests/MissionController.Tests/ProjectExecutionEngineTests.cs) and [FailureIsNotEvidenceTests](../../tests/MissionController.Tests/FailureIsNotEvidenceTests.cs).
2. Use a fake IMissionExecutionEngine to emit success, failure and cancellation across a two-stage plan.
3. Make a truth table for “stage two runs,” “project outcome” and “evidence indexed.”
4. Use a fake model to return plausible text after a failed sensor. Assert it never becomes accepted mission evidence.
5. Inject a synthetic credential marker into stdout and confirm the marker does not reach outward chunks, model input or the evidence index.
6. Find an unsupported workflow node and trace its actual terminal state; do not implement a success placeholder.

Expected: failures remain failures, approved continuations remain explicit, and rejected or secret-bearing data does not silently enter trusted recall.

**Cybersecurity case:** semantic success laundering happens when convincing prose hides failed execution. The regression must inspect behavioral consumers, not just the displayed sentence.

**Repair practice:** add a missing consumer assertion or complete one explicitly unsupported node through a governed interface. Broader autonomous planning is not a prerequisite for making the existing flow truthful.

**Submit:** state truth table and one rejected-evidence test.

**Check yourself:** Does a high similarity score authorize an action? Does continuing after failure erase that failure?

**Answer checkpoint:** neither. Similarity guides retrieval; explicit policy governs actions and preserves stage outcomes.
