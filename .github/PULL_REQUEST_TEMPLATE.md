<!--
Security problems do not go here. See SECURITY.md.
Code contributions need a signed CLA and a Signed-off-by line on every commit. See CONTRIBUTING.md.
-->

## What this changes

<!-- One concern per pull request. If this sentence needs an "and", consider two PRs. -->

## What you measured

<!--
Claims in this project carry the command that produced them. Paste it and its output.
"Should be faster" / "should be safer" cannot be merged; a benchmark or a probe can.
If this change needs no measurement (a typo, a comment), say so.
-->

```
```

## Checklist

- [ ] Full suite run locally and green — `dotnet test tests/MissionController.Tests/MissionController.Tests.csproj -c Debug --no-build` after a separate build step
- [ ] No new warnings (`TreatWarningsAsErrors` is on everywhere; a warning is a failure)
- [ ] No computed fact hand-edited — test count, template census, generated tutorial and published Field Guide hash are each re-derived by their own command (`AGENTS.md`)
- [ ] Every relative link I added resolves
- [ ] No document now claims more than the code does
- [ ] `Signed-off-by` on every commit (`git commit -s`)
- [ ] CLA signed, or this is a typo fix

## If a test failed and you changed a number to make it pass

Say which direction you established it in, and how. A failing count means the number is wrong in the
code or wrong in the document; editing the document to match a bug is the one change this project
will not take.
