# Week 10 — repair one defect and defend the result

## Lesson A: make the regression fail for the right reason

**Outcome:** produce a narrow patch with a causal proof.

A useful regression encodes an observable promise, not the lines used to implement it. “The resolver threw and no destination was granted” survives refactoring; “this private method was called twice” may not. Include a permitted control case so denying everything cannot pass as the fix.

Pick one current ticket. Reproduce it with a local deterministic fixture, record the original result, implement the smallest responsible change, and rerun the same case. Add boundary and failure cases that matter to that guarantee.

For a cross-language repair, trace the field through model, serializer, parser, authorization, kernel/OS use, reply and outward consumer. A C# test cannot prove an untested Rust hook. A documentation promise needs a matching evidence level.

## Lesson B: built, packaged, installed and enforced are different gates

**Outcome:** state what an artifact has actually demonstrated.

Project references determine target compatibility. Package resolution introduces managed and native dependencies. A successful build checks compilation; it does not prove package signing, installation identity, daemon provisioning or kernel attachment.

Read [build-msix.ps1](../../packaging/build-msix.ps1) and [install-enterprise.ps1](../../packaging/install-enterprise.ps1) as source. Identify where certificate identity, privilege and installation state enter. The course does not run enterprise installation or alter host policy.

Use an artifact/source hash to tie a result to what ran. A hash pins bytes; it does not prove the probe covered every policy dimension. The retained canary and daemon evidence must be read with their stated gaps.

## Capstone lab

1. Select R1, R2, R3, R4 or R5. R6 requires the advanced Linux environment.
2. State a concrete trigger and expected outcome in one sentence.
3. Record one failing pre-fix case, one valid control, and a boundary case.
4. Patch only the owning component and necessary callers/tests.
5. Run the focused regression, the course fixture and relevant existing tests.
6. Inspect the diff for unrelated changes and misleading success/measurement behavior.
7. Prepare an evidence note with revision, command, results and remaining integration gates.
8. Demonstrate the result in five minutes, tracing it down to the lowest layer you actually exercised.

~~~powershell
.\coursework\Run-Course.ps1 -Gate Lab
.\coursework\Run-Course.ps1 -Gate Regression
.\coursework\Run-Course.ps1 -Gate Links
git diff --check -- coursework docs/course docs/README.md
~~~

For a production capstone, extend the final diff check to your exact changed source and test paths. Run the specific tests you added: the course's regression filter is deliberately a subset, not an automatic full-suite claim.

## Acceptance rubric

| Gate | What the reviewer must see |
| --- | --- |
| Reproduction | Fixture fails on the unpatched behavior for the stated reason. |
| Correctness | The original case and boundary cases pass after the patch. |
| Compatibility | A permitted action still succeeds; existing relevant callers remain valid. |
| Security | Rejected input cannot reach the forbidden effect; secrets do not enter evidence. |
| Failure behavior | Cancellation, missing prerequisites and exceptions remain truthful. |
| Scope | Patch targets the owning seam and avoids unrelated rewrites. |
| Evidence | Reports exactly which host/kernel/transport paths were exercised. |

**Future architecture exercise:** order the next three repairs by dependency. An explicit supported-policy contract should precede a user-facing “fully confined” option. Bounded transport and truthful outcomes should precede higher-volume orchestration. Required audit-key behavior should precede a keyed-evidence promise.

**Submit:** patch, tests, five-minute walkthrough and a short evidence note. Include the next smallest step, not an open-ended platform rewrite.

**Check yourself:** Can a build pass close a live-enforcement gate? What does an unrun prerequisite mean?

**Answer checkpoint:** no; the prerequisite remains unverified. A passing capstone can honestly establish a limited boundary without claiming the whole product is release-ready.
