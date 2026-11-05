# SPLAT: licensing, sales claims and SOC readiness review

Reviewed 2026-10-28 against the shared working tree on `codex/rare-a2a-authority`, HEAD `bb93d79`,
including uncommitted product work and the integrated research patch. This is a source/evidence
review, not legal clearance, a penetration test or a CPA attestation. No customer package was rebuilt
or cleared for redistribution by this review. Legal conclusions about a particular distribution,
linking arrangement or contract need counsel; SOC scope and acceptance need the examining CPA.

## Decision

SPLAT has a defensible, bounded product proposition: local execution of declared workloads under
OS-enforced restrictions, with records and verification tools. It is a candidate for controlled
customer pilots on a specifically proved release. The present working tree is not that proved
release. Do not sell universal containment, administrator-proof history, or SOC 2 compliance.

AGPL plus commercial licensing can be a workable business model, subject to ownership and dependency
rights. The current legal wording and release-source workflow need reconciliation before commercial
distribution. An AGPL license does not itself conflict with SOC 2, and purchasing a commercial
license does not establish security or compliance.

## Licensing findings

| Priority | Finding and local evidence | Required resolution |
| --- | --- | --- |
| Before distribution | `README.md` License and `COMMERCIAL.md` emphasize modified versions as the source-sharing trigger. AGPL section 6 also applies to conveying covered object code without modification. `packaging/DISTRIBUTION-NOTICE.txt` already states this more accurately. | Align the public summaries and in-app terms around sections 4–6 and 13, with distinct distribution and network cases. |
| Before commercial contract | `SplatLegalTerms.cs` presents acceptance of an adapted proprietary-style EULA, with restrictions on reverse engineering, transfer, lending and other conduct. It has AGPL-precedence carve-outs, but the ShortNotice broadly requires acceptance. | Make Community's AGPL grant unambiguous in the actual installation/UI flow. Separate commercial terms and service terms; do not impose conflicting additional restrictions on AGPL recipients. Counsel should review the carve-outs, conduct provisions, indemnity, termination and liability clauses together. This review does not establish that an enforceable conflicting restriction has already been imposed. |
| Before distribution | Community packaging includes a source snapshot and inventories, but also permits preserved binaries and an external source archive. `customDllSourceCompleteness` can be `PROJECT_SOURCES_LOCATED; PRESERVED_BINARIES_NOT_REBUILT`. | Require evidence that the offered source corresponds to each shipped covered binary, including build/install scripts and applicable non-system dependencies. Locating a project is insufficient to establish correspondence. A generic GitHub link is not enough for an unidentified or modified binary. |
| Before guest redistribution | `splat-guest-package.ps1` can record `NOT_INCLUDED` or `FILES_INCLUDED_COMPLETENESS_UNVERIFIED`. The guest builder retains copyright files and exact Debian source-version locations, which is useful but not clearance. | Select and fulfill a source-delivery/offer mechanism permitted by each component's license. Verify exact source availability and required notices. Block release when the chosen mechanism is incomplete. Do not treat an inventory URL as a universal substitute for license obligations. |
| Before proprietary licensing | `CLA.md` and `CONTRIBUTING.md` establish a contributor-rights process, but the CLA is explicitly a draft pending counsel review. A repository policy does not prove executed rights grants for every contribution. | Maintain first-party ownership/assignment and executed contributor-license records. Identify the actual contracting/licensing entity consistently. Do not assume all third-party components can be relicensed by Platten Industries. |
| Before distribution | Dependency collection inventories Windows DLL provenance and copies notices; its own scope excludes legal clearance. Native static linking and the bundled guest create separate obligations. | Produce an artifact-level inventory covering NuGet, Cargo/native libraries, runtime assets, guest packages and embedded tools. Resolve license compatibility, notices, source and any applicable relinking requirements per component. A commercial SPLAT license does not erase these obligations. |

AGPL is not a prohibition on charging money or using software in a business. Nor does it
automatically license every independent workload or every program communicating with SPLAT. The
scope of a combined/derived work is a separate question. For section 13, use the actual condition:
modified network-interactive versions must offer their Corresponding Source to the users interacting
remotely. Avoid both “all company source must become public” and an unqualified internal-use exemption.
Ordinary execution alone is not a source-disclosure trigger. [S1–S3]

Suggested licensing summary for counsel to finalize:

> The Community edition is licensed under AGPL-3.0-only. Commercial use is permitted. Redistribution
> of covered binaries carries the license's corresponding-source requirements; modified versions
> supporting remote network interaction must offer corresponding source to their remote users.
> Separate commercial terms are available for rights Platten Industries is authorized to grant.
> Third-party components retain their own licenses. Independent workload outputs are not claimed
> by SPLAT merely because SPLAT executed them.

The wording above is a proposed replacement, not an amendment to the current license or contracts.

## Sales pitch against implementation

| Claim | Assessment | Defensible scope |
| --- | --- | --- |
| Per-task execution restrictions enforced below the model | Supported in implementation and historical release-specific probes | Name the tested build, host/guest configuration and declared enforcement dimensions. Retest the merged build. |
| Whatever the agent becomes, it cannot act outside its lease | Too broad: this sentence occurs in the README | `SUPPORTED_POLICY.md` limits exec identity, file coverage, local IPC and inherited-descriptor claims; `EXECUTION_POLICY.md` adds opt-in controls with separate evidence. No universal action boundary is established. |
| Full protection against a compromised operator or administrator | Not supported | `docs/THREAT-MODEL.md` explains that the Windows account owning WSL can act as guest root. Do not propose a transport change as a solution to that authority boundary. |
| Tamper-evident audit history | Conditional | Unkeyed chains can be recomputed by a file writer. HMAC helps against parties without the key; a local administrator may obtain local keys. Signed checkpoints are useful, but local signatures alone do not establish completeness or prevent rollback/deletion by the host. |
| Continuous or lossless monitoring | Not established | SIEM formatting and transport exist. The reviewed forwarding path has no durable outbox, acknowledgment cursor or persistent retry workflow. Copilot forwarding catches failures and returns false. Source review does not demonstrate delivery under outage/restart. |
| Local execution | Defensible with data-flow qualification | Containment is local. Configured AI gateways and SIEM destinations can receive data; local execution is not a promise that every payload stays on the machine. |
| SOC 2 aligned / ready / compliant | Only a narrowly labeled control-support statement is supportable | The README explicitly disclaims an auditor assessment, but the small mapping table does not establish control effectiveness or organization-level readiness. |

Suggested sales copy, pending proof of the offered release:

> SPLAT helps teams run declared AI-agent tasks locally under task-specific execution policies.
> On supported and verified Windows/WSL configurations, it restricts approved executable identities,
> selected file access, network destinations and resource use, and produces execution records for
> independent verification. It complements existing identity, endpoint-security and monitoring
> systems. Coverage and limitations are documented for each release.

For the current merged working tree, replace any release assurance with “under validation.” Avoid
unsupported market-wide statements that every alternative filters only in userspace. No comparative
benchmark or competitor assessment was completed by this review.

## SOC 2 and security-operations needs

These are different questions. A customer can use SPLAT as one part of its control environment.
A SOC 2 report examines a defined service organization's system and controls, including people,
procedures and operating evidence. A Type 2 examination includes operation over a specified period;
a code test suite is not a substitute. A downloadable local tool does not automatically need its
own SOC 2 report before it can be used by a SOC 2-audited customer. Scope the actual services,
support access, customer data and buyer requirements with a CPA. [S4, S5]

The README maps egress allow-listing directly to CC6.8. That is an imprecise crosswalk: CC6.8 concerns
unauthorized/malicious software; boundary and information-transmission restrictions more naturally
support CC6.6/CC6.7, while executable restrictions may contribute to CC6.8. CC7.2 requires monitoring
and analysis of anomalies, not just recording events. The applicable control design must be agreed
and evidenced; changing the table alone achieves no control. [S6]

| Area | What exists | What is missing or not demonstrated | Acceptance evidence to obtain |
| --- | --- | --- | --- |
| Access and authority | Authenticated native protocol, principal attribution, policy ceilings, workload privilege reduction | Protection against the WSL-owning account; reviewed organizational access lifecycle; deployment-specific separation of duties | Document trusted administrators, broker/host boundary and scoped identities; test enrollment, revocation and denied execution. Use an appropriately managed enforcement host where an adversary cannot control guest root. |
| Audit integrity | Chained ledger, optional HMAC, signed outcomes, Merkle checkpoints and standalone verifiers | Independent off-host anchoring, retention protection and completeness under privileged deletion | Have a separately controlled collector retain authenticated checkpoints and sequence cursors; demonstrate edit, deletion, truncation, replay and key-rotation detection under the stated trust model. |
| Monitoring and response | Syslog/CEF/Sentinel forwarding and kernel denial/drop counters | Durable delivery/recovery, lag alerts, operator triage and incident-response evidence | Simulate receiver outage and process restart; recover queued events with deduplication; alert on backlog/loss; retain incident drill records. |
| Release/change control | Source inventories, hashes, packaging guards and proof checks | A freshly proved merged release, independently reviewed changes, full artifact dependency/source closure | Match source, binary, BPF tags, installed package and probe evidence; test clean-machine install, upgrade and rollback; retain approvals and vulnerability triage. |
| Confidentiality | Local-first storage, configured egress, secret-handling controls and retention code | A complete deployment data-flow/retention inventory and evidence for configured external destinations | Use synthetic secrets to test logs, exports and model paths; verify permissions, retention/deletion, backup handling and vendor access. |
| Availability and recovery | Fail-closed behavior, pinned hooks, restart/recovery code and historical lifecycle tests | Service-specific recovery objectives, restore drills and operating support coverage | Establish scope-appropriate RTO/RPO, restore retained evidence, and prove fail-closed recovery on the actual deployment. These are risk-driven design choices, not a claim that every deployment requires the same architecture. |
| Governance | Security contact, published disclosure process, draft CLA and documented limitations | Evidence of risk assessment, personnel/access reviews, supplier oversight, change approvals and sustained control operation was not found in reviewed materials | Assign owners, keep operating records, and commission an independent readiness assessment for the chosen scope. Absence from this repository is not proof the organization has none elsewhere. |

Concrete SIEM issue: `SiemForwarder.TestConnectionAsync` returns success for a TLS-configured target
after TCP connect without a TLS handshake. UDP send success similarly does not prove receipt.
Make the UI distinguish reachability, TLS/authentication and acknowledged ingestion. This is an
engineering finding, not a claim that SOC 2 mandates a particular transport.

The security policy promises acknowledgement within 7 days and initial assessment within 14 days.
That is an explicit commitment, not 24/7 incident response. Enterprise response targets must be
negotiated, staffed and tested rather than implied by “enterprise” branding.

## Prioritized work

1. **Before offering this merged release:** complete native build/re-proof and the Windows last hop;
   review and record its program tags; bind the resulting evidence to the exact customer artifact.
   Do not recycle historical hashes or weaken proof checks.
2. **Before distribution or a proprietary agreement:** reconcile AGPL summaries and UI terms with
   counsel; close rights provenance; enforce source/notice completeness for every shipped component
   and every packaging route, including the guest. Keep unresolved package states release-blocking.
3. **For SOC buyers, the next code investment:** a durable audit outbox with persisted cursor,
   bounded storage, retries, deduplication, visible delivery lag/loss and meaningful TLS/ingestion
   health checks. Pair it with separately controlled receipt/checkpoint storage. Validate failures,
   not just successful sends.
4. **For the thesis's systems contribution:** continue committed policy-generation work to address
   the demonstrated validation-to-use race, with stable resource identity and explicit adversary
   assumptions. The current epoch field is not such a mechanism.
5. **For procurement:** package a deployment/data-flow description, threat model, control-support
   matrix, SBOM/license/source manifest, current independent security-test results, incident process,
   support commitments and recovery evidence. Ask a CPA to scope readiness before selling a SOC
   outcome. These are deliverables to establish, not features this review claims are finished.

## Verification and integration status

The requested patch is integrated into the real working tree, preserving the 16-byte deadline/epoch
ABI and peer receipt behavior. The probe and gate now decode that ABI explicitly. Research expiry
denials are distinguished in the BPF event hook flags. The new BPF source SHA-256 is
`d5bb4cad4c3397f1e12c0ca7952b10c1b2a2694b777ec84d30266d21b2b0af80`.

Evidence is recorded in `private/thesis/integration-2026-10-28/verification.json` and adjacent logs:
33 Python tests and 5 standalone Rust arithmetic tests pass; Rust source parsing and the native
diff whitespace check pass. The .NET test project builds with zero warnings and errors. The targeted
.NET test run aborted when the test host did not connect within 90 seconds: no test-pass claim is
made for that run. Full Linux compilation and native probes remain blocked by WSL access denial;
Git Bash also failed before parsing because MSYS object creation was denied.

Expected program tags are intentionally unset in the integrated profile pending native review;
the experimental gate refuses in that state. This does not affect ordinary admission without the
gate flag. Historical evidence remains historical; the merged build's proof is stale. Changes remain
uncommitted in the shared working tree; nothing was pushed, and unrelated peer work was not staged.
The original isolated candidate and its 13-file patch remain historical deliverables, not the patch
to apply again on top of this integrated tree.

## Primary references

- **S1:** GNU, [AGPL v3](https://www.gnu.org/licenses/agpl-3.0.html), especially sections 0–2, 4–7,
  10 and 13. The complete license is also in this repository's `LICENSE`.
- **S2:** GNU, [machine-readable AGPL text](https://www.gnu.org/licenses/agpl-3.0.dbk), including
  the binary-distribution and corresponding-source provisions.
- **S3:** GNU, [license FAQ](https://www.gnu.org/licenses/gpl-faq.en.html), including
  AGPLv3CorrespondingSource, UnreleasedModsAGPL and copyright-holder exceptions.
- **S4:** AICPA, [SOC services and criteria](https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services).
- **S5:** AICPA, [SOC 2 guide introduction, publisher-hosted excerpt](https://catalogimages.wiley.com/images/db/pdf/9781945498602.excerpt.pdf),
  particularly paragraphs 1.04–1.08 on scope, report types and user responsibilities.
- **S6:** AICPA, [Trust Services Criteria](https://us.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria-redlined.pdf),
  CC6.6–CC6.8 and CC7.2. The direct legacy URL redirected during this review; the indexed AICPA text
  supplied the CC6.8/CC7.2 passages. Confirm the current criteria copy with the CPA before finalizing a crosswalk.
- **S7:** AICPA, [October 28, 2026 proposed criteria update](https://www.aicpa-cima.com/news/article/aicpa-proposes-update-of-soc-2-r-trust-services-criteria-to-enhance-the-relevance-usability-and-value-of-cpas-reports).
  This is an exposure draft, including proposed AI considerations, not an already-effective set of
  new requirements. It should not be represented as a standard SPLAT has already satisfied.
