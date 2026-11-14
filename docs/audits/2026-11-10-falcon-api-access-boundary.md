# Falcon API access: operator intent and SPLAT-side boundaries

Recorded 2026-11-10 from the operator's instructions and the agreement review.
This is a project decision record, not legal clearance, an executed agreement,
or evidence of a qualified Falcon integration.

## Purpose of the request

The operator is requesting authorized, non-production Falcon API credentials
for integration validation. No upload or delivery of SPLAT source code is
planned as part of that request. Do not recast this effort as a source-code
licensing deal, OEM arrangement, or transfer of SPLAT ownership.

Potential test access includes Event Streams and documented process-identity
fields. Flight Control parent/child access is a separate requested capability
for tenant-isolation and PSFalcon export validation, not an assumed entitlement.

## Keep the verification boundary explicit

- Falcon supplies observations; SPLAT retains host-owned admission and enforcement
  authority. API access does not validate process identity or authorize bare-PID
  cancellation. Preserve tenant, host, process-generation and descendant checks.
- No successful live authentication or API validation was established in this
  session. The attempted requests stopped at missing/invalid credentials.
  Files produced after those failures are not live-validation evidence.
- PSFalcon draft PR [#539](https://github.com/CrowdStrike/psfalcon/pull/539)
  is a separate upstream contribution. Its offline regression results do not
  establish Falcon deployment compatibility, partnership, or endorsement.

## Contract and licensing questions retained for our side

No source upload is planned, but API access and application submission may still
carry contractual obligations. The reviewed Partner Program Agreement states
that application submission constitutes agreement; do not assume acceptance
starts only when credentials are issued. No submission or acceptance is asserted
by this record.

Retain these questions for the applicable access agreement and partner designation:

- Sections 6.2.2 and 7.7: distinguish an API-access request from providing a
  Partner Product for evaluation or granting rights in Feedback. Do not include
  SPLAT or third-party source in feedback without checking the available rights.
- Section 6.2.3: establish how integration-release approval applies to a public
  connector and its source distribution.
- Sections 7.2-7.4 and 12: establish permitted telemetry retention, sanitized
  fixtures, public test results, research publication and confidential information
  handling before publishing Falcon-derived evidence.
- Sections 16-17 and 19.4: retain indemnity, liability and competitor-termination
  questions for contract review; architectural separation does not resolve them.
- Obtain the applicable Program Guide/addenda. Any needed contractual changes
  must follow the agreement's authorized process; informal assurances are not
  an amendment.

These are review questions, not a finding that AGPL software or API-only
integration is prohibited. SPLAT's [LICENSE](../../LICENSE) and
[commercial licensing policy](../../COMMERCIAL.md) remain unchanged. Alternative
permissions require the necessary rights; third-party obligations remain.

Keep credentials and tenant evidence out of public Git history. Record approved
data-handling scope and evidence provenance when access actually becomes available.

## Sources reviewed

- [CrowdStrike Partner Program Agreement](https://www.crowdstrike.com/en-us/legal/partner-program-terms/)
- [Business Partner Standards](https://www.crowdstrike.com/en-us/legal/partner-standards/),
  version 2.0, effective 2025-08-29: confidentiality, licensed software, truthful
  representations and formally authorized agreements.

Recheck the terms actually presented for the requested access; this dated record
does not establish their future text or applicability to every partner type.
