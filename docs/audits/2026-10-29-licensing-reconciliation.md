# Licensing reconciliation — 2026-10-29

Status: implemented in the shared working tree, not committed or published. This follow-up addresses the conflicting Community terms identified in the 2026-10-28 license/sales/SOC review. It is not a complete dependency, contributor-rights or release-compliance clearance.

The Community notices now identify AGPL-3.0-only as the governing license. The adapted proprietary EULA, automatic liability cap, additional use restrictions and onboarding acceptance gate were removed. The app embeds the complete root `LICENSE` as a resource and displays it with the explanatory notice. Existing legal resource URIs remain stable. The privacy notice was preserved without a new factual audit.

`README.md`, `COMMERCIAL.md`, the distribution notice and the in-app notices distinguish binary conveyance under section 6, modified network-interactive versions under section 13, ordinary execution, and separately executed commercial agreements. Business use alone is not a commercial-license trigger. Alternative licensing is limited to rights the licensor owns or is authorized to grant; third-party obligations remain.

Evidence is recorded in `private/licensing-2026-10-29/verification.json`, including per-file before/after hashes. `licensing-reconciliation.patch` in that directory contains only this reconciliation's delta against the shared tree as found, rather than incorporating unrelated peer edits into a new commit.

Validation:

- Test project build: passed, zero warnings/errors (`build-tests.txt`). This is a build result, not a test-suite pass.
- Five compiled resource/notice checks: passed (`runtime-checks.txt`, executable probe source in `probe/`).
- Packaged license and complete AGPL in installer notice: passed (`package-checks.txt`). No installer was built or published.
- Root `LICENSE` unchanged; privacy notice unchanged; both edited XAML documents parse as XML (`record_reconciliation.py`).
- Full UI build: blocked during restore by NuGet DNS failure, `NU1301` and `NU1900` (`build-ui.txt`). UI compilation and interaction remain unverified.

Remaining release work includes matching shipped binaries to their complete Corresponding Source, dependency notices/source obligations, and evidence of contributor grants required for alternative licensing. Existing signed agreements were not amended. No SOC capability or certification is established by these licensing edits.

PR [#26](https://github.com/Spplatten/SPLAT/pull/26) was reviewed at `b8ff4d59481dc8e09067fd036cc05c1b15616030`: one added supported-policy limitation about host sleep extending the wall-clock end of a lease. The guarded merge request was rejected with HTTP 403, “Resource not accessible by integration.” The local GitHub CLI credential was invalid, and no browser-control tool was available. A subsequent GitHub read confirmed the PR remains open and mergeable. No merge or push is claimed.

License references: [GNU AGPL v3](https://www.gnu.org/licenses/agpl-3.0.html), especially sections 6, 9, 10 and 13; [GNU license FAQ](https://www.gnu.org/licenses/gpl-faq.html). The full license controls over the summaries.
