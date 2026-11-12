# Lite guest ownership and verification refresh

Date: 2026-11-11. Baseline: `b492a87` on `main`. This is a local C# and packaging measurement;
no real guest was imported, no kernel probe was rerun, and no deployment was certified.

## Change

The Lite guest's keep-alive shell checked its identity marker, but the caller did not wait for
that result. Once the daemon token was cached, a subsequent connection could proceed without
a successful ownership check. `WslLeasedExecutor.ConnectToDaemonAsync` now accepts an optional
guest validator, and `BundledWslGuest` supplies `RequireOwnedAsync`. The check runs before any
socket is opened, under the existing connection budget, independently of token caching.
Execution, health and receipt recovery all use that connection method.

The regression uses its own ephemeral loopback listener and a recording WSL runner. Two
authenticated health exchanges with one token read establish the cache control. After the
identity marker changes, a new connection must fail and the listener must have no connection
pending. A second test refuses wrong ownership before even reading the token. Both pass.
This holds local guest-selection consistency; it does not exclude the owning Windows account.

## Measurements

| Measurement | Result |
| --- | --- |
| Test-project build, SDK 10.0.401, separate from execution | Zero warnings and errors |
| `BundledWslGuestTests` | 11 passed, 3 failed at atomic receipt replacement denied by the environment |
| `ManagedSubstrateCheckTests` | 4 passed, including cold startup before token retrieval and the reply budget |
| `SplatGuestPackagingTests`, Windows PowerShell 5.1 | 8 failed with `AuthorizationManager check failed` |
| The same eight packaging controls under PowerShell 7.6.9 | 8 passed, including staging of archive `9c5fab83` (`20261014T000000Z-r2`) |
| `WslLeasedExecutorWireTests`, `LeaseReceiptRecoveryTests`, `SubstrateLifecycleTests` | 52 passed, no failures or skips |
| `DocumentationDriftTests` and `MissionCorpusTests` | 21 passed, including current-template recording coverage and its negative controls |
| Advertised suite inventory | Re-derived as 1195 by `TheAdvertisedTestCount_MatchesTheSuite` with `SPLAT_SYNC_TEST_COUNT=1`; this is not a full-suite passing result |

The [console evidence](../../packaging/evidence/lite-guest-console.json) is deliberately
**INCOMPLETE**. Its new driver, `packaging/probe-splat-guest-console.ps1`, builds separately,
runs ordinary VSTest, records every outcome and source/assembly/result hashes, and refuses
evidence if an input changes while it runs. It fails the command when a check does not pass.
The [packaging evidence](../../packaging/evidence/lite-guest-packaging.json) separately records
the passing PowerShell 7 run. Source archives remain `NOT_INCLUDED`.

Local raw results under `artifacts/verification/lite-20261111/` are retained:

- `bridge-regressions-20261111.trx`: SHA-256 `65604036b8452ee2f912c2916dbcb936269d15b72392755379fc8d48a265a0b9`.
- `evidence-gates-20261111.trx`: SHA-256 `304bfc5a4ffc1c2616bedec2acee23409406ceb7977df6dc5a0bdf326ec86a6c`.

Automatic approval rejected the request to run the targeted tests outside the sandbox because
escalated permissions are disabled. The atomic update and PowerShell 5.1 tests are retained;
neither was weakened, skipped or relabelled as a pass.

## Reconciled backlog

PR #18 merged at `27876a9`; it is no longer blocking a native re-proof. The November 8 native
record has verdict PASS and 90 Boolean checks against `d5bb4cad`, whose normalized source hash
still matches this checkout. The separate November 5 Debian proof is also retained. These
saved runs are evidence for their recorded daemon and guest state, not a fresh console install.

The current-definition mission-recording gate passes on this checkout. No recording was
regenerated or blessed during this work, and no live model requests were made. DNS elevation,
real console import, complete installation lifecycle, fleet/soak testing, trusted signing,
source/relinking materials and the remaining release gates are still separate work.
