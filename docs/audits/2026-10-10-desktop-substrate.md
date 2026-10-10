# Desktop substrate verification, 2026-10-10

Roadmap 5.0 remains in progress. The lifecycle library, managed desktop transport and eight leased
public sensors are implemented. The shared checkout was captured in `3d5e0d1`; subsequent bridge
framing tests and this verification do not turn that capture into privileged deployment evidence.

## Local evidence

| Check | Result and limit |
| --- | --- |
| Desktop and test-project builds | .NET SDK 10.0.401, Debug, single build worker, shared compilation disabled: zero warnings and errors. Test outputs were isolated after another process locked the shared output directory. |
| Desktop `--self-test` | Exit 0 at 2026-10-10T16:00:51Z; all 10 pages opened and loaded, including Kernel Lease; no unhandled exceptions. No mount or mission execution is part of that check. |
| Offline .NET assertions | 121 passed, one failed using an in-process allowlist over the compiled test assembly. The failed assertion is current-definition corpus coverage. This is not a full xUnit run; loopback integration and live model tests were not part of the completed check. |
| Python sensor checks | `python -B -m unittest discover -s tests -p test_leased_web_probe.py -v`: six passed. Tests exercise numeric socket pinning with hostname TLS, failover cleanup, redirect refusal, response bounds and BLS year comparisons without contacting any publisher. |
| Managed response framing | `ManagedBridgeClientTests`: complete frames return while the service remains open, split UTF-8 survives, truncated frames and invalid UTF-8 fail. Existing managed admission and lifecycle assertions also pass locally. |

The corpus failure names `grants-opportunity-ingestion`, the six `source-*` probes,
`trends-brief-composer` and `sysops-time-sync`. The first eight changed their tool definitions in
5.0; the last was already stale in the initial baseline. No fixture hashes or recorded answers were
changed to make this gate pass. The test count and tutorial were regenerated through their existing
test-owned synchronization paths.

## Pending execution and data scope

[`MissionController.SubstrateProbe`](../../tests/MissionController.SubstrateProbe/Program.cs)
supports `--plan <output-directory>` before `--execute <output-directory>`. The plan prints exact
template IDs, defaults, destinations and definition hashes. Execution checks the substrate first
and saves local receipts; it does not mount the guest, construct a model client or read the vault.
Its eight public requests target HTTPS port 443 at `api.grants.gov`, `api.bls.gov`, `wikimedia.org`,
`api.eia.gov`, `api.census.gov` and `rareresources.net`. BLS and Grants.gov use read-only query POSTs.
No API credential is supplied to those publishers.

The separate recording step in [`LiveMissionTests`](../../tests/MissionController.Tests/LiveMissionTests.cs)
sends template prompts and scrubbed sensor output to Anthropic's `api.anthropic.com/v1/messages`,
using the configured credential and model credit. The eight source probes send public observations;
the independent stale `sysops-time-sync` recording would send local Windows time/service telemetry.
Each recording must be reviewed and redacted before entering the committed corpus.

Automatic approval review rejected the live model recording because these payloads and destinations
needed specific authorization. A later request to run only the public-source probe was not executed
because automatic approval review had reached its usage limit. Neither operation ran. Offline
checks do not substitute for either proof.

Remaining acceptance: a real desktop mount/check lifecycle, the managed deployment and cross-account
proof from roadmap 2.4, eight public sensors under the real lease, fresh corpus recordings and a full
test run. The source-bound kernel evidence from 2026-10-06 remains its own proof, not evidence for
these new desktop paths. The current Field Guide publication record was updated separately in the
shared checkout; this verification did not perform or independently verify that publication.
