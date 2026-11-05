# Falcon sidecar operator procedure

An alert can request cancellation only for the task in the operator-owned admission binding.
The adapter never modifies a Falcon sensor or SPLAT's native lease maps. This is a prototype
webhook adapter with local contract tests, not a qualified CrowdStrike deployment.

Implementation: `src/splat-alert-sidecar/`. Evidence and limits:
[reconciliation follow-up](audits/2026-11-05-reconciliation-follow-up.md).
Architecture: [decoupled sensor enforcement](DECOUPLED-SENSOR-ENFORCEMENT.md).

## Prepare the admission boundary

The admission owner must establish a relationship between the SPLAT task UUID, native process
generation and the tenant's Falcon process-instance identity before enabling cancellation.
The sidecar does not discover this relationship. An OS PID, hostname, alert timestamp or Windows
process creation timestamp alone cannot supply the Linux boot/cgroup/PID/start-ticks tuple.
Automatic registration and descendant tracking remain unimplemented. If the deployment cannot
establish this mapping, keep it in offline validation; do not substitute a best-effort PID lookup.

Retain the existing binding fields: `taskId` (32 hexadecimal digits, no hyphens), `node`, `boot`
(nonempty GUID), `cgroup`, `pid`, `startTicks`, `source`, `rule`, `expiresUnixMs`, `listenPort`
and `a2aPort`. Source must be `falcon` in adapter mode. Ports must differ. The binding and mailbox
belong to one task. Existing normalized bindings retain their original mailbox fingerprint.

Add this `falcon` object to a Falcon-mode binding:

| JSON field | Operational meaning |
| --- | --- |
| `tenantId` | Exact tenant identifier from trusted enrollment. |
| `agentId` | Exact endpoint-agent identifier; never inferred from hostname. |
| `processInstanceId` | Opaque vendor process-generation identifier, not a recycled OS PID. |
| `notBeforeUnixMs` | Admission lower time bound; earlier observations are rejected even if otherwise fresh. |
| `profileSha256` | SHA-256 of the reviewed profile's exact bytes; even whitespace changes require a new binding. |

Keep binding, profile, certificate, mailbox and credentials inaccessible to the monitored workload.
The mailbox is a coalescing control record, not an archive of every alert. Preserve full sensor
history in the collector or SIEM.

## Review the event profile

Use a customer-authorized event sample and the deployment's schema to choose these fields.
The synthetic event in `FalconChecks.cs` is a test fixture, not a vendor schema promise.
Do not copy its field names into a production profile without checking a real event.

| Profile JSON field | Operational meaning |
| --- | --- |
| `version` | Integer `1`, the adapter profile contract. |
| `eventType` | Exact allowed type string for this profile. |
| `eventTypePointer` | JSON pointer to the event type. |
| `tenantPointer`, `agentPointer`, `processInstancePointer` | Exact identity fields to compare with the admission binding. |
| `rulePointer` | Rule identifier compared with the binding's allow-listed rule. |
| `eventIdPointer` | Bounded evidence ID retained for the first accepted alert. |
| `eventTimePointer` | Observation time, not relay receipt time. |
| `timeEncoding` | `unix-ms`, `unix-s`, or `iso8601`; ISO timestamps require an explicit offset. |

Pointers traverse objects only, with `/` separators and `~0`/`~1` escaping. A dotted key is literal.
Arrays cannot be traversed; submit one event per request. All seven pointers must differ.
Malformed pointers, duplicate JSON properties, missing fields and unsupported profile fields are
rejected. Unknown event fields are ignored. Unsigned integer IDs retain every digit; floating-point
and exponent encodings are rejected. Configuration files and request bodies are limited to 16 KiB.

## Build and inspect without dispatch

```powershell
$sdk = Join-Path $env:LOCALAPPDATA 'Microsoft\dotnet\dotnet.exe'
./packaging/test-alert-sidecar.ps1 -DotNetPath $sdk
$sidecar = './src/splat-alert-sidecar/bin/Release/net10.0/splat-alert-sidecar.dll'
& $sdk $sidecar --inspect-falcon-profile ./approved-falcon-profile.json
& $sdk $sidecar --check-falcon-event ./admission-binding.json ./approved-falcon-profile.json ./sample-event.json
```

- `$sdk` names the installed .NET 10 executable; where a runner redirects `LOCALAPPDATA`, set it to
  that executable's real path. `-DotNetPath` never falls back to the machine-wide .NET 9 SDK or
  suppresses warnings.
- `test-alert-sidecar.ps1` builds first, then runs `--self-test`; either failure fails the gate.
- `$sidecar` names the Release assembly produced by that build.
- `--inspect-falcon-profile` returns the exact profile hash after syntax checks; it does not approve
  the semantics of an identity field. Review the mapping before putting that hash in the binding.
- `--check-falcon-event` checks binding validity, schema, identity and freshness without network
  dispatch. Success includes `dispatched=false`; failure exits with code 2. An old captured sample
  will intentionally fail freshness checks. Keep historical samples as fixtures, not live alerts.

## Start an isolated pilot

Provide `SPLAT_ALERT_TOKEN` as a separate base64-encoded 32-byte random secret and
`SPLAT_A2A_CALLER_TOKEN` as the token `splat/RegisterSensor` returns for the bound task
([sensor registration](A2A-TEMPLATE-BRIDGE.md#sensor-registration)), which reads and cancels that
task only. The owner's own credential also works, but it can start new work under every skill the
owner holds. Supply
`SPLAT_ALERT_CERT_PASSWORD` if the PFX requires it. The listener certificate must validate for
`127.0.0.1`. A2A peer certificate validation remains enabled; never bypass it to make a pilot work.

```powershell
& $sdk $sidecar ./admission-binding.json ./mailbox.sqlite ./https-certificate.pfx ./approved-falcon-profile.json
```

- `admission-binding.json` supplies the fixed task and identity; event payloads cannot change them.
- `mailbox.sqlite` persists cancellation before HTTP acknowledgment. Its `.owner` file excludes
  concurrent sidecar owners. Reuse it only with the identical binding.
- `https-certificate.pfx` supplies the listener certificate and private key.
- `approved-falcon-profile.json` enables Falcon mode and must match the binding's exact profile hash.

The relay sends authenticated JSON POSTs to `https://127.0.0.1:<listenPort>/v1/falcon/alerts`
with `Authorization: Bearer <SPLAT_ALERT_TOKEN>` and `Content-Type: application/json`.
A Falcon-mode process does not also expose the normalized `/v1/alerts` route. Binding a Falcon
identity without supplying the profile is a startup error. There is no unauthenticated fallback.
The listener is loopback-only: remote Falcon/LogScale delivery needs a separately secured relay.
That relay must preserve the original observation time and exact identity, and must not follow
redirects carrying credentials. Do not expose this listener by simply opening a firewall port.

| Response | Required interpretation |
| --- | --- |
| `202` | Signal durably accepted or coalesced for the fixed task; termination is not confirmed. |
| `400`, `409` | Malformed schema or mismatched/stale identity; investigate rather than rewriting identity/time. |
| `401`, `404`, `405`, `415` | Check authentication, route, method or representation. |
| `413` | Body exceeds the contract; filter at the trusted collector without losing required fields. |
| `408`, `429`, `503` | Timeout, admission pressure or storage failure; bounded retry while the observation remains valid. |

The observation must be no older than 30 seconds, no more than 2 seconds in the future, and no
earlier than admission. Do not relabel an expired event with the current time. A cloud pipeline
whose delay exceeds this contract needs a reviewed design change before use.

Optional outcome export uses `SPLAT_LOGSCALE_INGEST_URL` and `SPLAT_LOGSCALE_INGEST_TOKEN`.
It runs separately from cancellation and records an export only on HTTP 200. Receivers must
deduplicate `splat.record_id`. The terminal outcome distinguishes a host report of drain from
a terminal task with no drain proof; neither the adapter nor the exporter independently verifies
the signed native receipt.

## Pilot acceptance and rollback

Before claiming live integration, capture one authorized real event and negative controls for
wrong tenant, endpoint, process generation, rule, profile hash and delayed delivery. Verify that
the independently observed native task drains, retain the receipt and installed binary hashes,
and measure observation-to-drain latency as a distribution. Test collector retries, mailbox disk
failure, restart recovery and coexistence with the installed sensor. Local handler tests do not
establish those deployment properties or SOC 2 compliance.

For rollback, disable relay delivery and stop the sidecar, retaining its mailbox for investigation.
This removes reactive cancellation; preinstalled SPLAT lease expiry remains independent. Stopping
the sidecar is not evidence that the workload stopped. Confirm drain through the existing host
control path before retiring the task binding or removing its durable state.
