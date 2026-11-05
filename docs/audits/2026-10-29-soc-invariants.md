# SOC monitoring invariants — work started 2026-10-29

Status: local changes, not a verified release or a SOC attestation. This closes the record for the
monitoring work interrupted by the subsequent ecosystem-sidecar task.

Source changes add explicit SIEM connection evidence, cancellable TLS handshakes, protocol validation,
CEF escaping, original event timestamps and octet-counted syslog TLS framing. The EDR isolation
method previously only changed an in-memory variable and manufactured an activation alert; it now
refuses unsupported isolation requests. Unknown isolation and real-time protection remain unknown.
The nullable protection field is an API contract change; consumers must not interpret null as false.

Evidence: `private/soc-2026-10-29/build.txt` records a test-project build with zero warnings/errors.
The VSTest attempt in `tests.txt` aborted after a 90-second test-host connection timeout.
`direct-checks.txt` records **22 passing and 7 failing targeted direct invocations** of compiled
test methods. The seven failures were socket-based tests that timed out; they are NOT waived or
counted as passes. TLS interoperability, wire delivery and the full UI build remain unverified.
The scratch harness build emitted NU1900 because NuGet vulnerability metadata was unreachable.

The changes and original snapshots are under `private/soc-2026-10-29/`; no peer work was staged.
The canonical test-count synchronization was not reached by the original harness because it had
failures. Counts must be derived with the repository's writer, never typed by hand.

Follow-up: the existing test project was rebuilt on 2026-11-04, then the canonical count test's
reflection-based writer was invoked directly and its assertion rechecked. Both succeeded
(`private/sidecar-2026-11-04/test-count-sync.txt`). This synchronized the counts without claiming
that the suite passed. Independent raw loopback checks recorded TCP permission denial and a UDP
receive timeout; the earlier seven test failures remain unresolved, not converted to passes.

Open control gaps: durable general-purpose SIEM delivery; independently retained audit checkpoints;
fresh native proof for the combined working tree; install/upgrade/rollback and recovery drills;
an authenticated provider EDR actuator and provider-state query; independent review and sustained
operating evidence. The sidecar experiment provides a one-task cancellation mailbox, not a replacement
for the general audit outbox.
