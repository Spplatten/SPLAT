# One-step secret input: daemon contract (5.2)

Implementation is in `secrets.rs`, `secret_memory.rs`, `secret_recovery.rs`, `identities.rs`,
`execution.rs`, and the execution path in `main.rs`. The ordinary native suite passes; the five
isolated root component checks are recorded with source and test-binary hashes in
[`evidence/secret-components.json`](evidence/secret-components.json). They exercise binary delivery,
UID drop, private IPC, malformed/cancelled uploads and workspace recovery.

**Full daemon enforcement and lifecycle proof remains pending.**
[`evidence/secret-probe.json`](evidence/secret-probe.json) records a failed startup attempt: the
installed service's older BPF pin set was correctly refused. Retiring those idle pins for the
prepared integration proof requires explicit operator approval in this session. No passing
component test replaces that proof. Desktop/vault handoff and `GovernedHttp` integration are
separate work; this change does not close all of roadmap 5.2 or caller identity in 2.4.

## Enable the broker

The service operator creates a canonical root-owned directory with mode 0700 and supplies
`--secret-socket /run/splat/secrets/input.sock`. The socket is mode 0600. Both ends check the
connected peer's native Linux UID is zero. A non-root daemon or `--mock-bpf` cannot enable it.
There is no shared-token-only fallback for submitting secret bytes.

`--secret-uid-start` defaults to 200000 and `--secret-uid-count` to 64; the count may be 1–256.
Reserve that UID/GID range administratively. Startup refuses existing accounts, processes or an
overlap with the ordinary workload identity. Each active secret step occupies one identity. A
failed drain or incomplete scratch/workspace cleanup quarantines that identity until restart.
Capacity exhaustion refuses work. Startup drains orphan cgroups before checking identities or
recovering secret workspaces.

This authenticates a **local root service principal**. It does not identify a Windows user, and
does not protect an operator-owned WSL distro from its Windows owner. A managed deployment must
run the issuer under the service-owned distro identity described by the caller-identity work.

## Session and wire sequence

1. Open protocol 3 with `proveFrames: true`, verify the `CHALLENGE`, then send and verify a
   `HEALTH_CHECK`. Require both `enforcing` and `secretStdinSupported` to be true. This round trip
   also confirms that the broker has registered the session.
2. Prepare the complete approved `EXECUTE_TOOL` object **without** `secretGrant`. It must name
   `protocolVersion: 3`, explicit safe `missionId` and `stepId` values (1–128 ASCII letters,
   digits, dots, dashes or underscores; neither `.` nor `..`), an absolute command and working
   directory, string `argv`, `allowedExecPaths` containing the command, explicit `allowNetwork`,
   IPv4 `allowedEgressIps` and ports in 1–65535. Empty endpoint lists are accepted. Require
   `ephemeralWorkspace: true` and `leaseDurationSeconds` in 5–300. The existing lease ceiling,
   workspace-root restrictions and executable policy still apply.
3. The root service opens the separate Unix broker socket and writes: a four-byte unsigned
   **big-endian** metadata length; exactly that many UTF-8 JSON bytes; then exactly
   `secretLength` raw bytes. It shuts down its write half. Binary secrets, including NUL, are
   accepted. The payload is never JSON, an environment value, or a command argument.
4. Metadata has exactly these camelCase fields: `clientNonce`, `serverNonce` (64 hex digits
   each, from that protocol session), `request` (the approved object), `ttlSeconds` (1–60),
   and `secretLength` (1–4096). Unknown metadata fields, oversized headers, truncated payloads
   and trailing bytes are refused. The header limit is 65536 bytes. An upload has five seconds
   including the response. The broker admits eight simultaneous uploads and 64 pending grants.
5. Success returns one JSON object, `{"secretGrant":"<64 hex digits>"}`, followed by EOF.
   Refusal closes the connection without echoing payload or metadata. Add that opaque grant
   to the same approved request and send it through the original session's authenticated
   protocol envelope. Do not reconnect, modify the request, or pipeline another request while
   its secret step runs. A grant is consumed atomically once; changing either nonce or any
   parsed request field invalidates the binding. TTL expiration and session closure destroy
   pending grants. A failed launch after consumption requires a fresh grant.

The daemon's issuer mode supports the same transfer:

```text
splat-agent --secret-socket /run/splat/secrets/input.sock --issue-secret /private/binding.json
```

Its stdin is the raw payload, terminated by EOF; stdout is only the opaque grant acknowledgement.
The binding file holds the public metadata described above, with `secretLength: 0`; the issuer
sets the actual bounded length from stdin. It runs as root without starting a daemon, loading
BPF, or taking the daemon lock. The host should pipe a vault value directly into this process,
close stdin, consume the acknowledgement, then close its own transient copy. Never put a vault
value in this file, a shell expression, an argument, or the protocol request. Oversized or empty
stdin is refused. The service supplies its own issuance deadline while writing stdin.

## Child and cleanup contract

All workloads now clear the inherited service environment. Fixed defaults are `PATH=/usr/bin:/bin`,
`LANG=C.UTF-8`, `HOME=/tmp`, `TMPDIR=/tmp`. Optional `environment` adds at most 16 string entries:
`LANG`, `LC_ALL`, `TZ`, `TERM`, or names beginning `SPLAT_PARAM_`. Names contain only uppercase ASCII
letters, digits and underscores and are at most 64 bytes; values are at most 1024 bytes and contain
no NUL. These are public business inputs. Loader, interpreter, proxy, PATH and HOME overrides are
refused. Ordinary workloads receive EOF on stdin.

Pending secret payloads occupy bounded `mlock`ed mappings excluded from dumps and fork inheritance;
drop overwrites those buffers with volatile stores before unmapping. Consumption creates a sealed,
anonymous, mode-0000 memfd. Its backing pages remain locked and excluded from the daemon's dumps
and fork mappings until teardown. Only its inherited stdin descriptor reaches the intended child.
The descriptor's seals prevent changes or resizing. A workload cannot reopen it by pathname.
Allocation, locking or sealing failure refuses the step.

Secret children retain the existing cgroup and mount jail, receive a distinct UID/GID, a private
IPC namespace, no supplementary groups, `no_new_privs`, and a zero hard core-file limit. An
inherited seccomp filter permits new IPv4 sockets and refuses other socket families, `socketpair`
and `io_uring_setup`; the existing BPF rules decide which IPv4 destinations are reachable. This
blocks local descriptor transfer and the asynchronous socket-creation bypass. The filter checks
the syscall architecture and rejects x32; x86-64 and AArch64 are the implemented ABIs. The evidence
here is for the recorded x86-64 kernel, not a live AArch64 deployment.

Secret steps discard stdout/stderr, and their violation frames withhold the process-controlled
`comm` string. Service logging no longer prints argv. The daemon sends structural lease, denial
and exit information; it does not attempt to redact arbitrary tool output after accepting it.
TCP handshakes, idle sessions and frame writes have 10-, 30- and 5-second limits respectively;
there are at most 128 accepted sessions. Disconnect or pipelining on an active secret session
ends the step. The deadline reaper kills descendants before removing policy. Drain verification
reads `cgroup.events` population for the whole subtree; a failed read is not an empty cgroup.
Duplicate active mission IDs cannot adopt or overwrite an existing cgroup.

The cleanup owner retains the jail until a verified drain, closes the secret input, removes
scratch and workspace, and only then releases the identity. Early returns follow that path too.
An unsuccessful drain retains policy and quarantines the identity; locked input/jail resources
are retained until daemon restart. A root-only `.secret-steps` journal under the configured
missions root records workspace names and UIDs **without secret content**, synced before exec.
After orphan drain, restart removes those workspaces before accepting another secret. Recovery
refuses corrupt records, path escape and changed ownership. If SIGKILL prevents teardown,
cleanup is completed on restart, not retroactively claimed at the crash.

The memory primitives follow the Linux [memfd](https://www.man7.org/linux/man-pages/man2/memfd_create.2.html)
and [madvise](https://www.man7.org/linux/man-pages/man2/madvise.2.html) contracts; subtree population
uses the kernel's [cgroup v2 interface](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

## Responses and evidence

`LEASE` adds `environmentMode: "explicit"`, `secretStdin: true` and `processOutput: "discarded"`.
The existing `workloadUid` is the reserved identity. A normally completed teardown adds
`secretStdinClosed: true` to `EXIT`; `workspaceRemoved` still reports its actual result.

When the guest signing key is available, `EXIT` also carries `secretOutcomeCanonical` and
`secretOutcomeSignature`. Verify the exact UTF-8 canonical string using the existing
`outcomePublicKey` (base64 PKCS#1 RSA public-key DER), RSA PKCS#1 v1.5 with SHA-256, and the pinned
guest key identity. Its JSON contains `type: "splat-secret-step/1"`, `stepId`, `requestSha256`,
`secretStdinClosed`, `environmentMode`, `processOutput`, and the original `outcomeCanonical`.
The request digest covers serde_json's compact parsed object with sorted keys, excluding only
`secretGrant`; it never hashes the secret. Verify the included outcome matches the ordinary
signed outcome. Preserve canonical text verbatim; reserializing JSON can change signed bytes.
An absent signing key produces no signature, as with ordinary outcomes.

The prepared [`probe-secrets.py`](probe-secrets.py) tests the enforcing daemon with synthetic
secrets and an in-process loopback receiver: grants, malformed uploads, root peer checks, CLI
issuance, egress denial, simultaneous UIDs, `/proc` read denial, output suppression, signatures,
failed spawn, disconnect, deadline, duplicate IDs and crash recovery. It records the binary and
every native source hash. It refuses to stop a service with populated leases. Its optional
`--retire-idle-pins INSTALLED_BPF_SHA256` step requires approval here: under the instance lock it
checks the exact pin directory and empty lease map before retiring policy, then retires the test
pins after drain and restores the installed service. The daemon's foreign-pin refusal is unchanged.

[`prove-secret-components.py`](prove-secret-components.py) records the five ignored
`root_secret` native tests separately. That safer test path neither starts/stops a service nor
changes BPF pins, and its evidence says so explicitly.

## Boundaries that remain

The grant service must approve the command, declared environment and egress together. A workload
that receives a credential can use it at an allowed endpoint; shared CDN addresses still require
the separate hostname-proxy work. This is not general information-flow enforcement: a malicious
recipient can encode information in allowed traffic, numeric audit fields, timing or process
metadata. Do not claim arbitrary secret non-exfiltration or isolation from guest root.

Provider credential revocation, Windows caller identity, and managed-vault buffer lifetime are
outside this daemon contract. Closing Linux descriptors does not revoke a provider credential.
Workloads can copy stdin into their own memory or scratch; the lease drains processes and removes
files, but does not promise physical erasure of freed pages, storage, host snapshots or previously
swapped workload memory. The core-file limit does not control a privileged piped core-dump helper;
the service operator must configure host crash collection appropriately for secret workloads.
