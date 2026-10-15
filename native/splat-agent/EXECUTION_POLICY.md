# Agent execution contracts

**Implemented; the recorded MCP-to-enforcing-daemon proof passes 50/50 checks.**
[agent-manifest-probe.json](evidence/agent-manifest-probe.json), recorded 2026-10-14 UTC,
binds the published Windows host, native daemon and compiled source inputs to the measured result.
[lease-isolation-agent-bridge.json](evidence/lease-isolation-agent-bridge.json) separately passes
51/51 lifecycle and isolation checks against the same daemon. These are measured-guest results;
clean-machine installation and managed cross-account deployment remain unproven. The earlier
[component record](evidence/execution-policy-components.json) retains its historical source hashes.

An agent tool binding may carry an `executionPolicy`. The manifest importer stores it on the
template, `TemplatePolicyCompiler` carries it into `LeaseSpec`, and `WslLeasedExecutor` sends
`EXECUTE_POLICY`, or `EXECUTE_AGENT` for an agent-bound endpoint. Older daemons refuse an unknown
operation rather than ignoring the restriction; `EXECUTE_AGENT` also requires enforcement when
the optional execution policy is absent.
The original executable, jail, operator ceiling, resource limits and BPF egress checks still apply.

The guest compiles the explicit syscall list into seccomp **classic BPF** at request time and
adds Landlock file rules in the fork child, after entering the jail and dropping privileges.
Both must succeed before exec. This is runtime policy generation, not generated Rust or a
new eBPF-LSM program. `POLICY_APPLIED` is sent only after successful spawn; a successful result
without it is rejected by the bridge. Its policy hash is an acknowledgement, not part of the
existing RSA-signed outcome format.

The [example agent](../../examples/agent-manifests/guest-identity.contract.json) is tied to the
measured Ubuntu guest's runtime files. Paste its JSON into **Build an agent**, review the
grants, and save. A missing runtime file or an older daemon refuses launch. Saving alone does
not execute the agent. The example's allowed inputs and denied `/etc/passwd` control were
exercised by `kernel_catalog_manifest_reads_only_the_declared_inputs`.

Use [infer-execution-policy.py](../../packaging/infer-execution-policy.py) with a saved
`strace -f -qq` trace, the executable, and a reviewed file-grant array to produce a candidate.
It does not execute a tool or authorize the result. It retains attempted calls, including failed
calls, and reports launch calls added explicitly. The binary hash is measured at review time;
the trace does not attest which binary produced it. Representative positive and negative cases
must be replayed before copying the candidate's `executionPolicy` into a tool binding.

## Supported boundary

- Schema version 1 requires x86_64, Landlock ABI 5 or newer, and an enforcing daemon.
- File grants target existing regular files. `read`, `write` (including truncation), and `execute`
  are independent. Explicit directory `tree` grants allow only read/execute for runtime support.
- Grant paths must be absolute, normalized and free of symlink components; rules pin the resolved
  objects during installation in the child's actual mount namespace. Use canonical paths even
  when the tool normally opens an alias. A grant does not expose a path absent from the jail.
- Unknown syscalls, other syscall ABIs, invalid grants and unavailable kernel features refuse or
  deny execution. Networked contracts still allow only AF_INET socket creation and remain bounded
  by the existing BPF destination policy. Offline contracts cannot request socket creation,
  connection, send or receive operations.
- File metadata, inherited descriptors, permitted output channels and semantic misuse of allowed
  operations are not eliminated. Landlock/seccomp denials are **not counted by the BPF ring-buffer
  telemetry**. Landlock access refusals normally return `EACCES`; disallowed syscalls return `EPERM`,
  while an incompatible syscall architecture terminates the process. Ordinary disconnect cleanup
  is measured separately by `disconnect_drains_descendants_and_workspace` in the lifecycle proof.
- Arbitrary JSON tool descriptions cannot establish a complete syscall set. Traces provide
  candidates, not proofs of all future branches. No automatic permission expansion follows a denial.

The kernel component tests cover allowed reads, write-only access, denied sibling files, refused
creation, denied exec and sockets, unknown syscalls, inheritance, invalid grants and composition
with a private mount namespace and observed unprivileged UID. The linked live proof adds authenticated
MCP-to-enforcing-daemon measurements; neither establishes clean-machine package deployment.
