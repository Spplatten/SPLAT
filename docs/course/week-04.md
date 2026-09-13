# Week 4 — Linux leases and kernel enforcement

## Lesson A: a lease connects policy to processes

**Outcome:** follow one request from daemon admission to a cgroup.

A Linux cgroup groups tasks and exposes resource controls. In this implementation, parent controllers must be delegated, child memory/CPU/PID values must be written, and their values must be read back. Inspect [apply_and_verify](../../native/splat-agent/src/cgroup.rs). Writing a configuration field is not evidence that the kernel accepted it.

A lease combines mission identity, executable identities, protected inodes, IPv4 endpoints, duration and resource limits. The daemon resolves guest paths to guest object identities. A Windows inode number cannot identify the same object in a Linux filesystem.

Study controller hierarchy and the distinction between resource accounting and isolation in the [kernel cgroup v2 reference](https://docs.kernel.org/admin-guide/cgroup-v2.html).

## Lesson B: the hook determines the boundary

**Outcome:** explain exactly which action each BPF hook observes.

The [BPF program](../../native/splat-agent/src/bpf/lease_lsm.bpf.c) checks executable admission, file opening and socket connection. It includes cgroup ID in resource keys so one mission's allow-list cannot authorize another. BPF-LSM attaches policy at kernel security hooks; the verifier checks program safety, not the business meaning of every policy field. [Kernel BPF-LSM reference](https://docs.kernel.org/bpf/prog_lsm.html).

Read [SUPPORTED_POLICY](../../native/splat-agent/SUPPORTED_POLICY.md) beside the code. Read-only filesystem and copy-on-write requests are refused. Unconnected UDP sends, local socket families and ambient filesystem access are documented gaps. The presence of file_open is not a complete filesystem jail.

On expiry, kill and drain descendants before removing policy. Removing the cgroup's policy marker first can make a surviving process appear unleased. Trace the reaper in [main.rs](../../native/splat-agent/src/main.rs) and kill_tree.

## Lab: turn a policy promise into a trace

~~~powershell
rg -n 'readOnlyFs|enableCow|protocolVersion|pre_exec|kill_tree' native/splat-agent/src/main.rs
rg -n 'SEC\(|lease_ipv4_key|is_leased' native/splat-agent/src/bpf/lease_lsm.bpf.c
~~~

1. Choose one allowed executable and one IPv4 endpoint from a synthetic lease.
2. Trace JSON → daemon validation → guest inode/endpoint → map key → hook decision.
3. Create four matrix rows: enforced in BPF, enforced through cgroup controls, refused, and not policed.
4. Review [daemon-probe.json](../../native/splat-agent/evidence/daemon-probe.json). Match a control and a denied case, and identify the recorded source hash.
5. Design a two-concurrent-lease regression: one mission may execute a fixture binary; the other may not.

Expected: the student can name a concrete unsupported request without calling it supported. Reviewing committed probes earns evidence-review credit, not a new host-test pass.

**Cybersecurity case:** a reference monitor needs complete coverage of the operations in its promise. A socket_connect policy alone cannot make a claim about every send path.

**Repair practice:** use ticket R6 in [repair tickets](repair-tickets.md) to design one additional boundary. Kernel work is an advanced extension; do not silently enable read-only or overlay flags in a compiler wrapper.

**Submit:** policy matrix, per-lease key drawing and proposed differential test.

**Check yourself:** Is cgroup resource control a filesystem namespace? Does a canary prove MCP-to-daemon execution?

**Answer checkpoint:** no. Resource ceilings, filesystem views and end-to-end connectivity are separate claims with separate tests.
