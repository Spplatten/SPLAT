<!-- Written 2026-09-20, after the substrate audit and the record change, in answer to "what should
     be done about these". Five weaknesses of the Linux lease, a recommendation for each, and the
     order. Opinions are marked as such; everything else was read out of the tree at 953c9bb. -->

# Substrate hardening — the five weaknesses, and what to do about each

The kernel program is small, straight-line and fails closed on the side that matters. The
weaknesses are around it: the boundary it draws is narrow, the process that installs it can die,
and the caller it trusts is identified by a secret. This is the plan for closing them, in the
order I would do it, with the reason for the order. Where a recommendation is a judgement rather
than a fact, it says so.

| # | Weakness | Fix | Effort | Needs root to prove | Order |
| --- | --- | --- | --- | --- | --- |
| 1 | A deny-list on files, not a jail | A mount namespace and `pivot_root` in `pre_exec`; the umask fix written by `provision` meanwhile | Large | Yes | First |
| 2 | UDP is unpoliced | An `lsm/socket_sendmsg` hook checking datagram destinations against the same map | Small kernel change, medium policy change | Yes | Second |
| 3 | Nothing survives the daemon | Pin the links and maps under `/sys/fs/bpf`; reopen them on start | Medium | Yes | Third |
| 4 | It hangs on a shared secret | A root-owned ceiling policy in the guest that bounds every lease, whoever asks | Small | No | Fourth, but cheap enough to do alongside |
| 5 | Today's change is unproven | Run the probes; then make re-proof a one-line unattended step | Small | Yes | Now |

---

## 1. From a deny-list to a jail

> **Done the same evening, pending the root probe.** [`jail.rs`](../../native/splat-agent/src/jail.rs)
> builds the root in the parent and enters it in `pre_exec` exactly as set out below, with `/etc`
> whole rather than sliced, and `readOnlyFs` is now honoured. `probe-daemon.sh` carries five checks
> for it. `provision --apply` writes the umask line. What follows is the reasoning as it stood
> before the code; the code is the reference now.

**What is true today.** The lease names inodes the workload may not open: `/etc/shadow`,
`/etc/sudoers`, and whatever the caller adds. Everything else on the guest is reachable at
`nobody`'s permissions, which on WSL includes the Windows drives under `/mnt` unless the
`umask=077` automount option is set. The runbook has that line; `provision` does not write it.

**What should be done.** Build P2 of [the plan](2026-09-09-oem-subtraction-plan.md): give the
workload its own mount namespace with a root that contains only what the lease needs. Inside the
same `pre_exec` closure that joins the cgroup, and before the privilege drop while the child is
still root:

1. `unshare(CLONE_NEWNS)`, then `mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)` so nothing
   the child mounts propagates back to the host.
2. Build the root at a per-lease directory the daemon prepared in the parent: bind mounts of
   `/usr`, `/bin`, `/lib`, `/lib64` and a curated slice of `/etc` (resolver, certificates, passwd
   for `nobody`), each remounted read-only; the workspace bind-mounted read-write; a fresh `tmpfs`
   at `/tmp`; a fresh `proc` because most tools need it; **no `/mnt`**, no `/home`, no `/root`.
3. `pivot_root` into it and `umount2` the old root with `MNT_DETACH`.

Every path must be a `CString` built in the parent, and every call a raw syscall, because the
closure runs in the forked child of a multithreaded process and may not allocate or lock. That
constraint is the whole difficulty, and it is why `cow.rs` has sat parked: the mount is the easy
half.

With that in place three refusals become features: `readOnlyFs` is a read-only bind of the
workspace, `overlayFs.enableCow` is `cow.rs` mounted as the workspace inside the new namespace,
and the deny-list becomes a second line rather than the only one. Ambient reads of the Windows
drives close because `/mnt` is simply not there.

**Meanwhile, today.** Make `splat-mcp provision --apply` write the `[automount] umask=077` line
to `/etc/wsl.conf` when it is absent, and report `todo` when a restart is needed to apply it. It
is a one-line change in the provisioner, and it turns a runbook step every operator has to
remember into something the tool does. My judgement: do this before anything else on this list.

**How it is proven.** Two new checks in `probe-daemon.sh`: a leased `cat` of a file outside the
workspace that is *not* on the deny-list (a file under `/home`, and one under `/mnt/c`) returns
ENOENT, because the path does not exist in the workload's root; and a leased write to the
workspace under `readOnlyFs` returns EROFS. Both need a root daemon.

## 2. Policing UDP

> **Done 2026-09-21, pending the root probe.** The `lsm/socket_sendmsg` hook is in, judging a
> datagram's own destination against the same allow-list, denying IPv6 and a too-short address as
> `connect` does, and passing a message with no destination because `connect` already judged that
> socket. Violations carry hook `4`, which `violation.rs` and `KernelViolationHook` name.
> `doctor` warns when an egress policy has no resolver. The probe carries both halves. The
> local-socket allow-list below is still not built.

**What is true today.** The `socket_connect` hook fires for TCP and for a UDP socket that calls
`connect()`. A datagram sent with `sendto()` on an unconnected socket never passes through it,
so a leased tool can reach any address over UDP, including a resolver on port 53. AF_UNIX and
AF_NETLINK are unpoliced by choice, because denying local IPC wholesale would break name
resolution and logging for the shipped catalogue.

**What should be done.** Add `lsm/socket_sendmsg`. For a leased cgroup: if the socket is
`AF_INET` and the message carries a destination (`msg->msg_name` is set, which is what an
unconnected `sendto` looks like), check `(cgroup, address, port)` against `allowed_connect_ipv4`
exactly as `socket_connect` does; a message with no destination is on a connected socket that
`socket_connect` already judged, so it passes. `AF_INET6` with a destination is denied, as
`connect` denies it. The hook runs on every `sendmsg` of a leased process and on nothing else,
and its first instruction is the `leased_cgroups` lookup, so the host pays nothing.

The policy side is the larger change and the one to think about: once UDP is policed, a lease
with the network on needs its resolver on port 53 in its allow-list or every name lookup fails.
That is correct behaviour, and it is also a surprise. The operator's `--egress` list should
therefore accept the resolver as an ordinary `address:53` entry, and `doctor` should say when a
policy names web endpoints and no resolver. The daemon must not add a resolver on its own; a
dimension nobody declared is the thing this daemon refuses on principle.

Local sockets stay unpoliced for now. The honest next step there is an allow-list of socket
paths keyed by inode through `unix_stream_connect`, which is the same shape as the file
deny-list; it is not urgent, because a leased tool that talks to a local daemon is talking to
something the operator installed.

**How it is proven.** A leased `dig @1.1.1.1` with the network off, refused with EPERM from
`sendto`; the same with `1.1.1.1:53` in the lease, answered. The recorded violation carries
hook `4`, so `violation.rs` and the C# enum gain a value.

## 3. Surviving the daemon

**What is true today.** The BPF programs and maps are owned by the daemon's file descriptors
and vanish when it exits. Since 2026-09-20 a restarting daemon kills every lease cgroup it
finds, so a workload no longer runs unpoliced indefinitely; it runs unpoliced for the length of
the crash-to-restart window, two seconds plus the time to drain.

**What should be done.** Pin the three program links and the five maps under a bpffs directory
named by the source hash: `/sys/fs/bpf/splat/<sha256 prefix>/`. On start, if that directory
exists and its objects open, reuse them: the hooks never detached, every lease that was policed
is still policed, and the daemon's job is to rebuild its table from `leased_cgroups`. It cannot
rebuild expiry or the mission names, so the honest treatment of a lease it inherits is the same
as today's: kill it, because nobody can say when it should have ended, but kill it *while it is
still policed*, which is the property the window lacks. If the directory holds another hash's
objects, remove them and load fresh; a program that changed must never be trusted to match maps
it did not create.

`libbpf-rs` has what this needs: `OpenMap::set_pin_path` and `reuse_pinned_map` before load, and
`Link::pin` after attach. The bpffs mount at `/sys/fs/bpf` is present on systemd guests; the
provisioner should check for it.

**Why third and not first.** The window is real, but it opens only when the daemon dies, and
the daemon exits on purpose only when it cannot enforce. A jail and a policed UDP path close
holes that are open on every lease, all the time.

**How it is proven.** Start a long lease, `kill -9` the daemon, and before the unit restarts it
attempt an exec outside the lease from inside the workload: EPERM, from a kernel program with no
daemon behind it. Then confirm the restarted daemon reports the inherited lease ended.

## 4. The shared secret

> **Done 2026-09-21.** [`ceiling.rs`](../../native/splat-agent/src/ceiling.rs) loads a root-owned
> `/etc/splat/policy.json` at startup, refuses to start under one that others could write, and
> intersects every request with it; `HEALTH_RESPONSE` and `doctor` say whether a host has one;
> `provision --apply [--egress ...]` writes it and restarts the daemon when it changed. Ten tests on
> the intersection, needing no root. What follows is the reasoning as it stood.

**What is true today.** The daemon trusts anyone who proves possession of `/etc/splat/agent.token`.
An unprivileged guest process cannot read it, and a squatter on the port learns nothing. Any
Windows process running as you can read it exactly as the bridge does, through `wsl -u root`,
because WSL lets any process of yours be root in the guest.

**What should be done, and what should not.** No transport fixes the Windows half. AF_VSOCK
would tell the daemon the caller is the host, not which process on the host, and a process
running as you can already do everything you can, including starting its own guest and reading
the file. That is the same trust boundary the Windows substrate lives under, where the mission
engine itself runs as the operator. I would stop describing it as a gap to close and describe it
as where the boundary is.

What is worth doing is bounding what a request can ask for, so that holding the token buys less.
A root-owned `/etc/splat/policy.json` in the guest, written by `provision` from the operator's
`--egress` and `--workspace`, holding a **ceiling lease**: the executables a lease may name (by
directory prefix), the endpoints it may name, the paths it must always protect, the largest
duration and clamps. Every `EXECUTE_TOOL` is intersected with it before anything is provisioned,
and a request outside it is refused with the same wording the daemon uses for an undeclared
dimension. The MCP host's `McpEgressPolicy` then becomes the first of two checks rather than the
only one, and the second runs in the process that installs the lease, where a stolen token cannot
reach around it.

This needs no root to prove: the intersection is a pure function with tests in `lease.rs`, and
`probe-daemon.sh` gains one check, a request outside the ceiling refused.

## 5. The unproven change

**What is true today.** The record change of 2026-09-20 compiles, its layout is asserted, and
its hooks are still straight-line code. Whether the verifier accepts it and the hooks still
refuse correctly is unknown until `probe-daemon.sh` and `probe-last-hop.ps1` run against a root
daemon, and the README says so.

**What should be done.** Run them; [GUIDE-operator.md](../GUIDE-operator.md) has the steps.
Then make this routine, because it will recur with items 1 to 3: every one of them changes the
kernel program and withdraws the claims again.

The unattended path already exists and needs no password: `wsl -u root` runs anything as root in
the guest. What the documented path adds is `sudo` inside `run-daemon.sh` and `probe-daemon.sh`,
which is what prompts. A `packaging/reprove-substrate.ps1` that stops the unit, starts a fresh
build as root through `wsl -u root`, runs both probes with the evidence directory pointed at the
tree, restarts the unit, and prints the two verdicts would turn re-proof into one command an
operator runs after every kernel-side change, and the drift test would then be the only thing
standing between a change and its claim, which is where it belongs. One caution from experience,
confirmed again on 2026-09-20: an agent running under the permission classifier is refused
stopping the installed service, starting a root daemon beside it, and reading the token, so this
script is for the operator's own terminal, not for an agent to run. That is also why the guide
gives the steps to you rather than reporting them done.

---

## The order, in one line

Umask into `provision` today; the jail; UDP; pinning; the ceiling policy whenever there is an
afternoon, since it needs no root; and re-proof after each, made cheap first.
