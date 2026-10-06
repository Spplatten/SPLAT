# Handoff — roadmap 2.4, caller identity on the bridge

**Written 2026-10-06.** For whoever takes 2.4 next, including a future session of the agent that
wrote this. The row in [ROADMAP.md](ROADMAP.md) says *half done*, and the half that remains is a
product decision rather than a protocol one. This page makes the decision cheap to take and the work
that follows it unambiguous.

Read [`THREAT-MODEL.md`](THREAT-MODEL.md) § *Who may drive the lease daemon* first. This handoff
assumes it and does not restate it.

---

## 1. What is already built — do not redo it

Protocol 3, landed 2026-09-14, with the daemon's own frames proven since 2026-09-23 (roadmap 2.6):

- The shared secret never crosses the wire. `HELLO` carries the caller's nonce; the daemon answers
  with an HMAC-SHA256 over that nonce and its own, which the caller checks before it sends anything
  else.
- Every request travels in an `AUTHENTICATED` frame whose proof covers both nonces, its place on the
  connection, and its exact bytes, checked in fixed time before the request is parsed.
- `HEALTH_CHECK` is included, since 2026-09-11.
- A caller that asks in its `HELLO` gets every later frame back in a `PROVEN` wrapper, and the
  `CHALLENGE` that agreed to it is proven under a label of its own so the agreement cannot be
  stripped in transit.

Vectors are asserted in [`auth.rs`](../native/splat-agent/src/auth.rs) and
`tests/MissionController.Tests/WslAgentSessionTests.cs` against the same values. The root probe
scored this: the daemon proved it held the token, refused a stranger, refused the token in the clear,
and proved every frame —
[`daemon-probe.json`](../native/splat-agent/evidence/daemon-probe.json), PASS over 74 checks at
`2026-10-06T03:47:49Z`.

**None of that is the gap.** The handshake is sound and nothing here asks for it to be changed.

---

## 2. The finding that reframed the row

Measured 2026-09-29 from an unelevated shell:

```
wsl.exe -u root -e /usr/bin/id   →   uid=0(root) gid=0(root)
```

The Windows user who owns a WSL2 distro is root inside it, by WSL's design. A process running as the
operator never needed the token: it can read the file, stop the daemon, load its own BPF programs, or
skip the daemon entirely and run the command itself.

So the gap was written down as *a shared secret identifies no caller*, and the measurement says the
secret is beside the point. **The guest is not a boundary against the Windows user who owns it.**

What is at stake is not root — the workload still runs as `nobody` under the kernel's hooks — it is
**ungoverned and unrecorded use of the sandbox**. An auditor asking what ran at 14:02 gets nothing,
because nothing wrote a row.

### Two things that are retired, and must not be proposed again

Both are in the threat model's table, and
`DocumentationDriftTests.TheCallerIdentityThreatModel_IsWrittenDown_AndNothingPromisesASocketWillCloseIt`
fails the build if a document goes back to promising either:

- **AF_VSOCK** identifies a virtual machine. Every Windows process presents the same host CID.
- **`SO_PEERCRED` over AF_UNIX in the guest** names whatever relay carried the bytes in, and any
  Windows process can spawn that relay.

They fail the same way: the caller they exist to exclude sits on the far side of a wire neither can
see across, and outranks the process that would be doing the excluding. **No wire contract closes
this.**

---

## 3. The decision

Three options from the threat model. Only the first excludes the stated caller.

| | Option | Excludes the operator's own Windows process? | Cost |
| :-- | :--- | :--- | :--- |
| 1 | **Move the principal.** Own the distro and run the bridge under a Windows identity that is not the operator's | **Yes**, with the limit in §4 | A service, a distro registered to that account, and identity moves up to the MCP layer |
| 2 | **Make the stolen capability worth less.** Refuse any lease without a per-mission authorization signed by a key the operator holds and the bridge does not | No, on its own — see §4 | Moderate; reuses the run-record signing already built |
| 3 | **Accept it and record it.** Keep the shared secret, make every lease attributable | No. The threat becomes detectable rather than prevented | None. This is today |

**Recommendation: 1, then 2, with 3 shipping and stated honestly until 1 lands.**

Option 1 is also what an OEM deployment looks like anyway — a platform builder embedding the daemon
owns the distro under their own service identity, not under an end user's. Building it is building
the reference deployment, not a detour from it.

---

## 4. Two limits to establish before writing code

**Option 2 does not close this alone, and the reason is not obvious.** The adversary is a Windows
process running as the operator. A per-mission authorization key held *by the operator, on the
operator's machine, under the operator's identity* is readable by that adversary — DPAPI does not
help, because its user scope protects against other users, which is exactly not this threat. Option 2
becomes real only once the key lives somewhere that process cannot reach: behind option 1's second
principal, or in a TPM-bound or hardware-token-held key requiring presence. The threat model already
says option 2 *complements* 1 rather than replacing it; this is why.

**Option 1 excludes a non-administrator operator, not an administrator.** If the operator is a local
admin — the normal case on a developer workstation, the abnormal case on a managed enterprise
endpoint — they can reach another local account's context by other means, and Windows does not treat
administrator-to-SYSTEM as a security boundary. So option 1 buys enforcement in the managed-fleet
deployment and hygiene on a solo developer's own box. That is a fair trade, because the managed fleet
is the buyer, but it must be written down rather than discovered by a licensee's security team.

---

## 5. Step 0 — the ten-minute measurement that can kill option 1

Do this before any code. It is the same shape as the measurement that created this row.

1. Create a second local Windows account, not an administrator.
2. Register a WSL distro under that account.
3. From an unelevated shell **as the operator**, run `wsl.exe -l -v` and
   `wsl.exe -d <that-distro> -u root -e /usr/bin/id`.

**What is being measured:** whether a distro registered to another account is invisible and
unreachable to the operator — WSL keeps its registrations per user — and whether the daemon's
`127.0.0.1:50051` inside that distro is reachable from the operator's own Windows session, since WSL2
localhost forwarding is per user session.

**If the distro is reachable, option 1 collapses and the answer is option 3.** Record the result in
the threat model either way; a negative result is worth as much here as a positive one and costs the
same ten minutes.

---

## 6. The work — option 1

Each step is separately testable. Stop at any boundary and the tree is still green.

1. **A service identity.** A dedicated local account, or a virtual service account with a loadable
   profile. Registered distro under it. `provision --apply` grows a mode that targets it.
2. **The bridge becomes a Windows service** running as that account. It is the only thing that
   speaks to the daemon; the token stops being reachable from the operator's session entirely.
3. **A named pipe between `splat-mcp` and the bridge service**, with an ACL naming who may connect.
   This is where identity becomes answerable at last: a named-pipe server can obtain the token owner
   of the process on the other end, because both ends are Windows processes on one machine — which
   is precisely what neither candidate guest-side transport could do.
4. **Identity moves up to the MCP layer**, where
   [`McpOperatorIdentityProvider`](../src/splat-mcp/McpOperatorIdentityProvider.cs) already lives.
   It already takes a token validator and an API-key validator; the pipe's answer becomes a third
   source of identity, and the ledger row records which one spoke.
5. **`unmount` removes all of it** — service, distro registration, account — the same way it removes
   the boot line. A deployment mode that cannot be undone is not one this product ships.

### Done when

- The step-0 measurement is recorded in [`THREAT-MODEL.md`](THREAT-MODEL.md), with its date.
- A probe check: from the operator's session, reading the token file and reaching the daemon both
  fail, while a lease driven through `splat-mcp` succeeds in the same run. It belongs in
  `native/splat-agent/probe-daemon.sh` beside the existing authentication checks so that
  [`reprove-substrate.ps1`](../packaging/reprove-substrate.ps1) scores it.
- [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md)'s **Caller identity** row says
  what is now excluded and names the administrator limit from §4.
- The roadmap row moves, and the wording constraint in §8 is lifted for the deployment mode that
  earns it — and only for that mode.

---

## 7. The work — option 2, after option 1

Per-mission authorization. The request carries a signature over the mission id, the template, the
argv, the workspace, the egress set and an expiry; the daemon verifies it against a public key pinned
at `/etc/splat/authz.pub` and refuses any lease without one once the key is present. A token taken
from the guest then buys nothing on its own.

Reuse the run-record signing: RSA PKCS#1 v1.5, for the reason roadmap 2.5 already gives — the shipped
Python and PowerShell verifiers check it with their standard libraries alone, and a second primitive
would mean hand-rolled curve arithmetic in three languages for a stranger to trust.

The private key must not be reachable by a process running as the operator, or this is decoration.
See §4.

---

## 8. While this is open

**No part of SPLAT may describe the bridge's authentication as identifying a caller.** It establishes
that the peer holds a secret every process running as the operator can obtain. That sentence is the
honest one and it is already what `SUPPORTED_POLICY.md` says.

This is not a style preference — a test enforces it, and the phrases it refuses are listed in §2.
The reason it is enforced rather than remembered is that the retired facts read as details and get
written back out as plans; the AF_VSOCK one sat in the textbook as a roadmap item for weeks, and the
measurement that retired it took ten seconds.
