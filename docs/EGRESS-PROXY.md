# Per-lease hostname egress proxy (design)

**This page is a plan. Nothing in it is built.** No row of
[SUPPORTED_POLICY.md](../native/splat-agent/SUPPORTED_POLICY.md) changes until a root run proves
what is built from this page. That run belongs to the v1 proof run, not to this work.

## What is missing today

Read from the source on 2026-11-13, not measured:

- Leased work reaches only the IPv4 `address:port` pairs the operator pinned
  (`splat-mcp --egress`, the ceiling's `allowedEgress`). A request can only narrow that list.
- There is no name resolution. A DNS query is a datagram destination like any other, and nothing
  adds a resolver. IPv6 is denied outright.
- So `pip`, `npm`, `git` and any fetch from a CDN fail: their addresses rotate, and a pinned
  address is stale by the time it is written down.
- Separately, an agent app's own shell and web tools never pass through SPLAT. SPLAT ships
  nothing that turns them off.

## The rule

**A lease that names hostnames reaches the network only through a proxy the daemon runs for that
lease alone, and the proxy carries a connection only to a hostname the operator's policy lists.**

- **One listener per lease.** The daemon binds `127.0.0.1:<port>` for each lease, from a pool of
  `LEASE_CAPACITY` (256) ports, handed out and reclaimed like the lease UID pool. The proxy runs
  inside the daemon, which is in no leased cgroup, so its own outbound connections are not judged.
- **The kernel admits only that listener.** The lease's entry in `allowed_connect_ipv4` is exactly
  `(its cgroup, 127.0.0.1, its port)`. The map is already keyed by cgroup, so a second lease that
  dials the first lease's port is refused by the existing hook. **No BPF source changes**, and the
  recorded BPF hash stays the one that was proven.
- **Hostnames and pinned addresses do not mix.** A request names `allowedEgressHosts` or
  `allowedEgressIps`, never both. One that names both is refused before a cgroup exists.
- **The daemon sets the environment.** `HTTPS_PROXY`, `HTTP_PROXY` and their lower-case forms
  point at the lease's listener. A request still cannot set a proxy variable itself.
- **CONNECT only.** The proxy accepts `CONNECT host:port` and nothing else. Plain-HTTP forwarding
  is not in this version.
- **Three checks per connection, in order:**
  1. `host:port` is in the lease's list. The lease's list must sit inside the operator's.
  2. The proxy resolves the name itself and connects to the address it resolved. A loopback,
     private, link-local or otherwise non-public address is refused, so a name cannot be pointed
     at the guest, the Windows host or another lease's listener.
  3. The first bytes from the tool must be a TLS ClientHello whose SNI equals the CONNECT
     hostname. Anything else closes the connection before a byte is forwarded.
- **The lease ends, the proxy ends.** Revoking the lease closes the listener and every connection
  it carries, and returns the port to the pool.

## The operator's policy

- `splat-mcp --egress-host name[:port]`, repeated. The port defaults to 443.
- The ceiling file gains `allowedEgressHosts`, written by `splat-mcp provision --apply`. Absent
  means no lease may name a hostname. Hostname egress is off until the operator turns it on.
- An entry is an exact name or `*.suffix`. A wildcard matches one or more whole labels below the
  suffix and never the suffix itself. Names are lower-cased ASCII; anything else is refused when
  the policy is read, not skipped.
- A request names `allowedEgressHosts`, each of which must match an operator entry. Omitted with
  `allowNetwork` true and no `allowedEgressIps`, it is refused: a missing key is not a default.

## The receipt

- The signed outcome gains two fields, appended after the existing ones:
  `egressHosts` (every `host:port` the proxy carried, sorted, comma-joined) and `egressRefused`
  (the count of connections it turned away).
- They appear only for a lease that had a proxy. Every other lease signs the same bytes as today.
- A lease may carry at most 64 distinct `host:port` pairs. The 65th is refused and counted. The
  list in the receipt is therefore complete by construction, never truncated.
- The unsigned EXIT frame also lists each refusal with its reason, for the operator to read.
- The C# receipt reader accepts the longer field set and stores both fields in the run record.

## The client profile

`packaging/client-profiles/` ships one settings file per supported agent app, plus one page saying
where each goes. The first is Claude Code: a managed-settings file that denies its built-in shell,
web fetch and web search tools, leaving the SPLAT MCP tools as the only way to run or fetch.

**What a profile is not:** enforcement. It is configuration of someone else's program. SPLAT
cannot observe whether it is installed, and the receipt says nothing about it.

## What stays open

- **Domain fronting.** The proxy sees the hostname in CONNECT and in SNI. Inside TLS a tool can
  send a different `Host` to a CDN that serves many names. Closing that means terminating TLS,
  which means a SPLAT root certificate in every lease. Not in this version.
- **An allowed host is a channel.** Anything a lease can read, it can send to a host on its list.
  The receipt names the host; it does not say what went there.
- **Tools that ignore the proxy variables** get no network at all. That fails closed.
- **Encrypted ClientHello** hides the true name. The proxy refuses a ClientHello that carries the
  ECH extension.
- **DNS is the daemon's resolver.** A poisoned answer still has to be a public address, and the
  server still has to pass the tool's own certificate check.

## Proving it

Without root, in the daemon's own test suite, against listeners on loopback:
- policy parsing and matching, including every wildcard edge;
- the CONNECT parser, the SNI parser and the ECH refusal, on captured and malformed bytes;
- the address filter;
- a full proxied connection in non-enforcing mode, and the receipt fields it produces;
- the port pool: exhaustion, reuse after revoke.

Under root, in the v1 proof run:
- a leased tool reaches an allowed host through the proxy;
- the same tool is refused a direct connection to that host's address;
- lease A is refused lease B's proxy port;
- the signed receipt lists the host, and verifies.

## Order of work

1. Policy parsing in the ceiling, and the request field.
2. The proxy module and the port pool.
3. Lease wiring: the map entry, the environment, teardown.
4. The receipt fields, daemon and C#.
5. `splat-mcp --egress-host` and the tool schema.
6. The client profile.
