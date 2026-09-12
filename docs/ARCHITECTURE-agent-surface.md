<!-- Companion to ARCHITECTURE.md. Covers every way an external agent reaches SPLAT: the splat-mcp
     server, the splat-langgraph adapter over it, and the Copilot / Semantic Kernel adapter in
     Infrastructure.Windows. The operator console is a host rather than an agent surface;
     ARCHITECTURE.md compares the two hosts. Read out of the tree at 0027e57 on 2026-09-10. -->

# Agent surface — how an external agent gets in

An agent decides what is safe to attempt from what it is told, so the surface is part of the
security model: a tool whose description overstates its containment invites exactly the request it
cannot contain. The rule on this surface is that each tool says which layer enforces it, and says
so plainly when the answer is "user space" or "nothing".

## `splat-mcp`

[`src/splat-mcp`](../src/splat-mcp) — a Model Context Protocol server, `net10.0-windows`, spawned by
its client and spoken to over stdio.

**Process model.** [`Program.cs`](../src/splat-mcp/Program.cs) wires every dependency by hand — the
comparison with the console is in [ARCHITECTURE.md](ARCHITECTURE.md#two-hosts-one-pipeline) — then
reads one JSON-RPC message per line from stdin and writes one response per line to stdout. It
answers `initialize`, `notifications/initialized`, `ping`, `tools/list` and `tools/call`; an
unparseable line gets `-32700` and an unknown method `-32601`; a line over 1 MiB gets `-32700` too,
refused before it is buffered, after which the reader skips to the next newline and the session
carries on — a stdio client has no second connection to reopen. `Main` settles its command line
before it builds anything ([`McpServerCommand`](../src/splat-mcp/McpServerCommand.cs)):
`--workspace <dir>` names the one directory `fs_read` and `fs_write` may touch, which must already
exist and is never created; without it the root is `%LOCALAPPDATA%\SPLAT\mcp-workspace`, named on
stderr at startup. `--egress a.b.c.d:port,...` names the only endpoints a `run_command` or
`run_code` lease may connect to, checked by [`McpEgressPolicy`](../src/splat-mcp/McpEgressPolicy.cs);
without it neither tool gets network. A bad option or a malformed list exits 2 with nothing built, and stdout carries only JSON-RPC —
written without the UTF-8 byte order mark it carried until 2026-09-11. `splat-mcp doctor` reports what this host will enforce — kernel, boot command line, daemon,
token — and exits 0 only when a lease would reach the kernel; its summary of a lease is copied
from [`SUPPORTED_POLICY.md`](../native/splat-agent/SUPPORTED_POLICY.md) and bound to it by a
test. It ships as one self-contained executable from
[`packaging/publish-splat-mcp.ps1`](../packaging/publish-splat-mcp.ps1), which refuses to report
success on a non-zero publish, a missing output, a stray file beside the executable, or a result
that cannot print its usage. There is no `dotnet tool` package: `PackAsTool` rejects the platform
target framework this project needs (NETSDK1146). First-run provisioning is the rest of P1 in
[the roadmap](ROADMAP.md).

**Identity before effects.** `HandleToolsCallAsync` resolves the actor before it dispatches, so a
refused credential reaches no executor and no file.
[`McpOperatorIdentityProvider`](../src/splat-mcp/McpOperatorIdentityProvider.cs) names the Windows
logon session the server runs under, tagged with the transport — a stdio server runs in its
client's own session, so there is no second principal to authenticate. When
`SPLAT_MCP_CLIENT_CREDENTIAL` is set it is validated as a JWT or an API key, and a credential that
fails refuses the call with `-32001` rather than falling back to an anonymous row.

**The tools, by what enforces them** — [`McpServerHandler.cs`](../src/splat-mcp/McpServerHandler.cs):

| Tool | Runs | Enforced by |
| --- | --- | --- |
| `run_command` | Builds a lease inline and calls `ILeasedExecutor` | The Linux lease daemon — see [who authors which half of the lease](ARCHITECTURE-linux-substrate.md#who-authors-a-lease-today). A run from here into the daemon is recorded in [`last-hop-probe.json`](../native/splat-agent/evidence/last-hop-probe.json) |
| `run_code` | A pattern pre-flight, then `run_command` with `/usr/bin/python3`, `/bin/sh` or `/bin/bash` and `argv = ["-c", code]` | As `run_command`. The pre-flight, [`DynamicCodeAstValidator`](../src/MissionController.Core/DynamicCodeAstValidator.cs), is regular expressions despite its name — a filter, not a boundary |
| `fs_read`, `fs_write` | [`WorkspaceGuard`](../src/splat-mcp/WorkspaceGuard.cs) | User space. Containment is judged on the path the kernel reports for the opened **handle**, and that same handle does the read or write, so a junction or symlink inside the workspace cannot redirect it. Refusals say they are a policy check, not a kernel denial |
| `diagnose_system` | `IMissionExecutionEngine` | The full Windows pipeline — [control plane](ARCHITECTURE-control-plane.md), [Windows substrate](ARCHITECTURE-windows-substrate.md) |
| `investigate_system` | `GovernedInvestigationLoop` | A chain of complete missions |
| `run_agent_brain` | `AgentBrainEngine` | Missions chosen by goal decomposition |
| `run_governed_crew` | `GovernedCrewEngine` | A mission per templated task. Besides `crewId`, the handler accepts an inline `crewDefinition` that the published schema does not advertise; `GovernedCrewParser` validates it, and it can run tools only through catalog templates — its other tasks are model calls with the prompts it supplies |
| `get_substrate_health` | `WslSubstrateHealthChecker` | Read-only; reports the daemon's `enforcing` field. Authenticated like every other request to the daemon, so a host that cannot read the token reports "reachable, refused" rather than an absent daemon |
| `list_diagnostic_templates`, `search_incident_memory`, `list_governed_crews` | The template registry, semantic memory, the crew catalog | Read-only |

**Every result carries an audit anchor.** After the tool runs, `AttachAuditAnchorAsync` appends a
final content item — `{"auditAnchor": {anchorHash, anchorEntryId, traceId, tool, timestampUtc}}` —
naming the ledger's head entry at that moment. Each entry's hash covers its predecessor, so that one
hash commits to everything the call wrote. When the caller passes `traceId`, and optionally
`clientName`, an `EXTERNAL_TRACE_CORRELATED` row recording the outcome is written first, so a
LangSmith or OpenTelemetry trace joins the ledger on one value. If anchoring fails, the result says
so instead of silently omitting it. The anchor points into this host's own ledger,
`%LOCALAPPDATA%\SPLAT\audit_ledger.db`.

**What this host does not have:** a revocation check before a mission (its engine is constructed
with `null`), a remediation engine, or a crew registry beyond the built-in catalog. Its ledger and
incident memory are separate from the console's.

## `splat-langgraph`

[`src/splat-langgraph-py`](../src/splat-langgraph-py) — a Python package, `splat_langgraph`, that
starts `splat-mcp` as an MCP stdio subprocess and offers its tools to LangChain and LangGraph.
Nothing is enforced on the Python side: everything a tool call inherits, it inherits by crossing
the `splat-mcp` seam.

- [`substrate.py`](../src/splat-langgraph-py/splat_langgraph/substrate.py) — `SplatSubstrate`, the
  async client (`SplatSubstrate.from_dotnet_project("src/splat-mcp")` in development), and the
  parsing of the audit anchor out of a result's last content item.
- [`tools.py`](../src/splat-langgraph-py/splat_langgraph/tools.py) — `build_splat_tools` wraps
  eight of the twelve tools; the `fs_*` pair, `get_substrate_health` and `list_governed_crews` are
  not exposed. Each call forwards a trace id — the LangChain `run_id`, or `splat_trace_id` from the
  run's metadata — and returns the anchor as the tool's artifact, so a checkpointer can persist it.

The solution does not build it, and this repository has no tests for it.

## The Copilot / Semantic Kernel adapter

[`src/MissionController.Infrastructure.Windows/Copilot`](../src/MissionController.Infrastructure.Windows/Copilot)
— for a host that runs Microsoft Copilot or Semantic Kernel tool calls and wants them governed.

- [`CopilotSafetySubstrate`](../src/MissionController.Infrastructure.Windows/Copilot/CopilotSafetySubstrate.cs)
  (`ICopilotSafetySubstrate`) evaluates the call against a `CopilotSafetyPolicy` through
  [`CopilotSafetyPolicyEngine`](../src/MissionController.Infrastructure.Windows/Copilot/CopilotSafetyPolicyEngine.cs);
  a denial seals `COPILOT_POLICY_BLOCKED` and returns. A permitted call has its arguments
  DLP-scrubbed and then runs one of two ways. By default, through `IProcessLauncher` under a job
  object — with the restricted token when the policy asks for it — in the caller's working
  directory when that exists and a fresh jail otherwise. When the call prefers it and an
  `ILeasedExecutor` was supplied, under a Linux lease. Either way it seals `COPILOT_TOOL_SUCCESS` or
  `COPILOT_TOOL_FAILED`, and it can stream to Microsoft Sentinel through
  [`SentinelCopilotTelemetryBridge`](../src/MissionController.Infrastructure.Windows/Copilot/SentinelCopilotTelemetryBridge.cs).
- [`SplatCopilotInvocationFilter`](../src/MissionController.Infrastructure.Windows/Copilot/SplatCopilotInvocationFilter.cs)
  and [`SplatCopilotPlugin`](../src/MissionController.Infrastructure.Windows/Copilot/SplatCopilotPlugin.cs)
  are shaped for Semantic Kernel's filter and plugin model, but the project takes no Semantic Kernel
  package; a host adapts them.
  [`SemanticKernelExtensions.AddSplatCopilotSafety`](../src/MissionController.Infrastructure.Windows/Copilot/SemanticKernelExtensions.cs)
  registers the set in a host's container. The plugin's workspace is
  `%LOCALAPPDATA%\SPLAT\copilot-workspace`.

Limits of the current code, all of which fail closed or stay dormant rather than open: the Windows
path launches without AppContainer network denial; the Linux path builds its lease with an
**empty** exec allow-list, which the daemon treats as "nothing permitted" and refuses — and no
shipped composition supplies an `ILeasedExecutor`, so that path is unreachable today. The console
registers the substrate, but no screen uses it. Tests:
[`CopilotSafetySubstrateTests`](../tests/MissionController.Tests/CopilotSafetySubstrateTests.cs).
