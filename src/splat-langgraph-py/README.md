# splat-langgraph

LangGraph/LangChain tools that execute inside **SPLAT's kernel-contained substrate** over MCP.

Your Python agent keeps its own graph, checkpointer, and tracing. SPLAT stays the enforcement
layer: every tool call crosses the `splat-mcp` seam and inherits — without reimplementing or
trusting anything on the Python side —

- **Win32 job-object clamps** (CPU/memory/PID quotas) and restricted-token launches,
- **WSL2 eBPF-LSM capability leases** (in-kernel `-EPERM` on unleased files and egress),
- the **DLP sanitization pass** over tool output,
- the **SHA-256 chained audit ledger** (non-repudiation for every execution).

A prompt-injected agent that talks a model into `curl evil.example` still hits the kernel deny:
the lease, not the prompt, decides.

## Install

```bash
pip install -e src/splat-langgraph-py
```

## Quickstart

```python
import asyncio
from langgraph.prebuilt import create_react_agent
from splat_langgraph import SplatSubstrate, build_splat_tools

async def main():
    substrate = SplatSubstrate(command="path/to/splat-mcp.exe")
    # Dev mode instead: SplatSubstrate.from_dotnet_project("src/splat-mcp")

    async with substrate:
        agent = create_react_agent("anthropic:claude-sonnet-5", build_splat_tools(substrate))
        result = await agent.ainvoke(
            {"messages": [("user", "Check DNS health and investigate anything abnormal.")]}
        )
        print(result["messages"][-1].content)

asyncio.run(main())
```

## Trace correlation (LangSmith / OpenTelemetry ↔ SPLAT ledger)

Each tool call forwards a trace id — the active LangChain `run_id`, or an explicit
`splat_trace_id` in the config metadata:

```python
await agent.ainvoke(inputs, config={"metadata": {"splat_trace_id": "incident-4711"}})
```

SPLAT writes an `EXTERNAL_TRACE_CORRELATED` row into the chained audit ledger *after* the tool
ran, recording tool name, trace id, client, and outcome. Auditors join a LangSmith trace to the
kernel-side execution record on that one value.

## Audit anchoring (checkpoint ⇄ Merkle chain)

Every result carries an `AuditAnchor` — the ledger's chain-head hash at response time. Because
each ledger entry's hash covers its predecessor, that single hash commits to every entry the call
produced. The tools return it as the LangChain tool **artifact**:

```python
tool_msg = result["messages"][-2]          # the ToolMessage
anchor = tool_msg.artifact["audit_anchor"]  # {"anchor_hash": "...", "anchor_entry_id": 42, ...}
```

Persist it in your checkpointer state and the checkpoint becomes cryptographically inseparable
from SPLAT's record of what actually executed: rolling back to step *N* later, you can prove
which sandboxed executions — stdout, verdicts, kernel violations — that step was derived from.
When a trace id was supplied, the anchored row *is* the trace-correlation row.

## Tools

| Tool | SPLAT capability |
| --- | --- |
| `splat_run_command` | Arbitrary command under an in-kernel BPF-LSM lease |
| `splat_run_code` | bash/sh/python3 script in an ephemeral sandbox |
| `splat_diagnose_system` | One governed 1:1:1 diagnostic template + AI analysis |
| `splat_investigate_system` | Bounded Reason-Act-Observe investigation loop |
| `splat_run_agent_brain` | Goal decomposition + grounded multi-hypothesis reasoning |
| `splat_run_governed_crew` | Pre-configured governed multi-agent crew |
| `splat_list_diagnostic_templates` | Governed template catalog |
| `splat_search_incident_memory` | Semantic search over past incidents |
