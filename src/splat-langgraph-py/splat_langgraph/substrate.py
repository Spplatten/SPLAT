"""Async client for the SPLAT MCP substrate (the splat-mcp stdio server).

The point of this module is inheritance, not transport: every tool call made
through :class:`SplatSubstrate` executes behind SPLAT's enforcement seam, so a
Python agent gets the Win32 job-object clamps, the WSL2 eBPF-LSM capability
leases, the DLP pass, and the SHA-256 chained audit ledger without any of that
being reimplemented (or trusted) on the Python side.
"""

from __future__ import annotations

import json
from contextlib import AsyncExitStack
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclass(frozen=True)
class AuditAnchor:
    """The ledger chain-head commitment returned with every SPLAT tool result.

    Each ledger entry's hash covers its predecessor, so this single hash
    commits - transitively - to every ledger entry the call produced. Embed it
    in your checkpoint (LangGraph checkpointer state, LangSmith run metadata)
    and the checkpoint becomes cryptographically inseparable from SPLAT's
    kernel-side record of what actually executed: an auditor can later resolve
    ``anchor_hash`` to a ledger row and verify the whole chain beneath it.
    """

    anchor_hash: str
    anchor_entry_id: int
    tool: str | None = None
    trace_id: str | None = None
    timestamp_utc: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SplatToolResult:
    """Primary text payload plus the parsed audit anchor, if the server sent one."""

    text: str
    anchor: AuditAnchor | None
    is_error: bool


def parse_anchor(item_text: str | None) -> AuditAnchor | None:
    """Parse one MCP content item as an auditAnchor metadata item, or return None.

    The server appends the anchor as the LAST content item; anything that is
    not a JSON object with an ``auditAnchor`` key is ordinary payload.
    """
    if not item_text:
        return None
    try:
        payload = json.loads(item_text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or "auditAnchor" not in payload:
        return None
    anchor = payload["auditAnchor"]
    if not isinstance(anchor, dict) or "anchorHash" not in anchor:
        # anchorError shape: the server ran the tool but could not anchor it.
        return None
    return AuditAnchor(
        anchor_hash=anchor["anchorHash"],
        anchor_entry_id=int(anchor.get("anchorEntryId", -1)),
        tool=anchor.get("tool"),
        trace_id=anchor.get("traceId"),
        timestamp_utc=anchor.get("timestampUtc"),
    )


class SplatSubstrate:
    """One stdio session to a splat-mcp server, usable as an async context manager.

    Example::

        substrate = SplatSubstrate(
            command="C:/C_AGENT_BUILDER/dist/App/splat-mcp.exe")
        async with substrate:
            result = await substrate.call_tool(
                "run_command", {"command": "/bin/ls"}, trace_id=run_id)
            print(result.text, result.anchor)
    """

    def __init__(
        self,
        command: str,
        args: list[str] | None = None,
        env: Mapping[str, str] | None = None,
        client_name: str = "langgraph",
    ) -> None:
        self._params = StdioServerParameters(
            command=command,
            args=list(args or []),
            env=dict(env) if env is not None else None,
        )
        self._client_name = client_name
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    @classmethod
    def from_dotnet_project(cls, project_dir: str, **kwargs: Any) -> "SplatSubstrate":
        """Development-mode launcher: ``dotnet run --project <splat-mcp dir>``."""
        return cls(command="dotnet", args=["run", "--project", project_dir], **kwargs)

    async def __aenter__(self) -> "SplatSubstrate":
        self._stack = AsyncExitStack()
        read, write = await self._stack.enter_async_context(stdio_client(self._params))
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        trace_id: str | None = None,
    ) -> SplatToolResult:
        """Call one SPLAT tool, correlating ``trace_id`` into the audit ledger.

        The trace id lands in a ledger row (action ``EXTERNAL_TRACE_CORRELATED``)
        written after the tool ran, and the returned anchor commits to that row.
        """
        if self._session is None:
            raise RuntimeError("SplatSubstrate is not connected; use 'async with substrate:'.")

        args: dict[str, Any] = dict(arguments)
        if trace_id:
            args["traceId"] = str(trace_id)
        args.setdefault("clientName", self._client_name)

        result = await self._session.call_tool(name, args)
        texts = [c.text for c in result.content if getattr(c, "type", None) == "text"]

        anchor = parse_anchor(texts[-1]) if texts else None
        payload_texts = texts[:-1] if anchor is not None else texts

        return SplatToolResult(
            text="\n".join(t for t in payload_texts if t),
            anchor=anchor,
            is_error=bool(result.isError),
        )
