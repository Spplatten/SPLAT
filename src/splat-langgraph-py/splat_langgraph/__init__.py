"""splat-langgraph: LangGraph/LangChain tools over SPLAT's kernel-contained substrate.

Python agents keep their own graph; SPLAT stays the enforcement layer. Every
call crosses the MCP seam and inherits the job objects, eBPF-LSM leases, DLP
pass, and SHA-256 chained audit ledger, and comes back carrying an
:class:`AuditAnchor` chain-head commitment for checkpoint anchoring.
"""

from .substrate import AuditAnchor, SplatSubstrate, SplatToolResult, parse_anchor
from .tools import build_splat_tools

__all__ = [
    "AuditAnchor",
    "SplatSubstrate",
    "SplatToolResult",
    "build_splat_tools",
    "parse_anchor",
]
