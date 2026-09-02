"""LangChain/LangGraph tool bindings over the SPLAT substrate.

Every tool returned by :func:`build_splat_tools` uses
``response_format="content_and_artifact"``: the model sees the text payload,
while the :class:`~splat_langgraph.substrate.AuditAnchor` rides in the tool
message's ``artifact`` for your checkpointer to embed. The active LangChain
run id (or an explicit ``splat_trace_id`` in the config metadata) is forwarded
as the SPLAT trace id, so LangSmith traces and SPLAT ledger rows join on one
value.
"""

from __future__ import annotations

from typing import Any

from langchain_core.runnables import RunnableConfig
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from .substrate import SplatSubstrate, SplatToolResult


def _trace_id_from_config(config: RunnableConfig | None) -> str | None:
    """Explicit metadata wins over the ambient run id, so callers can pin a stable id."""
    if not config:
        return None
    metadata = config.get("metadata") or {}
    explicit = metadata.get("splat_trace_id")
    if explicit:
        return str(explicit)
    run_id = config.get("run_id")
    return str(run_id) if run_id else None


def _artifact(result: SplatToolResult) -> dict[str, Any]:
    return {
        "audit_anchor": result.anchor.as_dict() if result.anchor else None,
        "is_error": result.is_error,
    }


class RunCommandArgs(BaseModel):
    command: str = Field(..., description="Executable path inside the sandbox (e.g. /bin/ls, /usr/bin/curl).")
    arguments: str = Field(default="", description="Command arguments.")
    working_directory: str = Field(default="/tmp", description="Working directory inside the sandbox.")
    allow_network: bool = Field(default=False, description="Whether kernel egress is permitted at all.")
    allowed_egress_ips: list[str] = Field(default_factory=list, description="Allow-listed egress IPv4 addresses.")
    timeout_seconds: int = Field(default=30, ge=5, le=300, description="Kernel lease lifespan in seconds.")
    read_only_fs: bool = Field(default=False, description="Mount the sandbox root read-only.")


class RunCodeArgs(BaseModel):
    code: str = Field(..., description="Script source to execute.")
    language: str = Field(default="bash", description="bash, sh, or python3.")
    allow_network: bool = Field(default=False, description="Whether kernel egress is permitted.")
    timeout_seconds: int = Field(default=30, ge=5, le=300, description="Kernel lease lifespan in seconds.")


class DiagnoseSystemArgs(BaseModel):
    template_id: str = Field(..., description="Governed 1:1:1 template id (see list_diagnostic_templates).")
    user_instruction: str = Field(default="", description="Optional directive to guide the analysis.")
    parameters: dict[str, str] = Field(default_factory=dict, description="Template parameter values.")


class InvestigateSystemArgs(BaseModel):
    starting_template_id: str = Field(..., description="Template id the investigation starts from.")
    investigation_goal: str = Field(default="", description="High-level goal or symptom description.")
    max_steps: int = Field(default=3, ge=1, le=5, description="Maximum chained sandboxed steps.")


class RunAgentBrainArgs(BaseModel):
    user_goal: str = Field(..., description="High-level natural-language goal to investigate autonomously.")
    max_reasoning_steps: int = Field(default=3, ge=1, le=5, description="Maximum reasoning steps.")


class RunGovernedCrewArgs(BaseModel):
    crew_id: str = Field(..., description="Crew id from list_governed_crews.")
    parameters: dict[str, str] = Field(default_factory=dict, description="Parameters passed to the crew's tasks.")


class ListTemplatesArgs(BaseModel):
    category: str = Field(default="", description="Optional category filter.")


class SearchIncidentMemoryArgs(BaseModel):
    query: str = Field(..., description="Symptom or incident description to search past diagnoses for.")
    top_k: int = Field(default=5, ge=1, le=20, description="Maximum results.")


def build_splat_tools(substrate: SplatSubstrate) -> list[StructuredTool]:
    """Build the SPLAT toolset bound to one connected substrate session.

    The substrate must be entered (``async with substrate:``) for the whole
    lifetime of any graph run that uses these tools.
    """

    async def run_command(
        command: str,
        arguments: str = "",
        working_directory: str = "/tmp",
        allow_network: bool = False,
        allowed_egress_ips: list[str] | None = None,
        timeout_seconds: int = 30,
        read_only_fs: bool = False,
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "run_command",
            {
                "command": command,
                "arguments": arguments,
                "workingDirectory": working_directory,
                "allowNetwork": allow_network,
                "allowedEgressIps": allowed_egress_ips or [],
                "timeoutSeconds": timeout_seconds,
                "readOnlyFs": read_only_fs,
            },
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    async def run_code(
        code: str,
        language: str = "bash",
        allow_network: bool = False,
        timeout_seconds: int = 30,
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "run_code",
            {
                "code": code,
                "language": language,
                "allowNetwork": allow_network,
                "timeoutSeconds": timeout_seconds,
            },
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    async def diagnose_system(
        template_id: str,
        user_instruction: str = "",
        parameters: dict[str, str] | None = None,
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "diagnose_system",
            {
                "templateId": template_id,
                "userInstruction": user_instruction,
                "parameters": parameters or {},
            },
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    async def investigate_system(
        starting_template_id: str,
        investigation_goal: str = "",
        max_steps: int = 3,
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "investigate_system",
            {
                "startingTemplateId": starting_template_id,
                "investigationGoal": investigation_goal,
                "maxSteps": max_steps,
            },
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    async def run_agent_brain(
        user_goal: str,
        max_reasoning_steps: int = 3,
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "run_agent_brain",
            {"userGoal": user_goal, "maxReasoningSteps": max_reasoning_steps},
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    async def run_governed_crew(
        crew_id: str,
        parameters: dict[str, str] | None = None,
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "run_governed_crew",
            {"crewId": crew_id, "parameters": parameters or {}},
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    async def list_diagnostic_templates(
        category: str = "",
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "list_diagnostic_templates",
            {"category": category} if category else {},
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    async def search_incident_memory(
        query: str,
        top_k: int = 5,
        config: RunnableConfig | None = None,
    ) -> tuple[str, dict[str, Any]]:
        result = await substrate.call_tool(
            "search_incident_memory",
            {"query": query, "topK": top_k},
            trace_id=_trace_id_from_config(config),
        )
        return result.text, _artifact(result)

    def make(coro: Any, name: str, description: str, args_schema: type[BaseModel]) -> StructuredTool:
        return StructuredTool.from_function(
            coroutine=coro,
            name=name,
            description=description,
            args_schema=args_schema,
            response_format="content_and_artifact",
        )

    return [
        make(
            run_command,
            "splat_run_command",
            "Execute a command inside SPLAT's in-kernel BPF-LSM capability lease: hardware CPU/memory"
            " clamps, egress filtering, and a chained audit ledger. Denials surface as -EPERM"
            " containment reports in the output.",
            RunCommandArgs,
        ),
        make(
            run_code,
            "splat_run_code",
            "Execute a bash/sh/python3 script under an ephemeral SPLAT kernel sandbox with full audit chaining.",
            RunCodeArgs,
        ),
        make(
            diagnose_system,
            "splat_diagnose_system",
            "Run one governed 1:1:1 diagnostic template through SPLAT's sandbox, DLP filter, and AI analysis stream.",
            DiagnoseSystemArgs,
        ),
        make(
            investigate_system,
            "splat_investigate_system",
            "Run SPLAT's bounded Reason-Act-Observe investigation loop: multi-step hypothesis testing"
            " across sandboxed governed templates.",
            InvestigateSystemArgs,
        ),
        make(
            run_agent_brain,
            "splat_run_agent_brain",
            "Run SPLAT's cognitive planning engine: goal decomposition, grounded multi-hypothesis"
            " investigation, and remediation formulation with a Merkle ledger commitment.",
            RunAgentBrainArgs,
        ),
        make(
            run_governed_crew,
            "splat_run_governed_crew",
            "Execute a pre-configured governed multi-agent crew under kernel containment, DLP"
            " sanitization, and chained audit ledgers.",
            RunGovernedCrewArgs,
        ),
        make(
            list_diagnostic_templates,
            "splat_list_diagnostic_templates",
            "List SPLAT's pre-approved governed diagnostic templates, optionally filtered by category.",
            ListTemplatesArgs,
        ),
        make(
            search_incident_memory,
            "splat_search_incident_memory",
            "Semantic search over SPLAT's historical incident memory of past diagnoses and remediations.",
            SearchIncidentMemoryArgs,
        ),
    ]
