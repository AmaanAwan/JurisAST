"""
Tainted Context Extensions for Pydantic AI RunContext.

Provides the dependency payload and context structures threaded through
Pydantic AI's RunContext for all agents in the JurisAST pipeline:

    JurisASTDeps — The primary dependency type for RunContext[JurisASTDeps].
                   Contains the taint registry, agent identity, session tracking,
                   and firewall configuration.

The TaintRegistry from jurisast_core.taint is re-exported here for convenience,
since it's the primary data structure accessed via RunContext.deps.

Design Decision:
    JurisASTDeps is a dataclass (not a Pydantic BaseModel) because:
    - It holds mutable references (TaintRegistry, firewall)
    - Pydantic's frozen validation would prevent runtime updates
    - Dataclasses are lighter-weight for dependency injection
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, List, Optional

from jurisast_core.config import JurisASTConfig
from jurisast_core.labels import LABEL_PUBLIC, SecurityLabel
from jurisast_core.solver import VerificationResult
from jurisast_core.taint import ProvenanceRecord, TaintedValue, TaintRegistry

if TYPE_CHECKING:
    from jurisast_pydantic.capability import JurisASTFirewall


@dataclass
class JurisASTDeps:
    """
    Dependencies injected into every Pydantic AI agent via RunContext[JurisASTDeps].

    This is the central dependency type that threads JurisAST's IFC state through
    the agent pipeline. Every agent in a multi-agent flow receives the same
    JurisASTDeps instance, ensuring shared taint tracking.

    Attributes:
        taint_registry: Session-scoped registry of all tainted values.
        agent_id: Unique identifier for this agent in the pipeline.
        session_id: Unique identifier for this execution session.
        config: JurisAST configuration (mode, solver settings, audit).
        firewall: Optional reference to the JurisASTFirewall capability
                  (set during agent construction).
        audit_log: Accumulated verification results for this session.

    Example:
        >>> from pydantic_ai import Agent, RunContext
        >>> deps = JurisASTDeps(
        ...     taint_registry=TaintRegistry(),
        ...     agent_id="fintech_agent",
        ... )
        >>> agent = Agent("google-gla:gemini-2.5-flash", deps_type=JurisASTDeps)
        >>> @agent.tool
        ... async def my_tool(ctx: RunContext[JurisASTDeps]) -> str:
        ...     registry = ctx.deps.taint_registry
        ...     ...
    """

    taint_registry: TaintRegistry = field(default_factory=TaintRegistry)
    agent_id: str = field(default_factory=lambda: f"agent_{uuid.uuid4().hex[:8]}")
    session_id: str = field(default_factory=lambda: f"session_{uuid.uuid4().hex[:8]}")
    config: JurisASTConfig = field(default_factory=JurisASTConfig)
    firewall: Optional[JurisASTFirewall] = field(default=None)
    audit_log: List[VerificationResult] = field(default_factory=list)

    def register_tainted_value(
        self,
        key: str,
        value: Any,
        label: SecurityLabel,
        source_tool: str,
        details: str | None = None,
    ) -> TaintedValue:
        """
        Create and register a new TaintedValue in the session's taint registry.

        This is the primary API for tool functions to register data they produce
        as tainted. The provenance chain begins with a "create" record.

        Args:
            key: Lookup key (typically tool_name + entity identifier).
            value: The raw data payload.
            label: Security label for the data.
            source_tool: Name of the tool producing this data.
            details: Optional description.

        Returns:
            The created TaintedValue (also registered in the registry).
        """
        tainted = TaintedValue.create(
            value=value,
            label=label,
            source_tool=source_tool,
            agent_id=self.agent_id,
            details=details,
        )
        self.taint_registry.register(key, tainted)
        return tainted

    def get_label_for_args(self, args: dict[str, Any]) -> SecurityLabel:
        """
        Compute the joined label for all tainted values referenced in tool args.

        Delegates to the taint registry's label resolution logic.

        Args:
            args: Tool call arguments dictionary.

        Returns:
            The SecurityLabel that is the join (LUB) of all referenced tainted values,
            or LABEL_PUBLIC if no tainted values are referenced.
        """
        return self.taint_registry.get_label_for_args(args)

    def record_verification(self, result: VerificationResult) -> None:
        """Append a verification result to the session's audit log."""
        self.audit_log.append(result)

    @property
    def verification_count(self) -> int:
        """Number of verification checks performed in this session."""
        return len(self.audit_log)

    @property
    def violation_count(self) -> int:
        """Number of VIOLATION results in this session."""
        return sum(1 for r in self.audit_log if r.status == "VIOLATION")

    @property
    def safe_count(self) -> int:
        """Number of SAFE results in this session."""
        return sum(1 for r in self.audit_log if r.status == "SAFE")
