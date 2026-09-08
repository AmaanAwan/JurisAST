"""
JurisAST Execution Firewall — Core Capability for Pydantic AI.

The JurisASTFirewall is the central enforcement engine that intercepts
every tool call in a Pydantic AI agent pipeline and uses Z3 SMT solving
to formally verify IFC compliance before execution.

Lifecycle:
    1. Agent requests tool execution → firewall.verify_tool_call()
    2. Extract AST IR from tool metadata + taint registry
    3. Encode graph into Z3 constraints
    4. Z3 check() → SAFE / VIOLATION / TIMEOUT
    5. If SAFE → allow execution
       If VIOLATION → block (enforce) / warn (audit) / record (permissive)
    6. After execution → firewall.record_tool_result()
    7. Register new tainted values in the TaintRegistry

Design Decision:
    The firewall operates as a standalone verification engine rather than
    implementing AbstractCapability directly, because:
    - It can be used outside of Pydantic AI (e.g., in tests, scripts)
    - It avoids tight coupling to Pydantic AI version internals
    - The verify_tool_call / record_tool_result API is framework-agnostic
    - Pydantic AI integration is done in agent.py via tool hooks
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Dict, List, Literal, Optional

from jurisast_core.config import JurisASTConfig
from jurisast_core.exceptions import TaintViolationError
from jurisast_core.labels import SecurityLabel
from jurisast_core.solver import VerificationResult, Z3SolverEngine
from jurisast_core.taint import TaintedValue, TaintRegistry

from jurisast_pydantic.decorators import get_jurisast_metadata, get_tool_type
from jurisast_pydantic.extractors import ToolCallExtractor

logger = logging.getLogger("jurisast.firewall")


class JurisASTFirewall:
    """
    The core execution firewall for JurisAST.

    Intercepts tool calls, builds AST IR fragments, encodes them into Z3
    constraints, and verifies IFC compliance before execution.

    Supports three enforcement modes:
        - "enforce": Block violating tool calls (raise TaintViolationError)
        - "audit": Log violations but allow execution
        - "permissive": Record audit entry only (for development)

    Attributes:
        config: JurisAST configuration (mode, solver settings, audit).
        taint_registry: Session-scoped registry of tainted values.
        extractor: Tool call to AST IR extractor.
        audit_log: Ordered list of all verification results.

    Example:
        >>> firewall = JurisASTFirewall(
        ...     config=JurisASTConfig(mode="enforce"),
        ...     taint_registry=TaintRegistry(),
        ...     agent_id="fintech_agent",
        ... )
        >>> # Verify before executing a tool
        >>> result = firewall.verify_tool_call(
        ...     tool_name="send_to_analytics",
        ...     tool_args={"payload": "customer_record_42"},
        ...     tool_callable=send_to_analytics,
        ... )
        >>> if result.status == "SAFE":
        ...     # Execute the tool
        ...     ...
    """

    def __init__(
        self,
        config: JurisASTConfig | None = None,
        taint_registry: TaintRegistry | None = None,
        agent_id: str = "default_agent",
        policies: Any = None,
    ) -> None:
        """
        Initialize the JurisAST firewall.

        Args:
            config: JurisAST configuration. Defaults to enforce mode.
            taint_registry: Shared taint registry. Creates new if None.
            agent_id: ID of the agent this firewall is attached to.
            policies: Optional PolicySet or sequence of PolicySet instances.
        """
        self.config = config or JurisASTConfig()
        self.taint_registry = (
            taint_registry if taint_registry is not None else TaintRegistry()
        )
        self.agent_id = agent_id
        self.policies = policies
        self.extractor = ToolCallExtractor()
        self.audit_log: List[VerificationResult] = []
        self._total_verification_time_ms: float = 0.0

    @property
    def mode(self) -> str:
        """Current enforcement mode."""
        return self.config.mode

    @property
    def total_verification_time_ms(self) -> float:
        """Cumulative Z3 verification time in milliseconds."""
        return self._total_verification_time_ms

    @property
    def stats(self) -> Dict[str, Any]:
        """Firewall statistics for monitoring and profiling."""
        return {
            "mode": self.mode,
            "agent_id": self.agent_id,
            "has_policies": self.policies is not None,
            "total_verifications": len(self.audit_log),
            "safe_count": sum(1 for r in self.audit_log if r.status == "SAFE"),
            "violation_count": sum(
                1 for r in self.audit_log if r.status == "VIOLATION"
            ),
            "timeout_count": sum(
                1 for r in self.audit_log if r.status == "TIMEOUT"
            ),
            "total_verification_time_ms": self._total_verification_time_ms,
            "mean_verification_time_ms": (
                self._total_verification_time_ms / len(self.audit_log)
                if self.audit_log
                else 0.0
            ),
            "taint_registry_size": self.taint_registry.size,
        }

    def verify_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_callable: Callable[..., Any],
    ) -> VerificationResult:
        """
        Verify a tool call against IFC policies before execution.

        This is the primary entry point for the firewall. It:
        1. Extracts an ExecutionGraph fragment from the tool metadata
        2. Creates a Z3 solver and encodes the graph
        3. Compiles and adds regulatory policy constraints (if configured)
        4. Runs verification and returns the result
        5. Enforces the result according to the configured mode

        Args:
            tool_name: Name of the tool being called.
            tool_args: Validated tool call arguments.
            tool_callable: The actual tool function (inspected for metadata).

        Returns:
            VerificationResult with status, latency, and violation details.

        Raises:
            TaintViolationError: If mode is "enforce" and a violation is detected.
        """
        # Step 1: Extract AST IR fragment
        graph = self.extractor.extract(
            tool_name=tool_name,
            tool_args=tool_args,
            tool_callable=tool_callable,
            registry=self.taint_registry,
            agent_id=self.agent_id,
        )

        # Step 2: Build solver and encode
        solver = Z3SolverEngine(
            timeout_ms=self.config.solver.timeout_ms,
        )
        solver.encode_graph(graph)

        # Step 2b: Inject regulatory policies if present
        if self.policies is not None:
            solver.add_policy_constraints(self.policies, graph)

        # Step 3: Verify
        result = solver.verify()

        # Track timing
        self._total_verification_time_ms += result.latency_ms
        self.audit_log.append(result)

        # Step 4: Enforce
        self._enforce_result(result, tool_name, tool_args)

        return result

    def _enforce_result(
        self,
        result: VerificationResult,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> None:
        """
        Apply enforcement action based on the verification result and mode.

        Args:
            result: The verification result from Z3.
            tool_name: Name of the tool for logging.
            tool_args: Tool arguments for logging.

        Raises:
            TaintViolationError: If mode is "enforce" and status is VIOLATION or TIMEOUT.
        """
        if result.status == "SAFE":
            logger.debug(
                "[SAFE] Tool '%s' verified in %.2fms",
                tool_name,
                result.latency_ms,
            )
            return

        if result.status == "VIOLATION":
            violation_msg = (
                f"IFC violation for tool '{tool_name}': "
                + "; ".join(result.violation_details)
            )

            if self.config.mode == "enforce":
                logger.warning("[BLOCKED] %s", violation_msg)
                raise TaintViolationError(
                    violation_msg,
                    violated_constraints=result.violated_constraints,
                    policy_name=(
                        result.violated_constraints[0]
                        if result.violated_constraints
                        else ""
                    ),
                )
            elif self.config.mode == "audit":
                logger.warning("[AUDIT] %s", violation_msg)
            else:  # permissive
                logger.info("[PERMISSIVE] %s", violation_msg)

        elif result.status == "TIMEOUT":
            timeout_msg = (
                f"Z3 solver timeout for tool '{tool_name}' "
                f"after {result.latency_ms:.2f}ms"
            )

            if self.config.mode == "enforce" and self.config.fail_closed:
                logger.warning("[BLOCKED] %s (fail-closed)", timeout_msg)
                raise TaintViolationError(
                    f"{timeout_msg} (fail-closed)",
                    policy_name="solver_timeout",
                )
            elif self.config.mode == "audit":
                logger.warning("[AUDIT] %s", timeout_msg)
            else:
                logger.info("[PERMISSIVE] %s", timeout_msg)

    def record_tool_result(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_result: Any,
        tool_callable: Callable[..., Any],
    ) -> Optional[TaintedValue]:
        """
        After tool execution, register any newly produced tainted values.

        This is called after a tool has executed successfully. For source tools,
        the result is wrapped in a TaintedValue with the label from the decorator
        metadata and registered in the TaintRegistry.

        For non-source tools (transforms, sinks), no new tainted values are
        registered (the existing taint state is sufficient).

        Args:
            tool_name: Name of the executed tool.
            tool_args: Tool call arguments.
            tool_result: The raw result from the tool execution.
            tool_callable: The tool function (inspected for metadata).

        Returns:
            The TaintedValue if one was created (source tools), None otherwise.
        """
        metadata = get_jurisast_metadata(tool_callable)
        if metadata is None:
            return None

        tool_type = metadata.get("type")

        if tool_type == "source":
            # Wrap the result in a TaintedValue and register
            label: SecurityLabel = metadata["label"]
            tainted = TaintedValue.create(
                value=tool_result,
                label=label,
                source_tool=tool_name,
                agent_id=self.agent_id,
                details=f"Retrieved by {tool_name}",
            )
            # Register under the tool name as the primary key
            self.taint_registry.register(tool_name, tainted)

            # Also register under the tool result if it's a string
            # (so downstream tools can reference it by value)
            if isinstance(tool_result, str):
                self.taint_registry.register(tool_result, tainted)

            logger.debug(
                "[REGISTERED] Tool '%s' produced tainted value with label %s",
                tool_name,
                label,
            )
            return tainted

        elif tool_type == "declassifier":
            # Register the declassified result with the downgraded label
            output_label: SecurityLabel = metadata["output_label"]
            tainted = TaintedValue.create(
                value=tool_result,
                label=output_label,
                source_tool=tool_name,
                agent_id=self.agent_id,
                details=f"Declassified by {tool_name} ({metadata.get('max_bits', '?')} bits)",
            )
            self.taint_registry.register(tool_name, tainted)

            if isinstance(tool_result, str):
                self.taint_registry.register(tool_result, tainted)

            logger.debug(
                "[DECLASSIFIED] Tool '%s' produced declassified value with label %s",
                tool_name,
                output_label,
            )
            return tainted

        return None

    def reset(self) -> None:
        """Reset the firewall state, clearing audit log and taint registry."""
        self.audit_log.clear()
        self._total_verification_time_ms = 0.0
        self.taint_registry.clear()
