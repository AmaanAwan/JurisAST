"""
JurisAST Exception Hierarchy.

All exceptions inherit from JurisASTError to enable blanket catching.
Each exception carries structured metadata for audit logging and
debugging, not just a string message.
"""

from __future__ import annotations

from typing import Any, List, Optional


class JurisASTError(Exception):
    """
    Base exception for all JurisAST errors.

    All JurisAST exceptions inherit from this class to enable:
        - Blanket exception handling: `except JurisASTError`
        - Structured metadata on every error for audit logging
        - Integration with Pydantic AI's error handling (SkipToolExecution etc.)
    """

    def __init__(self, message: str, **metadata: Any) -> None:
        super().__init__(message)
        self.metadata = metadata


class TaintViolationError(JurisASTError):
    """
    Raised when a tainted data flow violates an Information Flow Control policy.

    This is the primary enforcement exception. When Z3 determines that an
    execution graph is UNSAT (i.e., the proposed data flow violates a policy
    constraint), this exception is raised to abort the tool execution.

    Attributes:
        data_label: The security label of the data attempting to flow.
        sink_label: The security label / constraints of the target sink.
        policy_name: The name of the violated policy constraint.
        violated_constraints: List of Z3 constraint names from the unsat core.
        z3_model: Optional Z3 counterexample model for debugging.
    """

    def __init__(
        self,
        message: str,
        *,
        data_label: Any = None,
        sink_label: Any = None,
        policy_name: str = "",
        violated_constraints: Optional[List[str]] = None,
        z3_model: Any = None,
    ) -> None:
        super().__init__(
            message,
            data_label=data_label,
            sink_label=sink_label,
            policy_name=policy_name,
        )
        self.data_label = data_label
        self.sink_label = sink_label
        self.policy_name = policy_name
        self.violated_constraints = violated_constraints or []
        self.z3_model = z3_model

    def __str__(self) -> str:
        parts = [f"TaintViolationError: {self.args[0]}"]
        if self.policy_name:
            parts.append(f"  Policy: {self.policy_name}")
        if self.data_label is not None:
            parts.append(f"  Data Label: {self.data_label}")
        if self.sink_label is not None:
            parts.append(f"  Sink Label: {self.sink_label}")
        if self.violated_constraints:
            parts.append(f"  Violated Constraints: {self.violated_constraints}")
        return "\n".join(parts)


class DeclassificationDeniedError(JurisASTError):
    """
    Raised when a declassification request is rejected.

    Declassification can be denied when:
        - The output type exceeds the allowed information budget (max_bits)
        - The declassifier is not registered in the policy as a valid downgrade path
        - The target label is not reachable from the source label via the policy graph
    """

    def __init__(
        self,
        message: str,
        *,
        source_label: Any = None,
        target_label: Any = None,
        max_bits_allowed: Optional[float] = None,
        actual_bits: Optional[float] = None,
    ) -> None:
        super().__init__(
            message,
            source_label=source_label,
            target_label=target_label,
            max_bits_allowed=max_bits_allowed,
            actual_bits=actual_bits,
        )
        self.source_label = source_label
        self.target_label = target_label
        self.max_bits_allowed = max_bits_allowed
        self.actual_bits = actual_bits


class PolicyCompilationError(JurisASTError):
    """
    Raised when a policy definition cannot be compiled to Z3 constraints.

    This typically indicates a malformed policy (e.g., referencing a jurisdiction
    that doesn't exist, or contradictory constraints that make the policy
    trivially unsatisfiable).
    """

    def __init__(
        self,
        message: str,
        *,
        policy_name: str = "",
        constraint_name: str = "",
    ) -> None:
        super().__init__(
            message,
            policy_name=policy_name,
            constraint_name=constraint_name,
        )
        self.policy_name = policy_name
        self.constraint_name = constraint_name


class SolverTimeoutError(JurisASTError):
    """
    Raised when the Z3 SMT solver exceeds its configured timeout.

    In production, this should be treated as a **fail-closed** scenario:
    if we cannot prove the flow is safe within the timeout, we abort the
    execution rather than allowing a potentially unsafe flow.

    Attributes:
        timeout_ms: The configured timeout in milliseconds.
        solver_result: The raw Z3 result string (typically 'unknown').
    """

    def __init__(
        self,
        message: str,
        *,
        timeout_ms: Optional[int] = None,
        solver_result: str = "unknown",
    ) -> None:
        super().__init__(
            message,
            timeout_ms=timeout_ms,
            solver_result=solver_result,
        )
        self.timeout_ms = timeout_ms
        self.solver_result = solver_result


class TaintRegistryError(JurisASTError):
    """
    Raised when there is an error in the taint registry operations.

    This can occur when:
        - Attempting to look up a tainted value that doesn't exist
        - Registering a value with a duplicate key without explicit overwrite
    """

    pass


class ASTConstructionError(JurisASTError):
    """
    Raised when the AST intermediate representation cannot be constructed.

    This can occur when:
        - A tool call references nodes that don't exist in the graph
        - The graph contains cycles (violating DAG property)
        - A node's input references are inconsistent with the graph edges
    """

    pass
