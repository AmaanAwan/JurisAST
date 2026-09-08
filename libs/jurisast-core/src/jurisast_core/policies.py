"""
Regulatory Policy Engine for JurisAST.

Enables formal specification of cross-border data sovereignty, privacy,
and AI governance regulations (GDPR, EU AI Act, PCI-DSS, etc.) as declarative
policy sets that compile directly into Z3 first-order logic constraints.

Architecture:
    FlowConstraint:
        A declarative specification of permitted or forbidden information flows
        based on source/sink jurisdictions, classifications, and compartments.
    PolicySet:
        A collection of FlowConstraints representing a regulatory framework
        (e.g., GDPR_DATA_SOVEREIGNTY). Compiles against an ExecutionGraph
        into assumption-gated Z3 formulas with unsat core attribution.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Literal, Optional, Set

from pydantic import BaseModel, Field
from z3 import And, Bool, Not, Or

from jurisast_core.labels import Classification, Jurisdiction

if TYPE_CHECKING:
    from jurisast_core.ast_ir import ExecutionGraph
    from jurisast_core.solver import Z3SolverEngine


class ConstraintAction(str, Enum):
    """
    Action to take when an information flow constraint matches.

    Attributes:
        BLOCK: Immediately fail verification (raises TaintViolationError).
        DECLASSIFY_REQUIRED: Flow is blocked unless it traverses a valid DeclassifyNode.
        AUDIT: Record flow in audit trail without failing verification.
    """

    BLOCK = "BLOCK"
    DECLASSIFY_REQUIRED = "DECLASSIFY_REQUIRED"
    AUDIT = "AUDIT"


class FlowConstraint(BaseModel):
    """
    A single regulatory information flow constraint.

    Defines conditions under which data from specific source jurisdictions
    or classifications is restricted from reaching specific destination sinks.

    Examples:
        >>> # GDPR Article 44: EU PII cannot flow to US external sinks
        >>> constraint = FlowConstraint(
        ...     name="eu_pii_no_us_transfer",
        ...     description="EU PII/Sensitive PII cannot flow to US sinks",
        ...     regulation="GDPR Article 44",
        ...     source_jurisdictions={Jurisdiction.EU},
        ...     source_classification_min=Classification.PII,
        ...     forbidden_sink_jurisdictions={Jurisdiction.US, Jurisdiction.EXTERNAL},
        ...     action=ConstraintAction.BLOCK,
        ... )
    """

    name: str = Field(
        description="Unique identifier for this constraint within a policy set.",
    )
    description: str = Field(
        description="Human-readable explanation of the regulatory requirement.",
    )
    regulation: str = Field(
        default="",
        description="Statutory reference (e.g., 'GDPR Art. 44', 'EU AI Act Art. 10').",
    )
    source_jurisdictions: Optional[Set[Jurisdiction]] = Field(
        default=None,
        description="Set of source jurisdictions subject to this constraint. None matches any.",
    )
    source_classification_min: Optional[Classification] = Field(
        default=None,
        description="Minimum sensitivity classification level that triggers this constraint.",
    )
    forbidden_sink_jurisdictions: Optional[Set[Jurisdiction]] = Field(
        default=None,
        description="Set of destination sink jurisdictions forbidden to receive this data.",
    )
    sink_classification_max: Optional[Classification] = Field(
        default=None,
        description="Maximum classification the destination sink is permitted to receive.",
    )
    forbidden_compartments: Optional[FrozenSet[str]] = Field(
        default=None,
        description="Compartments strictly forbidden from reaching the matched sink.",
    )
    required_compartments: Optional[FrozenSet[str]] = Field(
        default=None,
        description="Compartments that MUST be present on the data flowing into the sink.",
    )
    allow_declassified: bool = Field(
        default=True,
        description="Whether a valid DeclassifyNode upstream permits the flow.",
    )
    action: ConstraintAction = Field(
        default=ConstraintAction.BLOCK,
        description="Enforcement action when flow matches this constraint.",
    )

    model_config = {"frozen": True}

    def matches_sink(self, target_jurisdiction: Jurisdiction, max_classification: Classification) -> bool:
        """Check if a sink's attributes trigger this constraint."""
        if self.forbidden_sink_jurisdictions is not None:
            if target_jurisdiction in self.forbidden_sink_jurisdictions:
                return True
        if self.sink_classification_max is not None:
            if max_classification > self.sink_classification_max:
                return True
        return False


class PolicySet(BaseModel):
    """
    A collection of flow constraints forming a complete regulatory compliance framework.

    Compiles declarative policy constraints into Z3 first-order logic expressions
    gated on assumption literals for assumption-based incremental solving and
    unsat core extraction.

    Examples:
        >>> policy = PolicySet(
        ...     policy_name="GDPR_SOVEREIGNTY",
        ...     version="1.0.0",
        ...     description="EU GDPR cross-border transfer protections",
        ...     constraints=[...],
        ... )
    """

    policy_name: str = Field(
        description="Unique name of the policy set (e.g., 'GDPR_DATA_SOVEREIGNTY').",
    )
    version: str = Field(
        default="1.0.0",
        description="Semantic version of this policy specification.",
    )
    description: str = Field(
        default="",
        description="Summary of the regulatory scope and guarantees.",
    )
    constraints: List[FlowConstraint] = Field(
        default_factory=list,
        description="List of flow constraints in this policy set.",
    )

    def add_constraint(self, constraint: FlowConstraint) -> None:
        """Add a constraint to this policy set."""
        self.constraints.append(constraint)

    def get_constraint(self, name: str) -> Optional[FlowConstraint]:
        """Retrieve a constraint by its name."""
        for c in self.constraints:
            if c.name == name:
                return c
        return None

    def compile_to_z3(
        self,
        graph: ExecutionGraph,
        solver: Z3SolverEngine,
    ) -> List[str]:
        """
        Compile all policy constraints against the execution graph into Z3 assertions.

        Each constraint is encoded as an implication gated on a named assumption literal:
            assumption_literal → (safe_flow_condition)

        If the flow violates the regulatory constraint, Z3 returns UNSAT and the
        unsat core includes the assumption literal, identifying the exact
        regulation, constraint, and graph node in human-readable output.

        Args:
            graph: The ExecutionGraph to analyze.
            solver: The Z3SolverEngine where constraints will be registered.

        Returns:
            List of generated assumption literal names.
        """
        registered_assumptions: List[str] = []

        sinks = graph.get_sinks()
        if not sinks:
            return registered_assumptions

        for constraint in self.constraints:
            # Audit constraints are monitored separately, not asserted as hard blockers
            if constraint.action == ConstraintAction.AUDIT:
                continue

            for sink in sinks:
                # Check if this sink is targeted by the constraint
                if not constraint.matches_sink(sink.target_jurisdiction, sink.max_classification):
                    continue

                for input_id in sink.input_node_ids:
                    ij, ic = solver._get_or_create_vars(input_id)
                    assumption_name = (
                        f"policy__{self.policy_name}__{constraint.name}__{input_id}__to__{sink.node_id}"
                    )

                    # Build Z3 violation conditions
                    conditions = []

                    # 1. Jurisdiction condition
                    if constraint.source_jurisdictions:
                        j_conditions = [ij == j.value for j in constraint.source_jurisdictions]
                        conditions.append(Or(*j_conditions) if len(j_conditions) > 1 else j_conditions[0])

                    # 2. Classification condition
                    if constraint.source_classification_min is not None:
                        conditions.append(ic >= constraint.source_classification_min.value)

                    # If no specific conditions, any incoming flow violates
                    if not conditions:
                        violation_expr = Bool(f"viol_{assumption_name}")
                        solver._solver.add(violation_expr == True)  # noqa: E712
                    elif len(conditions) == 1:
                        violation_expr = conditions[0]
                    else:
                        violation_expr = And(*conditions)

                    # Invariant: the violation condition must NOT hold
                    safe_formula = Not(violation_expr)

                    # Check compartment restrictions statically if present
                    if constraint.forbidden_compartments:
                        input_node = graph.get_node(input_id)
                        # Check if this input node carries forbidden compartments
                        node_label = getattr(input_node, "output_label", None) or getattr(
                            input_node, "label", None
                        )
                        if node_label and hasattr(node_label, "compartments"):
                            if node_label.compartments & constraint.forbidden_compartments:
                                # Unconditionally violated for this input
                                false_bool = Bool(f"comp_violation_{assumption_name}")
                                solver._solver.add(Not(false_bool))
                                safe_formula = false_bool

                    desc = (
                        f"[{constraint.regulation}] {constraint.description}: "
                        f"Flow from '{input_id}' to sink '{sink.node_id}' ({sink.tool_name}) "
                        f"violates sovereignty policy '{self.policy_name}'"
                    )

                    solver.add_custom_constraint(
                        name=assumption_name,
                        constraint=safe_formula,
                        description=desc,
                    )
                    registered_assumptions.append(assumption_name)

        return registered_assumptions
