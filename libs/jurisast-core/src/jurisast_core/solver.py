"""
Z3 SMT Solver Engine for Information Flow Control Verification.

Maps ExecutionGraph → Z3 first-order logic formulas and proves non-interference.

Architecture:
    The solver uses **assumption-based incremental solving** — the fastest Z3 pattern:
    - Constraints are added once to the solver
    - Each verification query uses assumption literals passed to check()
    - Learned lemmas are preserved across checks (unlike push/pop)
    - Unsat cores identify exactly which assumptions (= policy constraints) were violated

The core invariant being verified:
    ∀ source → sink path in the graph:
        source.jurisdiction ≤ sink.target_jurisdiction AND
        source.classification ≤ sink.max_classification

    UNLESS a valid DeclassifyNode exists on the path, in which case the
    declassified label replaces the source label for downstream checks.

Performance Target:
    - Typical solve time: < 5ms for graphs with ≤ 50 nodes
    - Worst case: < 50ms (hard timeout)
    - This is 40-400x faster than an LLM-as-a-Judge guardrail call
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field
from z3 import (
    And,
    Bool,
    BoolSort,
    Const,
    DeclareSort,
    Function,
    Implies,
    Int,
    IntSort,
    Not,
    Or,
    Solver,
    sat,
    unknown,
    unsat,
)

from jurisast_core.ast_ir import (
    AgentHandoffNode,
    ASTNode,
    ChatOutputSinkNode,
    DataSourceNode,
    DeclassifyNode,
    ExecutionGraph,
    HumanAttestedDeclassifyNode,
    ProjectionNode,
    SinkNode,
    TransformNode,
)
from jurisast_core.exceptions import SolverTimeoutError, TaintViolationError
from jurisast_core.labels import Classification, Jurisdiction


class VerificationResult(BaseModel):
    """
    Structured result from Z3 verification.

    Attributes:
        status: "SAFE" (all flows comply), "VIOLATION" (at least one flow violates policy),
                or "TIMEOUT" (solver exceeded time limit).
        latency_ms: Wall-clock time for the Z3 check() call.
        violated_constraints: Names of violated assumption literals from unsat core.
        violation_details: Human-readable explanations of each violation.
        graph_id: The ID of the verified execution graph.
        node_count: Number of nodes in the graph.
        constraint_count: Number of Z3 constraints generated.
    """

    status: Literal["SAFE", "VIOLATION", "TIMEOUT"] = Field(
        description="Verification outcome.",
    )
    latency_ms: float = Field(
        description="Wall-clock time for Z3 solve in milliseconds.",
    )
    violated_constraints: List[str] = Field(
        default_factory=list,
        description="Names of violated constraints from the Z3 unsat core.",
    )
    violation_details: List[str] = Field(
        default_factory=list,
        description="Human-readable explanations of each violation.",
    )
    graph_id: str = Field(
        default="",
        description="The ID of the verified execution graph.",
    )
    node_count: int = Field(
        default=0,
        description="Number of nodes in the verified graph.",
    )
    constraint_count: int = Field(
        default=0,
        description="Number of Z3 constraints generated.",
    )

    model_config = {"arbitrary_types_allowed": True}


class Z3SolverEngine:
    """
    Maps ExecutionGraph → Z3 first-order logic and proves non-interference.

    Uses assumption-based incremental solving for maximum performance:
    - Policy constraints are added as implications gated on assumption literals
    - check(*assumptions) verifies all constraints simultaneously
    - unsat_core() identifies the minimal set of violated constraints
    - Learned lemmas persist across calls (2-5x faster than push/pop)

    Usage:
        >>> engine = Z3SolverEngine(timeout_ms=50)
        >>> engine.encode_graph(execution_graph)
        >>> result = engine.verify()
        >>> if result.status == "VIOLATION":
        ...     print(result.violated_constraints)
    """

    def __init__(self, timeout_ms: int = 50) -> None:
        """
        Initialize the Z3 solver engine.

        Args:
            timeout_ms: Maximum time for Z3 to solve. Default 50ms.
                        Fail-closed: timeout → treat as violation.
        """
        self._solver = Solver()
        self._solver.set("timeout", timeout_ms)
        self._timeout_ms = timeout_ms

        # Z3 sorts — we use integers for jurisdiction/classification
        # to leverage Z3's efficient integer arithmetic theory
        self._jurisdiction_var: Dict[str, Any] = {}  # node_id → Z3 Int
        self._classification_var: Dict[str, Any] = {}  # node_id → Z3 Int

        # Assumption tracking for incremental solving
        self._assumptions: List[Any] = []
        self._assumption_names: Dict[str, str] = {}  # assumption_name → human description

        # Statistics
        self._constraint_count = 0
        self._encoded_graph_id = ""
        self._encoded_node_count = 0

    def _get_or_create_vars(self, node_id: str) -> tuple:
        """Get or create Z3 integer variables for a node's jurisdiction and classification."""
        if node_id not in self._jurisdiction_var:
            # Use sanitized name for Z3 (no special chars)
            safe_id = node_id.replace("-", "_").replace(".", "_")
            self._jurisdiction_var[node_id] = Int(f"j_{safe_id}")
            self._classification_var[node_id] = Int(f"c_{safe_id}")
        return self._jurisdiction_var[node_id], self._classification_var[node_id]

    def encode_graph(self, graph: ExecutionGraph) -> None:
        """
        Translate the entire execution graph into Z3 constraints.

        Processes nodes in topological order so that when encoding a node,
        all its input node variables are already defined.

        Args:
            graph: The ExecutionGraph to encode.
        """
        self._encoded_graph_id = graph.graph_id
        self._encoded_node_count = len(graph.nodes)

        for node in graph.topological_order():
            match node.node_type:
                case "data_source":
                    self._encode_source(node)
                case "transform":
                    self._encode_transform(node)
                case "projection":
                    self._encode_projection(node)
                case "sink":
                    self._encode_sink(node)
                case "chat_sink":
                    self._encode_chat_sink(node)
                case "declassify":
                    self._encode_declassifier(node)
                case "human_declassify":
                    self._encode_human_declassify(node)
                case "agent_handoff":
                    self._encode_handoff(node)

    def _encode_source(self, node: DataSourceNode) -> None:
        """
        Encode a data source as Z3 facts.

        Asserts the exact jurisdiction and classification values as constants.
        """
        j_var, c_var = self._get_or_create_vars(node.node_id)
        self._solver.add(j_var == node.label.jurisdiction.value)
        self._solver.add(c_var == node.label.classification.value)
        self._constraint_count += 2

    def _encode_transform(self, node: TransformNode) -> None:
        """
        Encode taint propagation for a transform.

        The transform's output label must be ≥ all input labels
        (i.e., the join / least upper bound). We assert:
            output.jurisdiction ≥ max(input jurisdictions)
            output.classification ≥ max(input classifications)

        AND we fix the output to its declared label value.
        """
        j_var, c_var = self._get_or_create_vars(node.node_id)

        # Assert the output label
        self._solver.add(j_var == node.output_label.jurisdiction.value)
        self._solver.add(c_var == node.output_label.classification.value)
        self._constraint_count += 2

        # Assert propagation: output ≥ each input
        for input_id in node.input_node_ids:
            ij, ic = self._get_or_create_vars(input_id)
            self._solver.add(j_var >= ij)
            self._solver.add(c_var >= ic)
            self._constraint_count += 2

    def _encode_sink(self, node: SinkNode) -> None:
        """
        Encode the non-interference invariant for a sink.

        For each input flowing into this sink, we create an assumption:
            input.jurisdiction ≤ sink.target_jurisdiction AND
            input.classification ≤ sink.max_classification

        If any input violates this, Z3 returns UNSAT and the assumption
        appears in the unsat core, identifying the exact violation.
        """
        sink_j = node.target_jurisdiction.value
        sink_c = node.max_classification.value

        for input_id in node.input_node_ids:
            ij, ic = self._get_or_create_vars(input_id)

            # Create a named assumption literal
            assumption_name = f"flow__{input_id}__to__{node.node_id}"
            assumption = Bool(assumption_name)
            self._assumptions.append(assumption)

            # The policy: input must be within the sink's bounds
            policy = And(ij <= sink_j, ic <= sink_c)

            # Assert: IF the assumption is active, THEN the policy must hold
            self._solver.add(Implies(assumption, policy))
            self._constraint_count += 1

            # Store human-readable description
            self._assumption_names[assumption_name] = (
                f"Data from '{input_id}' must satisfy "
                f"jurisdiction ≤ {node.target_jurisdiction.name} AND "
                f"classification ≤ {node.max_classification.name} "
                f"to flow into sink '{node.node_id}' ({node.tool_name})"
            )

    def _encode_declassifier(self, node: DeclassifyNode) -> None:
        """
        Encode a declassification node.

        Declassification is a valid label transition: the output carries
        the downgraded label regardless of the input label. The Z3 solver
        simply assigns the declassified label to this node's variables.

        The max_bits constraint is verified structurally at AST build time
        (Phase 4), not in Z3, because it's a static property of the output type.
        """
        j_var, c_var = self._get_or_create_vars(node.node_id)
        self._solver.add(j_var == node.output_label.jurisdiction.value)
        self._solver.add(c_var == node.output_label.classification.value)
        self._constraint_count += 2

    def _encode_handoff(self, node: AgentHandoffNode) -> None:
        """
        Encode inter-agent taint propagation.

        Similar to transform: the handoff's label must be ≥ all input labels.
        """
        j_var, c_var = self._get_or_create_vars(node.node_id)

        # Assert the propagated label
        self._solver.add(j_var == node.propagated_label.jurisdiction.value)
        self._solver.add(c_var == node.propagated_label.classification.value)
        self._constraint_count += 2

        # Assert propagation: output ≥ each input
        for input_id in node.input_node_ids:
            ij, ic = self._get_or_create_vars(input_id)
            self._solver.add(j_var >= ij)
            self._solver.add(c_var >= ic)
            self._constraint_count += 2

    def _encode_projection(self, node: ProjectionNode) -> None:
        """
        Encode fine-grained field projection.

        The projection isolates specific fields, assigning the projected field's
        specific label to the output variables rather than joining all fields,
        preventing conservative over-tainting and label creep.
        """
        j_var, c_var = self._get_or_create_vars(node.node_id)
        self._solver.add(j_var == node.projected_label.jurisdiction.value)
        self._solver.add(c_var == node.projected_label.classification.value)
        self._constraint_count += 2

    def _encode_chat_sink(self, node: ChatOutputSinkNode) -> None:
        """
        Encode the non-interference invariant for a conversational chat sink.

        Secures the conversational boundary: for each input node flowing into
        the response, assert that input jurisdiction and classification do not
        exceed the user's clearance.
        """
        sink_j = node.target_jurisdiction.value
        sink_c = node.max_classification.value

        for input_id in node.input_node_ids:
            ij, ic = self._get_or_create_vars(input_id)

            assumption_name = f"flow__{input_id}__to__{node.node_id}"
            assumption = Bool(assumption_name)
            self._assumptions.append(assumption)

            policy = And(ij <= sink_j, ic <= sink_c)
            self._solver.add(Implies(assumption, policy))
            self._constraint_count += 1

            self._assumption_names[assumption_name] = (
                f"Conversational response to user '{node.user_id}' would leak data from '{input_id}': "
                f"input requires clearance ≤ {node.target_jurisdiction.name}/{node.max_classification.name}"
            )

    def _encode_human_declassify(self, node: HumanAttestedDeclassifyNode) -> None:
        """
        Encode a human-attested declassification node for unstructured free text.

        The output carries the human-approved downgraded label.
        """
        j_var, c_var = self._get_or_create_vars(node.node_id)
        self._solver.add(j_var == node.target_label.jurisdiction.value)
        self._solver.add(c_var == node.target_label.classification.value)
        self._constraint_count += 2

    def add_custom_constraint(self, name: str, constraint: Any, description: str = "") -> None:
        """
        Add a custom Z3 constraint with an assumption literal.

        This is the extension point for regulatory policies (Phase 4).
        Each policy constraint is gated on an assumption so it appears
        in the unsat core when violated.

        Args:
            name: Unique name for this constraint.
            constraint: A Z3 Boolean expression.
            description: Human-readable description.
        """
        assumption = Bool(name)
        self._assumptions.append(assumption)
        self._solver.add(Implies(assumption, constraint))
        self._assumption_names[name] = description or name
        self._constraint_count += 1

    def add_policy_constraints(
        self,
        policies: Any,
        graph: ExecutionGraph,
    ) -> List[str]:
        """
        Compile and add constraints from one or more PolicySet objects.

        Args:
            policies: A single PolicySet or sequence of PolicySet instances.
            graph: The ExecutionGraph being verified.

        Returns:
            List of all assumption names registered by the policies.
        """
        if hasattr(policies, "compile_to_z3"):
            policy_list = [policies]
        else:
            policy_list = list(policies)

        all_assumptions: List[str] = []
        for policy in policy_list:
            assumptions = policy.compile_to_z3(graph=graph, solver=self)
            all_assumptions.extend(assumptions)
        return all_assumptions

    def verify(self) -> VerificationResult:
        """
        Check if the encoded execution graph satisfies all constraints.

        Uses Z3's assumption-based checking:
            - SAT → all assumptions can be satisfied → all flows are SAFE
            - UNSAT → at least one assumption is violated → VIOLATION detected
            - UNKNOWN → solver timeout → treated as TIMEOUT

        Returns:
            VerificationResult with status, latency, and violation details.
        """
        start_ns = time.perf_counter_ns()
        result = self._solver.check(*self._assumptions)
        latency_ns = time.perf_counter_ns() - start_ns
        latency_ms = latency_ns / 1e6

        if result == sat:
            return VerificationResult(
                status="SAFE",
                latency_ms=latency_ms,
                graph_id=self._encoded_graph_id,
                node_count=self._encoded_node_count,
                constraint_count=self._constraint_count,
            )
        elif result == unsat:
            # Extract unsat core — minimal set of conflicting assumptions
            core = self._solver.unsat_core()
            violated_names = [str(c) for c in core]
            violation_details = [
                self._assumption_names.get(name, name) for name in violated_names
            ]
            return VerificationResult(
                status="VIOLATION",
                latency_ms=latency_ms,
                violated_constraints=violated_names,
                violation_details=violation_details,
                graph_id=self._encoded_graph_id,
                node_count=self._encoded_node_count,
                constraint_count=self._constraint_count,
            )
        else:
            # unknown — timeout or other issue
            return VerificationResult(
                status="TIMEOUT",
                latency_ms=latency_ms,
                graph_id=self._encoded_graph_id,
                node_count=self._encoded_node_count,
                constraint_count=self._constraint_count,
                violation_details=[
                    f"Z3 returned '{result}' after {latency_ms:.2f}ms "
                    f"(timeout: {self._timeout_ms}ms)"
                ],
            )

    def verify_or_raise(self) -> VerificationResult:
        """
        Verify and raise on violation or timeout (fail-closed).

        Returns:
            VerificationResult with status "SAFE".

        Raises:
            TaintViolationError: If a flow violation is detected.
            SolverTimeoutError: If Z3 exceeds the configured timeout.
        """
        result = self.verify()
        if result.status == "VIOLATION":
            raise TaintViolationError(
                f"IFC violation in graph '{result.graph_id}': "
                + "; ".join(result.violation_details),
                violated_constraints=result.violated_constraints,
                policy_name=result.violated_constraints[0] if result.violated_constraints else "",
            )
        elif result.status == "TIMEOUT":
            raise SolverTimeoutError(
                f"Z3 solver timeout after {result.latency_ms:.2f}ms "
                f"(limit: {self._timeout_ms}ms)",
                timeout_ms=self._timeout_ms,
                solver_result="unknown",
            )
        return result

    def reset(self) -> None:
        """Reset the solver, clearing all constraints and assumptions."""
        self._solver.reset()
        self._solver.set("timeout", self._timeout_ms)
        self._jurisdiction_var.clear()
        self._classification_var.clear()
        self._assumptions.clear()
        self._assumption_names.clear()
        self._constraint_count = 0
        self._encoded_graph_id = ""
        self._encoded_node_count = 0

    @property
    def stats(self) -> Dict[str, Any]:
        """Return solver statistics for profiling."""
        return {
            "constraint_count": self._constraint_count,
            "assumption_count": len(self._assumptions),
            "node_count": self._encoded_node_count,
            "timeout_ms": self._timeout_ms,
            "z3_stats": str(self._solver.statistics()) if self._constraint_count > 0 else "N/A",
        }
