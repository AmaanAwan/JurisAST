"""
SMT Solver Timeout Bomb Generator for Phase 4 Red-Teaming.

Constructs pathological execution graphs and combinatorial constraint sets
designed to induce worst-case exponential backtracking in Z3, verifying that
the system strictly fails closed at the deadline (e.g., 50 ms).

Mathematical Principle:
    The white-box adversary uses the Pigeonhole Principle (PHP) or dense
    bipartite compartment mappings with N+1 items into N discrete slots.
    Resolution complexity for PHP in CDCL/SMT solvers is mathematically proven
    to be exponential Ω(2^N). This guarantees that solver execution will hit
    the hard deadline and trigger the fail-closed fallback.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple
from z3 import And, Bool, Not, Or

from jurisast_core.ast_ir import DataSourceNode, ExecutionGraph, SinkNode, TransformNode
from jurisast_core.exceptions import SolverTimeoutError
from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel
from jurisast_core.solver import Z3SolverEngine


@dataclass
class TimeoutStressResult:
    """Outcome of an SMT timeout stress test."""

    test_id: str
    description: str
    timeout_ms: int
    node_count: int
    constraint_count: int
    actual_latency_ms: float
    solver_status: str  # "SAFE", "VIOLATION", "TIMEOUT"
    failed_closed: bool  # True if SolverTimeoutError was raised or status was TIMEOUT
    error_message: Optional[str] = None


class SMTTimeoutBombGenerator:
    """
    Synthesizes combinatorial worst-case constraint graphs to test fail-closed behavior.
    """

    @staticmethod
    def generate_pigeonhole_bomb(
        num_holes: int = 9,
    ) -> Tuple[ExecutionGraph, List[Tuple[str, Any, str]]]:
        """
        Generate an execution graph with Pigeonhole constraint explosion.
        Maps (N+1) agents into N mutually exclusive secure compartments.
        Requires Ω(2^N) resolution steps, forcing Z3 timeout.
        """
        nodes = []
        edges = []
        custom_constraints: List[Tuple[str, Any, str]] = []

        label = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL)
        src = DataSourceNode(
            node_id="bomb_root",
            tool_name="root_vault",
            label=label,
        )
        nodes.append(src)

        num_pigeons = num_holes + 1
        agent_node_ids = []

        for i in range(num_pigeons):
            nid = f"pigeon_agent_{i}"
            node = TransformNode(
                node_id=nid,
                operation="pigeon_assign",
                input_node_ids=["bomb_root"],
                output_label=label,
            )
            nodes.append(node)
            edges.append(("bomb_root", nid))
            agent_node_ids.append(nid)

        sink = SinkNode(
            node_id="bomb_sink",
            tool_name="egress_point",
            input_node_ids=agent_node_ids,
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.CONFIDENTIAL,
        )
        nodes.append(sink)
        for nid in agent_node_ids:
            edges.append((nid, "bomb_sink"))

        # Construct Pigeonhole Propositional Formula:
        # P[i][j] = Pigeon i is assigned to Hole j
        p = [[Bool(f"php_p_{i}_h_{j}") for j in range(num_holes)] for i in range(num_pigeons)]

        # Clause 1: Every pigeon must be assigned to at least one hole
        for i in range(num_pigeons):
            clause = Or(*p[i])
            custom_constraints.append((
                f"php_pigeon_exists_{i}",
                clause,
                f"Pigeon {i} must occupy at least one hole",
            ))

        # Clause 2: No two pigeons can occupy the same hole (Exclusive Compartment)
        for j in range(num_holes):
            for i in range(num_pigeons):
                for k in range(i + 1, num_pigeons):
                    clause = Or(Not(p[i][j]), Not(p[k][j]))
                    custom_constraints.append((
                        f"php_excl_h{j}_p{i}_p{k}",
                        clause,
                        f"Hole {j} cannot hold both pigeon {i} and {k}",
                    ))

        graph = ExecutionGraph(
            graph_id=f"php_bomb_holes_{num_holes}",
            agent_id="redteam_adversary",
            nodes=nodes,
            edges=edges,
        )

        return graph, custom_constraints

    @classmethod
    def execute_timeout_test(
        cls,
        test_id: str,
        num_holes: int = 9,
        timeout_ms: int = 50,
    ) -> TimeoutStressResult:
        """
        Execute an SMT timeout bomb and verify fail-closed enforcement.
        """
        graph, constraints = cls.generate_pigeonhole_bomb(num_holes=num_holes)
        solver = Z3SolverEngine(timeout_ms=timeout_ms)
        solver.encode_graph(graph)

        for name, expr, desc in constraints:
            solver.add_custom_constraint(name=name, constraint=expr, description=desc)

        start_time = time.perf_counter()
        failed_closed = False
        error_msg = None

        try:
            # Test verify_or_raise (The production fail-closed entrypoint)
            solver.verify_or_raise()
            solver_status = "SAFE"
        except SolverTimeoutError as exc:
            # Correct fail-closed response!
            failed_closed = True
            solver_status = "TIMEOUT"
            error_msg = str(exc)
        except Exception as exc:
            # Any violation or other exception also fails closed
            failed_closed = True
            solver_status = "ERROR"
            error_msg = str(exc)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return TimeoutStressResult(
            test_id=test_id,
            description=f"Pigeonhole SMT Timeout Bomb ({num_holes} holes, {num_holes+1} items) under {timeout_ms}ms deadline",
            timeout_ms=timeout_ms,
            node_count=len(graph.nodes),
            constraint_count=solver.stats["constraint_count"],
            actual_latency_ms=elapsed_ms,
            solver_status=solver_status,
            failed_closed=failed_closed,
            error_message=error_msg,
        )
