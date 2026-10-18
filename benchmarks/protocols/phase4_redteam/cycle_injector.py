"""
Cyclic Dependency Graph Poisoning Suite for Phase 4 Red-Teaming.

Injects adversarial cycles into execution graphs to verify that Kahn's
topological sort algorithm detects feedback loops and raises ASTConstructionError,
halting execution cleanly before any SMT solver call or tool execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from jurisast_core.ast_ir import (
    AgentHandoffNode,
    DataSourceNode,
    ExecutionGraph,
    SinkNode,
    TransformNode,
)
from jurisast_core.exceptions import ASTConstructionError
from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel


@dataclass
class CycleInjectionResult:
    """Outcome of a cyclic dependency poisoning attempt."""

    test_id: str
    cycle_type: str
    description: str
    cycle_length: int
    detected_cleanly: bool  # True if ASTConstructionError was raised
    error_message: Optional[str] = None


class CyclicGraphInjector:
    """
    Constructs adversarial cyclic graphs across diverse topologies.
    """

    @staticmethod
    def create_self_loop() -> ExecutionGraph:
        """Adversarial Graph: Node A feeds directly into itself (A → A)."""
        label = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL)
        node_a = TransformNode(
            node_id="loop_node_a",
            input_node_ids=["loop_node_a"],
            operation="self_feedback",
            output_label=label,
        )
        return ExecutionGraph(
            graph_id="cycle_self_loop",
            agent_id="redteam_cycle_adversary",
            nodes=[node_a],
            edges=[("loop_node_a", "loop_node_a")],
        )

    @staticmethod
    def create_two_node_cycle() -> ExecutionGraph:
        """Adversarial Graph: Node A → Node B → Node A."""
        label = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL)
        src = DataSourceNode(node_id="src_root", tool_name="db_query", label=label)
        node_a = TransformNode(
            node_id="node_a",
            input_node_ids=["src_root", "node_b"],
            operation="step_a",
            output_label=label,
        )
        node_b = TransformNode(
            node_id="node_b",
            input_node_ids=["node_a"],
            operation="step_b",
            output_label=label,
        )
        sink = SinkNode(
            node_id="sink_out",
            tool_name="api_export",
            input_node_ids=["node_b"],
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.CONFIDENTIAL,
        )
        return ExecutionGraph(
            graph_id="cycle_two_node",
            agent_id="redteam_cycle_adversary",
            nodes=[src, node_a, node_b, sink],
            edges=[
                ("src_root", "node_a"),
                ("node_a", "node_b"),
                ("node_b", "node_a"),  # BACK EDGE
                ("node_b", "sink_out"),
            ],
        )

    @staticmethod
    def create_multi_agent_swarm_cycle(hops: int = 5) -> ExecutionGraph:
        """Adversarial Graph: Agent 1 → Agent 2 → ... → Agent N → Agent 1."""
        nodes = []
        edges = []
        agent_ids = [f"agent_{i}" for i in range(hops)]
        label = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL)

        for i in range(hops):
            prev_agent = agent_ids[(i - 1) % hops]
            curr_agent = agent_ids[i]
            node = AgentHandoffNode(
                node_id=f"handoff_{i}",
                input_node_ids=[f"handoff_{(i - 1) % hops}"] if i > 0 else [f"handoff_{hops - 1}"],
                source_agent_id=prev_agent,
                target_agent_id=curr_agent,
                propagated_label=label,
                description="multi_agent_circular_delegation",
            )
            nodes.append(node)

        for i in range(hops):
            edges.append((nodes[i].node_id, nodes[(i + 1) % hops].node_id))

        return ExecutionGraph(
            graph_id=f"cycle_swarm_hops_{hops}",
            agent_id="redteam_cycle_adversary",
            nodes=nodes,
            edges=edges,
        )

    @staticmethod
    def create_disconnected_cycle_in_dag() -> ExecutionGraph:
        """Adversarial Graph: Valid linear DAG component + hidden disconnected cyclic component."""
        label = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL)
        # Component 1: Clean Linear DAG
        src = DataSourceNode(node_id="valid_src", tool_name="fetch_user", label=label)
        sink = SinkNode(
            node_id="valid_sink",
            tool_name="deliver_report",
            input_node_ids=["valid_src"],
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.CONFIDENTIAL,
        )
        # Component 2: Hidden circular loop (C1 → C2 → C1)
        c1 = TransformNode(
            node_id="hidden_c1",
            input_node_ids=["hidden_c2"],
            operation="hidden_loop_1",
            output_label=label,
        )
        c2 = TransformNode(
            node_id="hidden_c2",
            input_node_ids=["hidden_c1"],
            operation="hidden_loop_2",
            output_label=label,
        )

        return ExecutionGraph(
            graph_id="cycle_disconnected_subgraph",
            agent_id="redteam_cycle_adversary",
            nodes=[src, sink, c1, c2],
            edges=[
                ("valid_src", "valid_sink"),
                ("hidden_c1", "hidden_c2"),
                ("hidden_c2", "hidden_c1"),
            ],
        )

    @classmethod
    def evaluate_graph(cls, test_id: str, graph: ExecutionGraph, cycle_type: str, cycle_len: int) -> CycleInjectionResult:
        """Evaluate whether Kahn's algorithm detects the cycle."""
        detected = False
        error_msg = None
        try:
            graph.topological_order()
        except ASTConstructionError as exc:
            detected = True
            error_msg = str(exc)
        except Exception as exc:
            error_msg = f"Unexpected exception: {exc}"

        return CycleInjectionResult(
            test_id=test_id,
            cycle_type=cycle_type,
            description=f"Adversarial cyclic graph ({cycle_type}) with cycle length {cycle_len}",
            cycle_length=cycle_len,
            detected_cleanly=detected,
            error_message=error_msg,
        )
