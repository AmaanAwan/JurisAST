"""
Property-based tests for Z3 SMT Solver Soundness and Non-Interference (solver.py).

Uses Hypothesis to verify fundamental mathematical invariants of the Z3 verification engine:
1. Soundness: If Z3 returns SAFE for a simple source->sink graph, then the sink clearance
   dominates the source label.
2. Completeness (Simple Flows): If a source->sink flow violates lattice dominance,
   Z3 ALWAYS returns VIOLATION.
3. Declassification Soundness: When a declassification node downgrades a label, Z3 verifies
   downstream flows using the declassified label rather than the original tainted label.
4. Monotonicity of Taint: Adding an intermediate transform that computes the join never
   makes a violating flow SAFE.
"""

import sys
import os

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"
))

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    LABEL_PUBLIC,
)
from jurisast_core.ast_ir import ExecutionGraphBuilder
from jurisast_core.solver import Z3SolverEngine


jurisdictions = st.sampled_from(list(Jurisdiction))
classifications = st.sampled_from(list(Classification))
compartments = st.frozensets(st.sampled_from(["finance", "hr", "legal"]), max_size=2)

security_labels = st.builds(
    SecurityLabel,
    jurisdiction=jurisdictions,
    classification=classifications,
    compartments=compartments,
)


class TestSolverSoundnessProperties:
    """Property-based verification of Z3 solver soundness and completeness."""

    @given(src_label=security_labels, target_j=jurisdictions, max_c=classifications)
    @settings(max_examples=200)
    def test_direct_flow_soundness_and_completeness(
        self,
        src_label: SecurityLabel,
        target_j: Jurisdiction,
        max_c: Classification,
    ):
        """
        For any direct source -> sink flow:
        Z3 returns SAFE  <==>  (src_label.jurisdiction <= target_j AND src_label.classification <= max_c)
        """
        builder = ExecutionGraphBuilder(agent_id="prop_agent")
        src = builder.add_source("fetch_data", src_label, node_id="src_1")
        builder.add_sink("target_sink", target_j, max_c, [src.node_id], node_id="snk_1")
        graph = builder.build()

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()

        expected_safe = (
            src_label.jurisdiction.value <= target_j.value
            and src_label.classification.value <= max_c.value
        )

        if expected_safe:
            assert result.status == "SAFE", (
                f"Expected SAFE but got {result.status} for source={src_label}, "
                f"sink=({target_j.name}, {max_c.name})"
            )
        else:
            assert result.status == "VIOLATION", (
                f"Expected VIOLATION but got {result.status} for source={src_label}, "
                f"sink=({target_j.name}, {max_c.name})"
            )

    @given(src_label=security_labels, target_j=jurisdictions, max_c=classifications)
    @settings(max_examples=100)
    def test_declassification_soundness(
        self,
        src_label: SecurityLabel,
        target_j: Jurisdiction,
        max_c: Classification,
    ):
        """
        Declassification to PUBLIC always allows flow to any sink that accepts PUBLIC data.
        """
        builder = ExecutionGraphBuilder(agent_id="prop_agent")
        src = builder.add_source("fetch_data", src_label, node_id="src_1")
        dcl = builder.add_declassifier(
            input_node_id=src.node_id,
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            node_id="dcl_1",
        )
        builder.add_sink("target_sink", target_j, max_c, [dcl.node_id], node_id="snk_1")
        graph = builder.build()

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()

        expected_safe = (
            LABEL_PUBLIC.jurisdiction.value <= target_j.value
            and LABEL_PUBLIC.classification.value <= max_c.value
        )
        assert result.status == ("SAFE" if expected_safe else "VIOLATION")

    @given(s1_label=security_labels, s2_label=security_labels, target_j=jurisdictions, max_c=classifications)
    @settings(max_examples=100)
    def test_merge_propagation_soundness(
        self,
        s1_label: SecurityLabel,
        s2_label: SecurityLabel,
        target_j: Jurisdiction,
        max_c: Classification,
    ):
        """
        When two sources merge, the result is SAFE only if the JOIN of both labels satisfies the sink.
        """
        builder = ExecutionGraphBuilder(agent_id="prop_agent")
        s1 = builder.add_source("fetch_1", s1_label, node_id="s1")
        s2 = builder.add_source("fetch_2", s2_label, node_id="s2")
        joined_label = s1_label.join(s2_label)
        xfm = builder.add_transform("merge", [s1.node_id, s2.node_id], joined_label, node_id="xfm_1")
        builder.add_sink("target_sink", target_j, max_c, [xfm.node_id], node_id="snk_1")
        graph = builder.build()

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()

        expected_safe = (
            joined_label.jurisdiction.value <= target_j.value
            and joined_label.classification.value <= max_c.value
        )
        assert result.status == ("SAFE" if expected_safe else "VIOLATION")
