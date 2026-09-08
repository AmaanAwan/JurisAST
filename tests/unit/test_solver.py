"""
Unit tests for the Z3 SMT Solver Engine (solver.py).

Tests cover:
- SAFE verification: compliant flows pass
- VIOLATION detection: non-compliant flows are blocked
- Unsat core extraction: violated constraints are identified
- Declassification: valid declassification allows downstream flow
- Multi-source merge: taint propagation through transforms
- Agent handoff: taint propagation across agent boundaries
- Performance: verification latency under target thresholds
- Custom constraints: extension point for regulatory policies
- Reset and reuse: solver can be reset for new graphs
- The GDPR scenario: EU PII → US webhook is blocked
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"
))

from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    LABEL_PUBLIC,
    LABEL_EU_PII,
    LABEL_EU_SENSITIVE_PII,
)
from jurisast_core.ast_ir import ExecutionGraphBuilder
from jurisast_core.solver import Z3SolverEngine, VerificationResult
from jurisast_core.exceptions import TaintViolationError, SolverTimeoutError


# ─── Helper: Build common test graphs ────────────────────────────────────────


def _build_safe_eu_to_eu_graph():
    """EU PII → EU sink (classification within bounds). Should be SAFE."""
    builder = ExecutionGraphBuilder(agent_id="agent_1")
    src = builder.add_source("fetch_customer", LABEL_EU_PII, node_id="src_eu")
    builder.add_sink(
        "store_eu_db", Jurisdiction.EU, Classification.SENSITIVE_PII,
        [src.node_id], node_id="snk_eu",
    )
    return builder.build()


def _build_violation_eu_pii_to_us_public():
    """EU PII → US PUBLIC sink. Should be VIOLATION (GDPR breach)."""
    builder = ExecutionGraphBuilder(agent_id="agent_1")
    src = builder.add_source("fetch_customer", LABEL_EU_PII, node_id="src_eu")
    builder.add_sink(
        "send_us_webhook", Jurisdiction.US, Classification.PUBLIC,
        [src.node_id], node_id="snk_us",
    )
    return builder.build()


def _build_declassification_graph():
    """EU PII → declassify(bool) → US PUBLIC sink. Should be SAFE."""
    builder = ExecutionGraphBuilder(agent_id="agent_1")
    src = builder.add_source("fetch_customer", LABEL_EU_PII, node_id="src_eu")
    dcl = builder.add_declassifier(
        input_node_id=src.node_id,
        output_type="bool",
        output_label=LABEL_PUBLIC,
        max_bits=1.0,
        node_id="dcl_sentiment",
    )
    builder.add_sink(
        "send_us_webhook", Jurisdiction.US, Classification.PUBLIC,
        [dcl.node_id], node_id="snk_us",
    )
    return builder.build()


def _build_multi_source_merge_graph():
    """
    EU PII + US CONFIDENTIAL → merge → EXTERNAL sink.
    Merged label = US/PII. Sink is EXTERNAL/PUBLIC → VIOLATION.
    """
    builder = ExecutionGraphBuilder(agent_id="agent_1")
    s1 = builder.add_source("fetch_eu", LABEL_EU_PII, node_id="src_eu")
    s2 = builder.add_source(
        "fetch_us",
        SecurityLabel(jurisdiction=Jurisdiction.US, classification=Classification.CONFIDENTIAL),
        node_id="src_us",
    )
    merged_label = s1.label.join(s2.label)
    xfm = builder.add_transform(
        "merge_records", [s1.node_id, s2.node_id], merged_label, node_id="xfm_merge",
    )
    builder.add_sink(
        "send_external", Jurisdiction.EXTERNAL, Classification.PUBLIC,
        [xfm.node_id], node_id="snk_ext",
    )
    return builder.build()


def _build_agent_handoff_graph():
    """Agent A fetches EU PII → handoff to Agent B → Agent B sends to EU sink. SAFE."""
    builder = ExecutionGraphBuilder(agent_id="agent_a")
    src = builder.add_source("fetch_customer", LABEL_EU_PII, node_id="src_eu")
    hnd = builder.add_handoff(
        source_agent_id="agent_a",
        target_agent_id="agent_b",
        input_node_ids=[src.node_id],
        propagated_label=LABEL_EU_PII,
        node_id="hnd_ab",
    )
    builder.add_sink(
        "store_eu", Jurisdiction.EU, Classification.SENSITIVE_PII,
        [hnd.node_id], node_id="snk_eu",
    )
    return builder.build()


def _build_multi_hop_laundering_graph():
    """
    EU PII → Agent A → Agent B → Agent C → US sink.
    Taint must propagate through all handoffs. VIOLATION.
    """
    builder = ExecutionGraphBuilder(agent_id="agent_a")
    src = builder.add_source("fetch_customer", LABEL_EU_PII, node_id="src_eu")
    h1 = builder.add_handoff(
        "agent_a", "agent_b", [src.node_id], LABEL_EU_PII, node_id="h1",
    )
    h2 = builder.add_handoff(
        "agent_b", "agent_c", [h1.node_id], LABEL_EU_PII, node_id="h2",
    )
    builder.add_sink(
        "send_us", Jurisdiction.US, Classification.PUBLIC,
        [h2.node_id], node_id="snk_us",
    )
    return builder.build()


# ─── SAFE Flow Tests ─────────────────────────────────────────────────────────


class TestSafeFlows:
    """Tests verifying that compliant data flows pass verification."""

    def test_eu_pii_to_eu_sink(self):
        """EU PII → EU sink (within bounds) should be SAFE."""
        graph = _build_safe_eu_to_eu_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "SAFE"
        assert result.latency_ms >= 0
        assert result.violated_constraints == []

    def test_public_to_external(self):
        """PUBLIC data → EXTERNAL sink should always be SAFE."""
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        src = builder.add_source("public_api", LABEL_PUBLIC, node_id="src_pub")
        builder.add_sink(
            "external_webhook", Jurisdiction.EXTERNAL, Classification.PUBLIC,
            [src.node_id], node_id="snk_ext",
        )
        graph = builder.build()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "SAFE"

    def test_declassification_enables_flow(self):
        """EU PII → declassify(bool) → US PUBLIC should be SAFE."""
        graph = _build_declassification_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "SAFE"

    def test_agent_handoff_same_jurisdiction(self):
        """EU PII → handoff → EU sink should be SAFE."""
        graph = _build_agent_handoff_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "SAFE"

    def test_transform_within_bounds(self):
        """EU PII → transform → EU/SENSITIVE_PII sink should be SAFE."""
        builder = ExecutionGraphBuilder(agent_id="a")
        src = builder.add_source("fetch", LABEL_EU_PII, node_id="s1")
        xfm = builder.add_transform("summarize", [src.node_id], LABEL_EU_PII, node_id="x1")
        builder.add_sink(
            "store", Jurisdiction.EU, Classification.SENSITIVE_PII,
            [xfm.node_id], node_id="k1",
        )
        graph = builder.build()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        assert engine.verify().status == "SAFE"


# ─── VIOLATION Detection Tests ───────────────────────────────────────────────


class TestViolationDetection:
    """Tests verifying that non-compliant data flows are detected."""

    def test_eu_pii_to_us_public_is_violation(self):
        """The core GDPR scenario: EU PII → US PUBLIC = VIOLATION."""
        graph = _build_violation_eu_pii_to_us_public()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "VIOLATION"
        assert len(result.violated_constraints) > 0

    def test_violation_unsat_core_identifies_flow(self):
        """The unsat core should name the specific flow that violated policy."""
        graph = _build_violation_eu_pii_to_us_public()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "VIOLATION"
        # The constraint name encodes the source → sink flow
        constraint_names = result.violated_constraints
        assert len(constraint_names) >= 1
        # Should reference both the source and sink nodes
        combined = " ".join(constraint_names)
        assert "src_eu" in combined
        assert "snk_us" in combined

    def test_violation_has_human_readable_details(self):
        """Violation details should explain what happened."""
        graph = _build_violation_eu_pii_to_us_public()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert len(result.violation_details) > 0
        detail = result.violation_details[0]
        assert "jurisdiction" in detail.lower() or "classification" in detail.lower()

    def test_multi_source_merge_violation(self):
        """Merged EU PII + US CONF → EXTERNAL/PUBLIC = VIOLATION."""
        graph = _build_multi_source_merge_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "VIOLATION"

    def test_multi_hop_laundering_detected(self):
        """
        EU PII laundered through 3 agents → US sink.
        Taint must propagate. VIOLATION.
        """
        graph = _build_multi_hop_laundering_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "VIOLATION"

    def test_classification_violation_same_jurisdiction(self):
        """EU RESTRICTED → EU PUBLIC sink = VIOLATION (classification too low)."""
        builder = ExecutionGraphBuilder(agent_id="a")
        src = builder.add_source(
            "fetch_restricted",
            SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.RESTRICTED),
            node_id="s1",
        )
        builder.add_sink(
            "store_public", Jurisdiction.EU, Classification.PUBLIC,
            [src.node_id], node_id="k1",
        )
        graph = builder.build()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "VIOLATION"


# ─── verify_or_raise Tests ───────────────────────────────────────────────────


class TestVerifyOrRaise:
    """Tests for the fail-closed verify_or_raise() method."""

    def test_safe_returns_result(self):
        graph = _build_safe_eu_to_eu_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify_or_raise()
        assert result.status == "SAFE"

    def test_violation_raises_taint_error(self):
        graph = _build_violation_eu_pii_to_us_public()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        with pytest.raises(TaintViolationError) as exc_info:
            engine.verify_or_raise()
        assert len(exc_info.value.violated_constraints) > 0


# ─── Custom Constraints Tests ────────────────────────────────────────────────


class TestCustomConstraints:
    """Tests for the custom constraint extension point."""

    def test_custom_constraint_can_cause_violation(self):
        """Adding a custom Z3 constraint that is unsatisfiable."""
        from z3 import Bool, Not

        builder = ExecutionGraphBuilder(agent_id="a")
        src = builder.add_source("fetch", LABEL_PUBLIC, node_id="s1")
        builder.add_sink(
            "send", Jurisdiction.EXTERNAL, Classification.PUBLIC,
            [src.node_id], node_id="k1",
        )
        graph = builder.build()

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)

        # Add an impossible custom constraint
        engine.add_custom_constraint(
            name="custom_block_all",
            constraint=Bool("impossible_false"),  # unasserted → defaults to False path
            description="Block all flows for testing",
        )
        # The custom constraint is Implies(assumption, Bool("impossible_false"))
        # Since impossible_false is not asserted true, Z3 cannot satisfy the assumption
        # Actually let's make it explicit:
        engine._solver.add(Not(Bool("impossible_false")))
        result = engine.verify()
        assert result.status == "VIOLATION"
        assert "custom_block_all" in result.violated_constraints


# ─── Solver Reset & Reuse Tests ──────────────────────────────────────────────


class TestSolverReset:
    """Tests for solver reset and reuse."""

    def test_reset_clears_state(self):
        engine = Z3SolverEngine(timeout_ms=1000)
        graph = _build_safe_eu_to_eu_graph()
        engine.encode_graph(graph)
        assert engine.stats["constraint_count"] > 0

        engine.reset()
        assert engine.stats["constraint_count"] == 0
        assert engine.stats["assumption_count"] == 0
        assert engine.stats["node_count"] == 0

    def test_reuse_after_reset(self):
        engine = Z3SolverEngine(timeout_ms=1000)

        # First: verify a safe graph
        graph1 = _build_safe_eu_to_eu_graph()
        engine.encode_graph(graph1)
        r1 = engine.verify()
        assert r1.status == "SAFE"

        # Reset
        engine.reset()

        # Second: verify a violating graph
        graph2 = _build_violation_eu_pii_to_us_public()
        engine.encode_graph(graph2)
        r2 = engine.verify()
        assert r2.status == "VIOLATION"


# ─── Performance Tests ───────────────────────────────────────────────────────


class TestPerformance:
    """Tests verifying solver latency is within acceptable bounds."""

    def test_simple_graph_under_20ms(self):
        """Simple 2-node graph should verify in well under 20ms."""
        graph = _build_safe_eu_to_eu_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.latency_ms < 20.0, f"Took {result.latency_ms}ms, expected < 20ms"

    def test_medium_graph_under_50ms(self):
        """10-node graph should verify in under 50ms."""
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        # Create a chain of 8 transforms between source and sink
        src = builder.add_source("fetch", LABEL_EU_PII, node_id="s0")
        prev_id = src.node_id
        for i in range(8):
            xfm = builder.add_transform(
                f"step_{i}", [prev_id], LABEL_EU_PII, node_id=f"x{i}",
            )
            prev_id = xfm.node_id
        builder.add_sink(
            "send", Jurisdiction.EU, Classification.SENSITIVE_PII,
            [prev_id], node_id="k1",
        )
        graph = builder.build()
        assert len(graph) == 10

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.status == "SAFE"
        assert result.latency_ms < 50.0, f"Took {result.latency_ms}ms, expected < 50ms"

    def test_verification_result_stats(self):
        """VerificationResult should contain node/constraint counts."""
        graph = _build_safe_eu_to_eu_graph()
        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()
        assert result.node_count == 2
        assert result.constraint_count > 0
        assert result.graph_id == graph.graph_id


# ─── The Complete GDPR Scenario Test ─────────────────────────────────────────


class TestGDPRScenario:
    """
    End-to-end test of the complete GDPR scenario from the proposal:

    1. Agent fetches EU citizen's financial record (EU/SENSITIVE_PII)
    2. Agent summarizes the record (taint propagates)
    3. Agent tries to send summary to US analytics webhook → BLOCKED
    4. Agent uses declassifier to extract sentiment (bool) → 1 bit
    5. Declassified sentiment sent to US webhook → ALLOWED
    """

    def test_direct_transfer_blocked(self):
        """Steps 1-3: Direct EU SENSITIVE_PII → US webhook is blocked."""
        builder = ExecutionGraphBuilder(agent_id="fintech_agent")
        src = builder.add_source(
            "fetch_financial_record", LABEL_EU_SENSITIVE_PII, node_id="src_fin",
        )
        xfm = builder.add_transform(
            "summarize", [src.node_id], LABEL_EU_SENSITIVE_PII, node_id="xfm_summary",
        )
        builder.add_sink(
            "send_to_analytics", Jurisdiction.US, Classification.PUBLIC,
            [xfm.node_id], node_id="snk_analytics",
        )
        graph = builder.build()

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()

        assert result.status == "VIOLATION"
        assert any("snk_analytics" in c for c in result.violated_constraints)

    def test_declassified_transfer_allowed(self):
        """Steps 4-5: EU PII → declassify(bool) → US webhook is allowed."""
        builder = ExecutionGraphBuilder(agent_id="fintech_agent")
        src = builder.add_source(
            "fetch_financial_record", LABEL_EU_SENSITIVE_PII, node_id="src_fin",
        )
        dcl = builder.add_declassifier(
            input_node_id=src.node_id,
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            node_id="dcl_sentiment",
        )
        builder.add_sink(
            "send_to_analytics", Jurisdiction.US, Classification.PUBLIC,
            [dcl.node_id], node_id="snk_analytics",
        )
        graph = builder.build()

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()

        assert result.status == "SAFE"

    def test_full_scenario_both_paths(self):
        """
        Combined graph with both paths:
        - Path A: src → summary → US webhook (VIOLATION)
        - Path B: src → declassify → US webhook (SAFE alone)

        Since Path A exists, the graph should be VIOLATION.
        """
        builder = ExecutionGraphBuilder(agent_id="fintech_agent")
        src = builder.add_source(
            "fetch_financial_record", LABEL_EU_SENSITIVE_PII, node_id="src_fin",
        )
        # Path A: direct summary to US
        xfm = builder.add_transform(
            "summarize", [src.node_id], LABEL_EU_SENSITIVE_PII, node_id="xfm_summary",
        )
        builder.add_sink(
            "send_summary_us", Jurisdiction.US, Classification.PUBLIC,
            [xfm.node_id], node_id="snk_direct",
        )
        # Path B: declassify then send
        dcl = builder.add_declassifier(
            input_node_id=src.node_id,
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            node_id="dcl_sentiment",
        )
        builder.add_sink(
            "send_sentiment_us", Jurisdiction.US, Classification.PUBLIC,
            [dcl.node_id], node_id="snk_safe",
        )
        graph = builder.build()

        engine = Z3SolverEngine(timeout_ms=1000)
        engine.encode_graph(graph)
        result = engine.verify()

        # Graph should be VIOLATION because Path A exists
        assert result.status == "VIOLATION"
        # Only the direct path should be violated, not the declassified path
        violated = " ".join(result.violated_constraints)
        assert "snk_direct" in violated
        assert "snk_safe" not in violated
