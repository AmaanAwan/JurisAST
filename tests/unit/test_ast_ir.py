"""
Unit tests for the AST Intermediate Representation (ast_ir.py).

Tests cover:
- Node type construction (all 5 variants)
- ExecutionGraph construction, node accessors, and property queries
- Topological ordering (Kahn's algorithm)
- Cycle detection
- Structural validation
- ExecutionGraphBuilder fluent API with automatic edge wiring
- Error handling for invalid references and duplicate IDs
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
from jurisast_core.ast_ir import (
    DataSourceNode,
    TransformNode,
    SinkNode,
    DeclassifyNode,
    AgentHandoffNode,
    ExecutionGraph,
    ExecutionGraphBuilder,
)
from jurisast_core.exceptions import ASTConstructionError


# ─── Node Construction Tests ─────────────────────────────────────────────────


class TestDataSourceNode:
    def test_construction(self):
        node = DataSourceNode(
            node_id="src_1",
            tool_name="fetch_customer",
            label=LABEL_EU_PII,
            arguments={"customer_id": "42"},
        )
        assert node.node_type == "data_source"
        assert node.tool_name == "fetch_customer"
        assert node.label == LABEL_EU_PII
        assert node.arguments == {"customer_id": "42"}

    def test_auto_generated_id(self):
        node = DataSourceNode(tool_name="test", label=LABEL_PUBLIC)
        assert node.node_id.startswith("src_")

    def test_optional_description(self):
        node = DataSourceNode(
            tool_name="test", label=LABEL_PUBLIC,
            description="Fetching public data",
        )
        assert node.description == "Fetching public data"


class TestTransformNode:
    def test_construction(self):
        node = TransformNode(
            node_id="xfm_1",
            operation="summarize",
            input_node_ids=["src_1", "src_2"],
            output_label=LABEL_EU_PII,
        )
        assert node.node_type == "transform"
        assert node.operation == "summarize"
        assert len(node.input_node_ids) == 2


class TestSinkNode:
    def test_construction(self):
        node = SinkNode(
            node_id="snk_1",
            tool_name="send_webhook",
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PUBLIC,
            input_node_ids=["xfm_1"],
        )
        assert node.node_type == "sink"
        assert node.target_jurisdiction == Jurisdiction.US
        assert node.max_classification == Classification.PUBLIC


class TestDeclassifyNode:
    def test_construction(self):
        node = DeclassifyNode(
            node_id="dcl_1",
            input_node_id="src_1",
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
        )
        assert node.node_type == "declassify"
        assert node.max_bits == 1.0
        assert node.output_type == "bool"

    def test_max_bits_validation(self):
        with pytest.raises(Exception):
            DeclassifyNode(
                node_id="dcl_bad",
                input_node_id="src_1",
                output_type="bool",
                output_label=LABEL_PUBLIC,
                max_bits=-1.0,  # negative not allowed
            )


class TestAgentHandoffNode:
    def test_construction(self):
        node = AgentHandoffNode(
            node_id="hnd_1",
            source_agent_id="agent_a",
            target_agent_id="agent_b",
            input_node_ids=["src_1"],
            propagated_label=LABEL_EU_PII,
        )
        assert node.node_type == "agent_handoff"
        assert node.source_agent_id == "agent_a"
        assert node.target_agent_id == "agent_b"


# ─── ExecutionGraph Tests ────────────────────────────────────────────────────


class TestExecutionGraph:
    """Tests for the ExecutionGraph container."""

    def _make_simple_graph(self) -> ExecutionGraph:
        """Helper: src → xfm → snk"""
        src = DataSourceNode(node_id="src_1", tool_name="fetch", label=LABEL_EU_PII)
        xfm = TransformNode(
            node_id="xfm_1", operation="summarize",
            input_node_ids=["src_1"], output_label=LABEL_EU_PII,
        )
        snk = SinkNode(
            node_id="snk_1", tool_name="webhook",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=["xfm_1"],
        )
        return ExecutionGraph(
            graph_id="test_graph",
            agent_id="agent_1",
            nodes=[src, xfm, snk],
            edges=[("src_1", "xfm_1"), ("xfm_1", "snk_1")],
        )

    def test_get_node(self):
        graph = self._make_simple_graph()
        node = graph.get_node("src_1")
        assert isinstance(node, DataSourceNode)
        assert node.tool_name == "fetch"

    def test_get_node_not_found(self):
        graph = self._make_simple_graph()
        with pytest.raises(ASTConstructionError, match="not found"):
            graph.get_node("nonexistent")

    def test_get_sources(self):
        graph = self._make_simple_graph()
        sources = graph.get_sources()
        assert len(sources) == 1
        assert sources[0].node_id == "src_1"

    def test_get_sinks(self):
        graph = self._make_simple_graph()
        sinks = graph.get_sinks()
        assert len(sinks) == 1
        assert sinks[0].node_id == "snk_1"

    def test_get_transforms(self):
        graph = self._make_simple_graph()
        transforms = graph.get_transforms()
        assert len(transforms) == 1
        assert transforms[0].operation == "summarize"

    def test_node_ids(self):
        graph = self._make_simple_graph()
        assert graph.node_ids == {"src_1", "xfm_1", "snk_1"}

    def test_len(self):
        graph = self._make_simple_graph()
        assert len(graph) == 3

    def test_repr(self):
        graph = self._make_simple_graph()
        r = repr(graph)
        assert "test_graph" in r
        assert "nodes=3" in r


class TestTopologicalOrder:
    """Tests for topological sorting."""

    def test_simple_chain(self):
        """src → xfm → snk should produce [src, xfm, snk]."""
        src = DataSourceNode(node_id="s1", tool_name="fetch", label=LABEL_EU_PII)
        xfm = TransformNode(
            node_id="x1", operation="transform",
            input_node_ids=["s1"], output_label=LABEL_EU_PII,
        )
        snk = SinkNode(
            node_id="k1", tool_name="send",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=["x1"],
        )
        graph = ExecutionGraph(
            graph_id="topo_test", agent_id="agent_1",
            nodes=[snk, src, xfm],  # Deliberately out of order
            edges=[("s1", "x1"), ("x1", "k1")],
        )
        order = graph.topological_order()
        ids = [n.node_id for n in order]
        assert ids.index("s1") < ids.index("x1") < ids.index("k1")

    def test_diamond_graph(self):
        """
        src → xfm_a ─┐
                      ├→ snk
        src → xfm_b ─┘
        """
        src = DataSourceNode(node_id="s1", tool_name="fetch", label=LABEL_EU_PII)
        xfm_a = TransformNode(
            node_id="xa", operation="path_a",
            input_node_ids=["s1"], output_label=LABEL_EU_PII,
        )
        xfm_b = TransformNode(
            node_id="xb", operation="path_b",
            input_node_ids=["s1"], output_label=LABEL_EU_PII,
        )
        snk = SinkNode(
            node_id="k1", tool_name="merge_send",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=["xa", "xb"],
        )
        graph = ExecutionGraph(
            graph_id="diamond", agent_id="agent_1",
            nodes=[snk, xfm_b, src, xfm_a],
            edges=[("s1", "xa"), ("s1", "xb"), ("xa", "k1"), ("xb", "k1")],
        )
        order = graph.topological_order()
        ids = [n.node_id for n in order]
        assert ids.index("s1") < ids.index("xa")
        assert ids.index("s1") < ids.index("xb")
        assert ids.index("xa") < ids.index("k1")
        assert ids.index("xb") < ids.index("k1")

    def test_cycle_detection(self):
        """Cycles should raise ASTConstructionError."""
        n1 = DataSourceNode(node_id="n1", tool_name="t", label=LABEL_PUBLIC)
        n2 = TransformNode(
            node_id="n2", operation="op",
            input_node_ids=["n1"], output_label=LABEL_PUBLIC,
        )
        graph = ExecutionGraph(
            graph_id="cyclic", agent_id="agent_1",
            nodes=[n1, n2],
            edges=[("n1", "n2"), ("n2", "n1")],  # Cycle!
        )
        with pytest.raises(ASTConstructionError, match="[Cc]ycle"):
            graph.topological_order()

    def test_predecessors(self):
        src = DataSourceNode(node_id="s1", tool_name="fetch", label=LABEL_PUBLIC)
        snk = SinkNode(
            node_id="k1", tool_name="send",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.PUBLIC,
            input_node_ids=["s1"],
        )
        graph = ExecutionGraph(
            graph_id="pred_test", agent_id="a",
            nodes=[src, snk], edges=[("s1", "k1")],
        )
        preds = graph.get_predecessors("k1")
        assert len(preds) == 1
        assert preds[0].node_id == "s1"

    def test_successors(self):
        src = DataSourceNode(node_id="s1", tool_name="fetch", label=LABEL_PUBLIC)
        snk = SinkNode(
            node_id="k1", tool_name="send",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.PUBLIC,
            input_node_ids=["s1"],
        )
        graph = ExecutionGraph(
            graph_id="succ_test", agent_id="a",
            nodes=[src, snk], edges=[("s1", "k1")],
        )
        succs = graph.get_successors("s1")
        assert len(succs) == 1
        assert succs[0].node_id == "k1"


class TestGraphValidation:
    """Tests for structural validation."""

    def test_valid_graph(self):
        src = DataSourceNode(node_id="s1", tool_name="t", label=LABEL_PUBLIC)
        snk = SinkNode(
            node_id="k1", tool_name="t",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.PUBLIC,
            input_node_ids=["s1"],
        )
        graph = ExecutionGraph(
            graph_id="valid", agent_id="a",
            nodes=[src, snk], edges=[("s1", "k1")],
        )
        assert graph.is_valid()
        assert len(graph.validate_structure()) == 0

    def test_invalid_edge_reference(self):
        src = DataSourceNode(node_id="s1", tool_name="t", label=LABEL_PUBLIC)
        graph = ExecutionGraph(
            graph_id="bad_edge", agent_id="a",
            nodes=[src],
            edges=[("s1", "nonexistent")],  # target doesn't exist
        )
        errors = graph.validate_structure()
        assert len(errors) > 0
        assert any("nonexistent" in e for e in errors)

    def test_source_with_incoming_edge(self):
        src = DataSourceNode(node_id="s1", tool_name="t", label=LABEL_PUBLIC)
        src2 = DataSourceNode(node_id="s2", tool_name="t", label=LABEL_PUBLIC)
        graph = ExecutionGraph(
            graph_id="bad_source", agent_id="a",
            nodes=[src, src2],
            edges=[("s2", "s1")],  # source shouldn't have incoming
        )
        errors = graph.validate_structure()
        assert any("incoming" in e.lower() for e in errors)


# ─── ExecutionGraphBuilder Tests ─────────────────────────────────────────────


class TestExecutionGraphBuilder:
    """Tests for the fluent graph builder."""

    def test_simple_build(self):
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        src = builder.add_source("fetch_customer", LABEL_EU_PII, node_id="s1")
        builder.add_sink(
            "send_webhook", Jurisdiction.EU, Classification.SENSITIVE_PII,
            [src.node_id], node_id="k1",
        )
        graph = builder.build()
        assert len(graph) == 2
        assert len(graph.edges) == 1
        assert graph.is_valid()

    def test_builder_auto_edges(self):
        """Builder should automatically create edges from input_node_ids."""
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        src = builder.add_source("fetch", LABEL_EU_PII, node_id="s1")
        xfm = builder.add_transform(
            "summarize", [src.node_id], LABEL_EU_PII, node_id="x1",
        )
        builder.add_sink(
            "send", Jurisdiction.EU, Classification.SENSITIVE_PII,
            [xfm.node_id], node_id="k1",
        )
        graph = builder.build()
        assert graph.edges == [("s1", "x1"), ("x1", "k1")]

    def test_builder_with_declassifier(self):
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        src = builder.add_source("fetch", LABEL_EU_PII, node_id="s1")
        dcl = builder.add_declassifier(
            input_node_id=src.node_id,
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            node_id="d1",
        )
        builder.add_sink(
            "send", Jurisdiction.US, Classification.PUBLIC,
            [dcl.node_id], node_id="k1",
        )
        graph = builder.build()
        assert len(graph) == 3
        assert graph.is_valid()
        assert len(graph.get_declassifiers()) == 1

    def test_builder_with_handoff(self):
        builder = ExecutionGraphBuilder(agent_id="agent_a")
        src = builder.add_source("fetch", LABEL_EU_PII, node_id="s1")
        hnd = builder.add_handoff(
            source_agent_id="agent_a",
            target_agent_id="agent_b",
            input_node_ids=[src.node_id],
            propagated_label=LABEL_EU_PII,
            node_id="h1",
        )
        builder.add_sink(
            "send", Jurisdiction.EU, Classification.SENSITIVE_PII,
            [hnd.node_id], node_id="k1",
        )
        graph = builder.build()
        assert len(graph.get_handoffs()) == 1
        assert graph.is_valid()

    def test_builder_duplicate_id_raises(self):
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        builder.add_source("fetch", LABEL_PUBLIC, node_id="same_id")
        with pytest.raises(ASTConstructionError, match="[Dd]uplicate"):
            builder.add_source("fetch2", LABEL_PUBLIC, node_id="same_id")

    def test_builder_invalid_input_reference(self):
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        with pytest.raises(ASTConstructionError, match="does not exist"):
            builder.add_transform(
                "op", ["nonexistent_node"], LABEL_PUBLIC, node_id="x1",
            )

    def test_builder_node_count(self):
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        assert builder.node_count == 0
        builder.add_source("t", LABEL_PUBLIC, node_id="s1")
        assert builder.node_count == 1
        builder.add_sink("t", Jurisdiction.EU, Classification.PUBLIC, ["s1"], node_id="k1")
        assert builder.node_count == 2
        assert builder.edge_count == 1

    def test_complex_multi_source_graph(self):
        """
        Two sources → merge transform → sink
        """
        builder = ExecutionGraphBuilder(agent_id="agent_1")
        s1 = builder.add_source("fetch_eu", LABEL_EU_PII, node_id="s1")
        s2 = builder.add_source(
            "fetch_us",
            SecurityLabel(jurisdiction=Jurisdiction.US, classification=Classification.CONFIDENTIAL),
            node_id="s2",
        )
        merged_label = s1.label.join(s2.label)
        xfm = builder.add_transform(
            "merge", [s1.node_id, s2.node_id], merged_label, node_id="x1",
        )
        builder.add_sink(
            "send", Jurisdiction.EXTERNAL, Classification.SENSITIVE_PII,
            [xfm.node_id], node_id="k1",
        )
        graph = builder.build()
        assert len(graph) == 4
        assert len(graph.edges) == 3  # s1→x1, s2→x1, x1→k1
        assert graph.is_valid()

        # Verify topological order
        order_ids = [n.node_id for n in graph.topological_order()]
        assert order_ids.index("s1") < order_ids.index("x1")
        assert order_ids.index("s2") < order_ids.index("x1")
        assert order_ids.index("x1") < order_ids.index("k1")


# ─── Serialization Tests ─────────────────────────────────────────────────────


class TestSerialization:
    """Test that the AST IR serializes/deserializes correctly via Pydantic."""

    def test_node_roundtrip(self):
        node = DataSourceNode(
            node_id="s1", tool_name="fetch", label=LABEL_EU_PII,
            arguments={"id": 42},
        )
        json_str = node.model_dump_json()
        restored = DataSourceNode.model_validate_json(json_str)
        assert restored.node_id == "s1"
        assert restored.label == LABEL_EU_PII

    def test_graph_node_count_after_build(self):
        builder = ExecutionGraphBuilder(agent_id="a")
        builder.add_source("t", LABEL_PUBLIC, node_id="s1")
        builder.add_sink("t", Jurisdiction.EU, Classification.PUBLIC, ["s1"], node_id="k1")
        graph = builder.build()
        data = graph.model_dump()
        assert len(data["nodes"]) == 2
        assert len(data["edges"]) == 1
