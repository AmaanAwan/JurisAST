"""
Unit tests for JurisAST ToolCallExtractor.

Tests the extraction of ExecutionGraph fragments from tool call metadata
and arguments, verifying correct AST IR node construction for all tool types.
"""

import pytest

from jurisast_core.ast_ir import (
    DataSourceNode,
    DeclassifyNode,
    SinkNode,
    TransformNode,
    AgentHandoffNode,
)
from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    LABEL_PUBLIC,
    LABEL_EU_PII,
    LABEL_EU_SENSITIVE_PII,
)
from jurisast_core.taint import TaintedValue, TaintRegistry

from jurisast_pydantic.decorators import (
    tainted_source,
    tainted_sink,
    declassifier,
    agent_handoff,
)
from jurisast_pydantic.extractors import ToolCallExtractor


@pytest.fixture
def extractor():
    """Fresh ToolCallExtractor instance."""
    return ToolCallExtractor()


@pytest.fixture
def registry():
    """Fresh TaintRegistry instance."""
    return TaintRegistry()


@pytest.fixture
def registry_with_eu_pii(registry):
    """TaintRegistry with an EU PII value registered."""
    tv = TaintedValue.create(
        value="John Doe, Berlin, DE",
        label=LABEL_EU_PII,
        source_tool="fetch_customer",
        agent_id="test_agent",
    )
    registry.register("customer_data", tv)
    return registry


# ─── Source Extraction Tests ──────────────────────────────────────────────────


class TestSourceExtraction:
    """Tests for extracting source tool graphs."""

    def test_source_produces_single_data_source_node(self, extractor, registry):
        """Source tool produces a graph with a single DataSourceNode."""

        @tainted_source(Jurisdiction.EU, Classification.PII)
        def fetch_customer(customer_id: str) -> str:
            return "data"

        graph = extractor.extract(
            tool_name="fetch_customer",
            tool_args={"customer_id": "C42"},
            tool_callable=fetch_customer,
            registry=registry,
            agent_id="test_agent",
        )

        assert len(graph.nodes) == 1
        node = graph.nodes[0]
        assert isinstance(node, DataSourceNode)
        assert node.tool_name == "fetch_customer"
        assert node.label.jurisdiction == Jurisdiction.EU
        assert node.label.classification == Classification.PII

    def test_source_arguments_preserved(self, extractor, registry):
        """Source node preserves tool arguments."""

        @tainted_source(Jurisdiction.US, Classification.CONFIDENTIAL)
        def fetch(doc_id: str) -> str:
            return "doc"

        graph = extractor.extract(
            tool_name="fetch",
            tool_args={"doc_id": "D123"},
            tool_callable=fetch,
            registry=registry,
        )

        node = graph.nodes[0]
        assert node.arguments == {"doc_id": "D123"}


# ─── Sink Extraction Tests ───────────────────────────────────────────────────


class TestSinkExtraction:
    """Tests for extracting sink tool graphs."""

    def test_sink_with_tainted_input(self, extractor, registry_with_eu_pii):
        """Sink with tainted input produces source + sink graph."""

        @tainted_sink(Jurisdiction.US, Classification.PUBLIC)
        def send_analytics(payload: str) -> str:
            return "sent"

        graph = extractor.extract(
            tool_name="send_analytics",
            tool_args={"payload": "customer_data"},
            tool_callable=send_analytics,
            registry=registry_with_eu_pii,
            agent_id="test_agent",
        )

        # Should have a source node for the tainted input and a sink node
        sources = graph.get_sources()
        sinks = graph.get_sinks()
        assert len(sources) == 1
        assert len(sinks) == 1

        # Source should carry EU/PII label
        assert sources[0].label == LABEL_EU_PII

        # Sink should have US/PUBLIC constraints
        assert sinks[0].target_jurisdiction == Jurisdiction.US
        assert sinks[0].max_classification == Classification.PUBLIC

    def test_sink_without_tainted_input(self, extractor, registry):
        """Sink with untainted input produces public source + sink graph."""

        @tainted_sink(Jurisdiction.EXTERNAL, Classification.PUBLIC)
        def post_webhook(data: str) -> str:
            return "posted"

        graph = extractor.extract(
            tool_name="post_webhook",
            tool_args={"data": "hello_world"},
            tool_callable=post_webhook,
            registry=registry,
        )

        sources = graph.get_sources()
        sinks = graph.get_sinks()
        assert len(sources) == 1
        assert len(sinks) == 1
        assert sources[0].label == LABEL_PUBLIC

    def test_sink_graph_has_correct_edges(self, extractor, registry_with_eu_pii):
        """Sink graph has edges from source to sink."""

        @tainted_sink(Jurisdiction.US, Classification.PUBLIC)
        def send(payload: str) -> str:
            return "sent"

        graph = extractor.extract(
            tool_name="send",
            tool_args={"payload": "customer_data"},
            tool_callable=send,
            registry=registry_with_eu_pii,
        )

        assert len(graph.edges) >= 1
        # The sink node should receive input from the source
        sink = graph.get_sinks()[0]
        assert len(sink.input_node_ids) >= 1

    def test_sink_graph_is_valid(self, extractor, registry_with_eu_pii):
        """Sink graph passes structural validation."""

        @tainted_sink(Jurisdiction.US, Classification.PUBLIC)
        def send(payload: str) -> str:
            return "sent"

        graph = extractor.extract(
            tool_name="send",
            tool_args={"payload": "customer_data"},
            tool_callable=send,
            registry=registry_with_eu_pii,
        )

        assert graph.is_valid()


# ─── Declassifier Extraction Tests ───────────────────────────────────────────


class TestDeclassifierExtraction:
    """Tests for extracting declassifier tool graphs."""

    def test_declassifier_produces_source_and_declassify(
        self, extractor, registry_with_eu_pii
    ):
        """Declassifier produces source + DeclassifyNode graph."""

        @declassifier(
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            output_type="bool",
        )
        def extract_sentiment(text: str) -> bool:
            return True

        graph = extractor.extract(
            tool_name="extract_sentiment",
            tool_args={"text": "customer_data"},
            tool_callable=extract_sentiment,
            registry=registry_with_eu_pii,
        )

        sources = graph.get_sources()
        declassifiers = graph.get_declassifiers()
        assert len(sources) == 1
        assert len(declassifiers) == 1

        # Input should carry EU/PII label
        assert sources[0].label == LABEL_EU_PII

        # Declassify node should carry the downgraded label
        dcl = declassifiers[0]
        assert dcl.output_label == LABEL_PUBLIC
        assert dcl.max_bits == 1.0
        assert dcl.output_type == "bool"

    def test_declassifier_graph_is_valid(self, extractor, registry_with_eu_pii):
        """Declassifier graph passes structural validation."""

        @declassifier(output_label=LABEL_PUBLIC, max_bits=1.0)
        def extract(text: str) -> bool:
            return True

        graph = extractor.extract(
            tool_name="extract",
            tool_args={"text": "customer_data"},
            tool_callable=extract,
            registry=registry_with_eu_pii,
        )

        assert graph.is_valid()


# ─── Handoff Extraction Tests ────────────────────────────────────────────────


class TestHandoffExtraction:
    """Tests for extracting agent handoff graphs."""

    def test_handoff_produces_source_and_handoff(
        self, extractor, registry_with_eu_pii
    ):
        """Handoff produces source + AgentHandoffNode graph."""

        @agent_handoff(target_agent_id="summarizer")
        def send_to_summarizer(data: str) -> str:
            return "handed off"

        graph = extractor.extract(
            tool_name="send_to_summarizer",
            tool_args={"data": "customer_data"},
            tool_callable=send_to_summarizer,
            registry=registry_with_eu_pii,
            agent_id="originator",
        )

        sources = graph.get_sources()
        handoffs = graph.get_handoffs()
        assert len(sources) == 1
        assert len(handoffs) == 1

        hnd = handoffs[0]
        assert hnd.source_agent_id == "originator"
        assert hnd.target_agent_id == "summarizer"
        assert hnd.propagated_label == LABEL_EU_PII


# ─── Transform (Default) Extraction Tests ────────────────────────────────────


class TestTransformExtraction:
    """Tests for extracting generic transform graphs (no JurisAST metadata)."""

    def test_undecorated_tool_creates_transform(self, extractor, registry_with_eu_pii):
        """Undecorated tools produce a transform graph."""

        def summarize(text: str) -> str:
            return "summary"

        graph = extractor.extract(
            tool_name="summarize",
            tool_args={"text": "customer_data"},
            tool_callable=summarize,
            registry=registry_with_eu_pii,
        )

        sources = graph.get_sources()
        transforms = graph.get_transforms()
        assert len(sources) == 1
        assert len(transforms) == 1

        assert transforms[0].output_label == LABEL_EU_PII

    def test_undecorated_untainted_creates_public_transform(
        self, extractor, registry
    ):
        """Undecorated tool with untainted input creates public transform."""

        def compute(x: str) -> str:
            return "result"

        graph = extractor.extract(
            tool_name="compute",
            tool_args={"x": "plain_value"},
            tool_callable=compute,
            registry=registry,
        )

        transforms = graph.get_transforms()
        assert len(transforms) == 1
        assert transforms[0].output_label == LABEL_PUBLIC


# ─── Multi-input Tests ───────────────────────────────────────────────────────


class TestMultiInputExtraction:
    """Tests for tools with multiple tainted inputs."""

    def test_sink_with_multiple_tainted_inputs(self, extractor, registry):
        """Sink with multiple tainted inputs creates source for each."""
        registry.register(
            "eu_data",
            TaintedValue(value="eu", label=LABEL_EU_PII),
        )
        us_label = SecurityLabel(
            jurisdiction=Jurisdiction.US,
            classification=Classification.CONFIDENTIAL,
        )
        registry.register(
            "us_data",
            TaintedValue(value="us", label=us_label),
        )

        @tainted_sink(Jurisdiction.EXTERNAL, Classification.PUBLIC)
        def send_combined(eu_ref: str, us_ref: str) -> str:
            return "sent"

        graph = extractor.extract(
            tool_name="send_combined",
            tool_args={"eu_ref": "eu_data", "us_ref": "us_data"},
            tool_callable=send_combined,
            registry=registry,
        )

        sources = graph.get_sources()
        sinks = graph.get_sinks()
        assert len(sources) == 2
        assert len(sinks) == 1
        assert len(sinks[0].input_node_ids) == 2
