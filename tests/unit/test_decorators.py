"""
Unit tests for JurisAST Pydantic AI decorators.

Tests the @tainted_source, @tainted_sink, @declassifier, and @agent_handoff
decorators, verifying metadata attachment, argument validation, introspection
utilities, and composition with other decorators.
"""

import pytest

from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    LABEL_PUBLIC,
    LABEL_EU_PII,
)

from jurisast_pydantic.decorators import (
    JURISAST_METADATA_KEY,
    agent_handoff,
    declassifier,
    get_jurisast_metadata,
    get_tool_type,
    is_tainted_tool,
    tainted_sink,
    tainted_source,
)


# ─── @tainted_source Tests ────────────────────────────────────────────────────


class TestTaintedSource:
    """Tests for the @tainted_source decorator."""

    def test_attaches_metadata(self):
        """Decorator attaches __jurisast_metadata__ to the function."""

        @tainted_source(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        def fetch_customer(customer_id: str) -> str:
            return f"record_{customer_id}"

        metadata = getattr(fetch_customer, JURISAST_METADATA_KEY, None)
        assert metadata is not None
        assert metadata["type"] == "source"

    def test_label_construction(self):
        """Decorator constructs the correct SecurityLabel."""

        @tainted_source(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"finance", "hr"}),
        )
        def fetch_record() -> str:
            return "data"

        metadata = get_jurisast_metadata(fetch_record)
        assert metadata is not None
        label = metadata["label"]
        assert isinstance(label, SecurityLabel)
        assert label.jurisdiction == Jurisdiction.EU
        assert label.classification == Classification.SENSITIVE_PII
        assert label.compartments == frozenset({"finance", "hr"})

    def test_default_compartments(self):
        """Default compartments is an empty frozenset."""

        @tainted_source(
            jurisdiction=Jurisdiction.US,
            classification=Classification.CONFIDENTIAL,
        )
        def fetch() -> str:
            return "data"

        metadata = get_jurisast_metadata(fetch)
        assert metadata["compartments"] == frozenset()

    def test_preserves_function_name(self):
        """Decorator preserves the original function name."""

        @tainted_source(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        def my_fancy_tool() -> str:
            return "data"

        assert my_fancy_tool.__name__ == "my_fancy_tool"

    def test_preserves_function_docstring(self):
        """Decorator preserves the original function docstring."""

        @tainted_source(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        def documented_tool() -> str:
            """Fetch a customer record from the EU database."""
            return "data"

        assert "customer record" in documented_tool.__doc__

    def test_function_still_callable(self):
        """Decorated function still executes correctly."""

        @tainted_source(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        def get_data(x: int) -> int:
            return x * 2

        assert get_data(21) == 42

    def test_description_stored(self):
        """Optional description is stored in metadata."""

        @tainted_source(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            description="EU customer financial records",
        )
        def fetch() -> str:
            return "data"

        metadata = get_jurisast_metadata(fetch)
        assert metadata["description"] == "EU customer financial records"


# ─── @tainted_sink Tests ──────────────────────────────────────────────────────


class TestTaintedSink:
    """Tests for the @tainted_sink decorator."""

    def test_attaches_sink_metadata(self):
        """Decorator attaches sink-type metadata."""

        @tainted_sink(
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PUBLIC,
        )
        def send_analytics(payload: str) -> str:
            return "sent"

        metadata = get_jurisast_metadata(send_analytics)
        assert metadata is not None
        assert metadata["type"] == "sink"
        assert metadata["target_jurisdiction"] == Jurisdiction.US
        assert metadata["max_classification"] == Classification.PUBLIC

    def test_preserves_function_behavior(self):
        """Sink decorator doesn't alter function behavior."""

        @tainted_sink(
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.PUBLIC,
        )
        def post_webhook(data: str) -> str:
            return f"posted: {data}"

        assert post_webhook("hello") == "posted: hello"

    def test_sink_description(self):
        """Sink description is stored."""

        @tainted_sink(
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PUBLIC,
            description="US analytics webhook",
        )
        def send(payload: str) -> str:
            return "sent"

        assert get_jurisast_metadata(send)["description"] == "US analytics webhook"


# ─── @declassifier Tests ──────────────────────────────────────────────────────


class TestDeclassifier:
    """Tests for the @declassifier decorator."""

    def test_attaches_declassifier_metadata(self):
        """Decorator attaches declassifier-type metadata."""

        @declassifier(
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            output_type="bool",
        )
        def extract_sentiment(text: str) -> bool:
            return True

        metadata = get_jurisast_metadata(extract_sentiment)
        assert metadata is not None
        assert metadata["type"] == "declassifier"
        assert metadata["output_label"] == LABEL_PUBLIC
        assert metadata["max_bits"] == 1.0
        assert metadata["output_type"] == "bool"

    def test_enum_declassifier(self):
        """Declassifier with enum output stores correct bits."""
        import math

        @declassifier(
            output_label=SecurityLabel(
                jurisdiction=Jurisdiction.INTERNAL,
                classification=Classification.INTERNAL_ONLY,
            ),
            max_bits=math.log2(5),
            output_type="enum",
        )
        def classify_document(text: str) -> str:
            return "category_a"

        metadata = get_jurisast_metadata(classify_document)
        assert metadata["max_bits"] == pytest.approx(2.3219, abs=0.01)

    def test_output_schema_stored(self):
        """Output schema is stored in metadata."""

        @declassifier(
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            output_schema={"type": "boolean"},
        )
        def extract(text: str) -> bool:
            return True

        metadata = get_jurisast_metadata(extract)
        assert metadata["output_schema"] == {"type": "boolean"}


# ─── @agent_handoff Tests ─────────────────────────────────────────────────────


class TestAgentHandoff:
    """Tests for the @agent_handoff decorator."""

    def test_attaches_handoff_metadata(self):
        """Decorator attaches handoff-type metadata."""

        @agent_handoff(target_agent_id="summarizer_agent")
        def send_to_summarizer(data: str) -> str:
            return "handed off"

        metadata = get_jurisast_metadata(send_to_summarizer)
        assert metadata is not None
        assert metadata["type"] == "handoff"
        assert metadata["target_agent_id"] == "summarizer_agent"

    def test_handoff_description(self):
        """Handoff description is stored."""

        @agent_handoff(
            target_agent_id="analyst",
            description="Transfer financial data for analysis",
        )
        def transfer(data: str) -> str:
            return "done"

        metadata = get_jurisast_metadata(transfer)
        assert metadata["description"] == "Transfer financial data for analysis"


# ─── Introspection Utility Tests ──────────────────────────────────────────────


class TestIntrospectionUtilities:
    """Tests for get_jurisast_metadata, get_tool_type, is_tainted_tool."""

    def test_get_metadata_on_undecorated(self):
        """get_jurisast_metadata returns None for undecorated functions."""

        def plain_func() -> str:
            return "plain"

        assert get_jurisast_metadata(plain_func) is None

    def test_get_tool_type_source(self):
        """get_tool_type returns 'source' for @tainted_source."""

        @tainted_source(Jurisdiction.EU, Classification.PII)
        def fetch() -> str:
            return "data"

        assert get_tool_type(fetch) == "source"

    def test_get_tool_type_sink(self):
        """get_tool_type returns 'sink' for @tainted_sink."""

        @tainted_sink(Jurisdiction.US, Classification.PUBLIC)
        def send(payload: str) -> str:
            return "sent"

        assert get_tool_type(send) == "sink"

    def test_get_tool_type_declassifier(self):
        """get_tool_type returns 'declassifier' for @declassifier."""

        @declassifier(LABEL_PUBLIC, max_bits=1.0)
        def extract(text: str) -> bool:
            return True

        assert get_tool_type(extract) == "declassifier"

    def test_get_tool_type_handoff(self):
        """get_tool_type returns 'handoff' for @agent_handoff."""

        @agent_handoff(target_agent_id="other")
        def transfer(data: str) -> str:
            return "done"

        assert get_tool_type(transfer) == "handoff"

    def test_get_tool_type_undecorated(self):
        """get_tool_type returns None for undecorated functions."""

        def plain() -> str:
            return "plain"

        assert get_tool_type(plain) is None

    def test_is_tainted_tool_true(self):
        """is_tainted_tool returns True for decorated functions."""

        @tainted_source(Jurisdiction.EU, Classification.PII)
        def fetch() -> str:
            return "data"

        assert is_tainted_tool(fetch) is True

    def test_is_tainted_tool_false(self):
        """is_tainted_tool returns False for undecorated functions."""

        def plain() -> str:
            return "plain"

        assert is_tainted_tool(plain) is False


# ─── Edge Cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge case tests for decorators."""

    def test_double_decoration_overwrites(self):
        """Applying two JurisAST decorators keeps the outer one."""

        @tainted_sink(Jurisdiction.US, Classification.PUBLIC)
        @tainted_source(Jurisdiction.EU, Classification.PII)
        def double_decorated() -> str:
            return "data"

        # The outer decorator (@tainted_sink) wins
        assert get_tool_type(double_decorated) == "sink"

    def test_async_function_support(self):
        """Decorators work with async functions."""

        @tainted_source(Jurisdiction.EU, Classification.PII)
        async def async_fetch(customer_id: str) -> str:
            return f"record_{customer_id}"

        assert get_tool_type(async_fetch) == "source"
        metadata = get_jurisast_metadata(async_fetch)
        assert metadata["label"].jurisdiction == Jurisdiction.EU

    def test_all_jurisdiction_values(self):
        """All Jurisdiction enum values work as source jurisdiction."""
        for jurisdiction in Jurisdiction:

            @tainted_source(
                jurisdiction=jurisdiction,
                classification=Classification.PUBLIC,
            )
            def func() -> str:
                return "data"

            metadata = get_jurisast_metadata(func)
            assert metadata["jurisdiction"] == jurisdiction

    def test_all_classification_values(self):
        """All Classification enum values work as source classification."""
        for classification in Classification:

            @tainted_source(
                jurisdiction=Jurisdiction.INTERNAL,
                classification=classification,
            )
            def func() -> str:
                return "data"

            metadata = get_jurisast_metadata(func)
            assert metadata["classification"] == classification

    def test_lambda_decoration(self):
        """Decorators work on lambdas (via manual application)."""
        func = tainted_source(Jurisdiction.EU, Classification.PII)(
            lambda: "data"
        )
        assert get_tool_type(func) == "source"
