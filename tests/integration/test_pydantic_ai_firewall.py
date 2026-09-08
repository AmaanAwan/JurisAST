"""
Integration tests for JurisAST Pydantic AI Firewall.

End-to-end tests verifying multi-step agent flows with the JurisAST firewall,
testing the full lifecycle from tool interception through Z3 verification.

These tests use the firewall directly (no LLM calls) to verify that the
formal verification pipeline works correctly across realistic multi-step
scenarios.
"""

import pytest

from jurisast_core.config import JurisASTConfig, SolverConfig
from jurisast_core.exceptions import TaintViolationError
from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    LABEL_PUBLIC,
    LABEL_EU_PII,
    LABEL_EU_SENSITIVE_PII,
)
from jurisast_core.taint import TaintedValue, TaintRegistry

from jurisast_pydantic.capability import JurisASTFirewall
from jurisast_pydantic.decorators import (
    tainted_source,
    tainted_sink,
    declassifier,
    agent_handoff,
)
from jurisast_pydantic.tainted_context import JurisASTDeps
from jurisast_pydantic.agent import (
    create_jurisast_deps,
    resolve_model,
    GEMINI_FLASH,
    GEMINI_PRO,
)


# ─── Realistic tool functions for FinTech scenario ───────────────────────────


@tainted_source(
    jurisdiction=Jurisdiction.EU,
    classification=Classification.SENSITIVE_PII,
    compartments=frozenset({"finance"}),
    description="Fetch EU customer financial record from database",
)
def fetch_eu_financial_record(customer_id: str) -> str:
    """Simulate fetching an EU customer's financial data."""
    return f"Customer {customer_id}: IBAN DE89370400440532013000, Balance €42,000"


@tainted_source(
    jurisdiction=Jurisdiction.US,
    classification=Classification.CONFIDENTIAL,
    description="Fetch US market analysis report",
)
def fetch_us_market_report(report_id: str) -> str:
    """Simulate fetching a US market report."""
    return f"Report {report_id}: Q3 revenue projections..."


@tainted_sink(
    target_jurisdiction=Jurisdiction.US,
    max_classification=Classification.PUBLIC,
    description="Send analytics payload to US-based webhook",
)
def send_to_us_analytics_webhook(payload: str) -> str:
    """Simulate sending data to a US analytics endpoint."""
    return f"Sent to US webhook: {payload}"


@tainted_sink(
    target_jurisdiction=Jurisdiction.EU,
    max_classification=Classification.RESTRICTED,
    description="Save data to EU-sovereign database",
)
def save_to_eu_database(data: str) -> str:
    """Simulate saving data to an EU database."""
    return f"Saved to EU DB: {data}"


@tainted_sink(
    target_jurisdiction=Jurisdiction.EXTERNAL,
    max_classification=Classification.PUBLIC,
    description="Post to public Slack channel",
)
def post_to_slack(message: str) -> str:
    """Simulate posting to a public Slack channel."""
    return f"Posted to Slack: {message}"


@declassifier(
    output_label=SecurityLabel(
        jurisdiction=Jurisdiction.INTERNAL,
        classification=Classification.PUBLIC,
    ),
    max_bits=1.0,
    output_type="bool",
    description="Extract boolean sentiment from text",
)
def extract_sentiment_bool(text: str) -> bool:
    """Extract positive/negative sentiment. Bounded to 1 bit."""
    return True


@declassifier(
    output_label=SecurityLabel(
        jurisdiction=Jurisdiction.INTERNAL,
        classification=Classification.INTERNAL_ONLY,
    ),
    max_bits=2.32,
    output_type="enum",
    description="Classify risk level into 5 categories",
)
def classify_risk_level(text: str) -> str:
    """Classify risk level: very_low, low, medium, high, very_high."""
    return "medium"


@agent_handoff(
    target_agent_id="summarizer_agent",
    description="Transfer data to summarizer agent",
)
def send_to_summarizer_agent(data: str) -> str:
    """Send data to the summarizer agent."""
    return f"Summarizer received: {data}"


# ─── Scenario: Compliant EU-Internal Flow ────────────────────────────────────


class TestCompliantFlows:
    """Tests for flows that comply with all IFC policies."""

    def test_eu_data_stays_in_eu(self):
        """EU financial data → EU database is compliant."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(
                mode="enforce",
                solver=SolverConfig(timeout_ms=500),
            ),
            taint_registry=registry,
            agent_id="fintech_agent",
        )

        # Step 1: Fetch EU financial data
        result = firewall.verify_tool_call(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            fetch_eu_financial_record,
        )
        assert result.status == "SAFE"

        firewall.record_tool_result(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            "IBAN DE89..., Balance €42,000",
            fetch_eu_financial_record,
        )

        # Step 2: Save to EU database
        result = firewall.verify_tool_call(
            "save_to_eu_database",
            {"data": "fetch_eu_financial_record"},
            save_to_eu_database,
        )
        assert result.status == "SAFE"

    def test_public_data_to_any_sink(self):
        """Public/internal data can flow to any sink."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
        )

        # Untainted data to US analytics → SAFE
        result = firewall.verify_tool_call(
            "send_to_us_analytics_webhook",
            {"payload": "market_summary"},
            send_to_us_analytics_webhook,
        )
        assert result.status == "SAFE"

        # Untainted data to Slack → SAFE
        result = firewall.verify_tool_call(
            "post_to_slack",
            {"message": "Hello everyone!"},
            post_to_slack,
        )
        assert result.status == "SAFE"


# ─── Scenario: Cross-Border Violation ────────────────────────────────────────


class TestCrossBorderViolations:
    """Tests for cross-border data flow violations."""

    def test_eu_pii_blocked_at_us_boundary(self):
        """EU SENSITIVE_PII → US webhook is blocked."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
            agent_id="fintech_agent",
        )

        # Fetch EU financial data
        firewall.verify_tool_call(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            fetch_eu_financial_record,
        )
        firewall.record_tool_result(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            "IBAN DE89...",
            fetch_eu_financial_record,
        )

        # Attempt to send to US → BLOCKED
        with pytest.raises(TaintViolationError) as exc_info:
            firewall.verify_tool_call(
                "send_to_us_analytics_webhook",
                {"payload": "fetch_eu_financial_record"},
                send_to_us_analytics_webhook,
            )

        # Verify the error contains useful information
        error = exc_info.value
        assert len(error.violated_constraints) > 0 or "violation" in str(error).lower()

    def test_eu_pii_blocked_at_external_boundary(self):
        """EU SENSITIVE_PII → external Slack is blocked."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
        )

        firewall.verify_tool_call(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            fetch_eu_financial_record,
        )
        firewall.record_tool_result(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            "IBAN DE89...",
            fetch_eu_financial_record,
        )

        with pytest.raises(TaintViolationError):
            firewall.verify_tool_call(
                "post_to_slack",
                {"message": "fetch_eu_financial_record"},
                post_to_slack,
            )


# ─── Scenario: Declassification Enables Safe Transfer ────────────────────────


class TestDeclassificationFlow:
    """Tests for declassification enabling previously blocked flows."""

    def test_eu_pii_declassified_then_us_safe(self):
        """EU PII → declassify (bool sentiment) → US webhook is SAFE."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
            agent_id="fintech_agent",
        )

        # Step 1: Fetch EU financial data
        firewall.verify_tool_call(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            fetch_eu_financial_record,
        )
        firewall.record_tool_result(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            "IBAN DE89...",
            fetch_eu_financial_record,
        )

        # Step 2: Declassify to boolean sentiment (1 bit)
        result = firewall.verify_tool_call(
            "extract_sentiment_bool",
            {"text": "fetch_eu_financial_record"},
            extract_sentiment_bool,
        )
        assert result.status == "SAFE"

        firewall.record_tool_result(
            "extract_sentiment_bool",
            {"text": "fetch_eu_financial_record"},
            "positive",
            extract_sentiment_bool,
        )

        # Step 3: Send declassified data to US → SAFE
        result = firewall.verify_tool_call(
            "send_to_us_analytics_webhook",
            {"payload": "extract_sentiment_bool"},
            send_to_us_analytics_webhook,
        )
        assert result.status == "SAFE"

    def test_enum_declassification_flow(self):
        """EU PII → risk classification (5 categories) → Slack is SAFE."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
        )

        # Fetch
        firewall.verify_tool_call(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            fetch_eu_financial_record,
        )
        firewall.record_tool_result(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            "Financial data...",
            fetch_eu_financial_record,
        )

        # Declassify to risk level
        firewall.verify_tool_call(
            "classify_risk_level",
            {"text": "fetch_eu_financial_record"},
            classify_risk_level,
        )
        firewall.record_tool_result(
            "classify_risk_level",
            {"text": "fetch_eu_financial_record"},
            "medium",
            classify_risk_level,
        )

        # Post to Slack → SAFE (declassified to INTERNAL/INTERNAL_ONLY)
        # But wait — post_to_slack requires EXTERNAL/PUBLIC.
        # INTERNAL_ONLY > PUBLIC, so this should be a VIOLATION.
        # Let's test that the correct constraint is applied:
        with pytest.raises(TaintViolationError):
            firewall.verify_tool_call(
                "post_to_slack",
                {"payload": "classify_risk_level"},
                post_to_slack,
            )


# ─── Scenario: Multi-Agent Handoff ───────────────────────────────────────────


class TestMultiAgentHandoff:
    """Tests for multi-agent handoff scenarios."""

    def test_handoff_preserves_taint(self):
        """Agent handoff is verified and taint is preserved."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
            agent_id="originator",
        )

        # Fetch EU data
        firewall.verify_tool_call(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            fetch_eu_financial_record,
        )
        firewall.record_tool_result(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            "Financial data...",
            fetch_eu_financial_record,
        )

        # Handoff to summarizer → SAFE (handoff just propagates taint)
        result = firewall.verify_tool_call(
            "send_to_summarizer_agent",
            {"data": "fetch_eu_financial_record"},
            send_to_summarizer_agent,
        )
        assert result.status == "SAFE"


# ─── Agent Factory Tests ─────────────────────────────────────────────────────


class TestAgentFactory:
    """Tests for agent factory functions and model resolution."""

    def test_resolve_model_aliases(self):
        """Model aliases resolve correctly."""
        assert resolve_model("gemini-flash") == GEMINI_FLASH
        assert resolve_model("gemini-pro") == GEMINI_PRO
        assert resolve_model("flash") == GEMINI_FLASH
        assert resolve_model("pro") == GEMINI_PRO
        assert resolve_model("gemini-2.5-flash") == GEMINI_FLASH

    def test_resolve_model_passthrough(self):
        """Fully-qualified model strings pass through unchanged."""
        assert resolve_model("google-gla:gemini-2.5-flash") == GEMINI_FLASH
        assert resolve_model("openai:gpt-4o") == "openai:gpt-4o"

    def test_create_jurisast_deps(self):
        """create_jurisast_deps produces a fully configured JurisASTDeps."""
        deps = create_jurisast_deps(
            agent_id="test_agent",
            session_id="test_session",
        )
        assert deps.agent_id == "test_agent"
        assert deps.session_id == "test_session"
        assert deps.taint_registry is not None
        assert deps.firewall is not None
        assert deps.config.mode == "enforce"

    def test_create_jurisast_deps_shared_registry(self):
        """Multiple deps can share a TaintRegistry."""
        registry = TaintRegistry()
        deps1 = create_jurisast_deps(
            agent_id="agent_1",
            taint_registry=registry,
        )
        deps2 = create_jurisast_deps(
            agent_id="agent_2",
            taint_registry=registry,
        )

        assert deps1.taint_registry is deps2.taint_registry

    def test_create_deps_custom_mode(self):
        """Custom config mode is respected."""
        deps = create_jurisast_deps(
            config=JurisASTConfig(mode="audit"),
        )
        assert deps.config.mode == "audit"
        assert deps.firewall.mode == "audit"


# ─── Performance Tracking Tests ──────────────────────────────────────────────


class TestPerformanceTracking:
    """Tests for verification performance metrics."""

    def test_verification_latency_under_50ms(self):
        """Each verification should complete well under 50ms."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
        )

        # Verify a source call
        result = firewall.verify_tool_call(
            "fetch_eu_financial_record",
            {"customer_id": "EU001"},
            fetch_eu_financial_record,
        )

        assert result.latency_ms < 50.0, (
            f"Verification took {result.latency_ms:.2f}ms, exceeding 50ms target"
        )

    def test_cumulative_timing(self):
        """Cumulative timing is tracked across verifications."""
        registry = TaintRegistry()
        firewall = JurisASTFirewall(
            config=JurisASTConfig(mode="enforce"),
            taint_registry=registry,
        )

        for i in range(5):
            firewall.verify_tool_call(
                "fetch_eu_financial_record",
                {"customer_id": f"C{i}"},
                fetch_eu_financial_record,
            )

        assert firewall.total_verification_time_ms > 0
        assert len(firewall.audit_log) == 5
