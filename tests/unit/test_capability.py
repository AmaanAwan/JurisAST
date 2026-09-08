"""
Unit tests for JurisAST Firewall (capability.py).

Tests the JurisASTFirewall across enforce, audit, and permissive modes,
verifying tool call interception, Z3 verification, enforcement actions,
audit logging, and taint registration.
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


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def registry():
    """Fresh TaintRegistry."""
    return TaintRegistry()


@pytest.fixture
def registry_with_eu_pii(registry):
    """Registry with an EU PII value."""
    tv = TaintedValue.create(
        value="John Doe, Berlin, DE",
        label=LABEL_EU_PII,
        source_tool="fetch_customer",
        agent_id="test_agent",
    )
    registry.register("customer_data", tv)
    return registry


@pytest.fixture
def enforce_firewall(registry):
    """Firewall in enforce mode."""
    return JurisASTFirewall(
        config=JurisASTConfig(mode="enforce"),
        taint_registry=registry,
        agent_id="test_agent",
    )


@pytest.fixture
def audit_firewall(registry):
    """Firewall in audit mode."""
    return JurisASTFirewall(
        config=JurisASTConfig(mode="audit"),
        taint_registry=registry,
        agent_id="test_agent",
    )


@pytest.fixture
def permissive_firewall(registry):
    """Firewall in permissive mode."""
    return JurisASTFirewall(
        config=JurisASTConfig(mode="permissive"),
        taint_registry=registry,
        agent_id="test_agent",
    )


# ─── Helper tool functions ───────────────────────────────────────────────────


@tainted_source(Jurisdiction.EU, Classification.PII)
def fetch_customer_eu(customer_id: str) -> str:
    return f"John Doe, Berlin (ID: {customer_id})"


@tainted_source(Jurisdiction.EU, Classification.SENSITIVE_PII)
def fetch_financial_eu(account_id: str) -> str:
    return f"Bank account: {account_id}, Balance: €10,000"


@tainted_sink(Jurisdiction.US, Classification.PUBLIC)
def send_to_us_analytics(payload: str) -> str:
    return f"sent: {payload}"


@tainted_sink(Jurisdiction.EU, Classification.SENSITIVE_PII)
def save_to_eu_db(data: str) -> str:
    return f"saved: {data}"


@declassifier(
    output_label=LABEL_PUBLIC,
    max_bits=1.0,
    output_type="bool",
)
def extract_sentiment(text: str) -> bool:
    return True


@agent_handoff(target_agent_id="summarizer")
def send_to_summarizer(data: str) -> str:
    return f"handed off: {data}"


def undecorated_tool(x: str) -> str:
    return f"processed: {x}"


# ─── SAFE Flow Tests ─────────────────────────────────────────────────────────


class TestSafeFlows:
    """Tests where flows are verified as SAFE."""

    def test_source_tool_always_safe(self, enforce_firewall):
        """Source tools (data entry) are always SAFE since they have no sink."""
        result = enforce_firewall.verify_tool_call(
            tool_name="fetch_customer_eu",
            tool_args={"customer_id": "C42"},
            tool_callable=fetch_customer_eu,
        )
        assert result.status == "SAFE"

    def test_untainted_sink_safe(self, enforce_firewall):
        """Sink with no tainted inputs is SAFE."""
        result = enforce_firewall.verify_tool_call(
            tool_name="send_to_us_analytics",
            tool_args={"payload": "untainted_data"},
            tool_callable=send_to_us_analytics,
        )
        assert result.status == "SAFE"

    def test_eu_data_to_eu_sink_safe(self, enforce_firewall, registry):
        """EU data flowing to an EU sink is SAFE."""
        registry.register(
            "eu_record",
            TaintedValue(value="EU data", label=LABEL_EU_PII),
        )
        enforce_firewall.taint_registry = registry

        result = enforce_firewall.verify_tool_call(
            tool_name="save_to_eu_db",
            tool_args={"data": "eu_record"},
            tool_callable=save_to_eu_db,
        )
        assert result.status == "SAFE"

    def test_declassifier_safe(self, enforce_firewall, registry):
        """Declassifier tool is always SAFE (it produces downgraded data)."""
        registry.register(
            "sensitive_data",
            TaintedValue(value="PII text", label=LABEL_EU_PII),
        )
        enforce_firewall.taint_registry = registry

        result = enforce_firewall.verify_tool_call(
            tool_name="extract_sentiment",
            tool_args={"text": "sensitive_data"},
            tool_callable=extract_sentiment,
        )
        assert result.status == "SAFE"

    def test_undecorated_tool_safe(self, enforce_firewall):
        """Undecorated tools (transforms) are always SAFE."""
        result = enforce_firewall.verify_tool_call(
            tool_name="undecorated_tool",
            tool_args={"x": "hello"},
            tool_callable=undecorated_tool,
        )
        assert result.status == "SAFE"


# ─── VIOLATION Tests ──────────────────────────────────────────────────────────


class TestViolationDetection:
    """Tests where flows are detected as VIOLATIONS."""

    def test_eu_pii_to_us_sink_violation_enforced(self, enforce_firewall, registry):
        """EU PII flowing to US sink raises TaintViolationError in enforce mode."""
        registry.register(
            "customer_data",
            TaintedValue(value="EU PII", label=LABEL_EU_PII),
        )
        enforce_firewall.taint_registry = registry

        with pytest.raises(TaintViolationError) as exc_info:
            enforce_firewall.verify_tool_call(
                tool_name="send_to_us_analytics",
                tool_args={"payload": "customer_data"},
                tool_callable=send_to_us_analytics,
            )

        assert "violation" in str(exc_info.value).lower() or "IFC" in str(exc_info.value)

    def test_eu_sensitive_pii_to_us_sink_violation(self, enforce_firewall, registry):
        """EU SENSITIVE_PII flowing to US sink is VIOLATION."""
        registry.register(
            "financial_data",
            TaintedValue(value="Financial", label=LABEL_EU_SENSITIVE_PII),
        )
        enforce_firewall.taint_registry = registry

        with pytest.raises(TaintViolationError):
            enforce_firewall.verify_tool_call(
                tool_name="send_to_us_analytics",
                tool_args={"payload": "financial_data"},
                tool_callable=send_to_us_analytics,
            )


# ─── Enforcement Mode Tests ──────────────────────────────────────────────────


class TestEnforcementModes:
    """Tests for different enforcement modes."""

    def test_audit_mode_allows_violation(self, audit_firewall, registry):
        """Audit mode logs but does not raise on violation."""
        registry.register(
            "customer_data",
            TaintedValue(value="EU PII", label=LABEL_EU_PII),
        )
        audit_firewall.taint_registry = registry

        # Should NOT raise
        result = audit_firewall.verify_tool_call(
            tool_name="send_to_us_analytics",
            tool_args={"payload": "customer_data"},
            tool_callable=send_to_us_analytics,
        )
        assert result.status == "VIOLATION"

    def test_permissive_mode_allows_violation(self, permissive_firewall, registry):
        """Permissive mode allows violations without raising."""
        registry.register(
            "customer_data",
            TaintedValue(value="EU PII", label=LABEL_EU_PII),
        )
        permissive_firewall.taint_registry = registry

        result = permissive_firewall.verify_tool_call(
            tool_name="send_to_us_analytics",
            tool_args={"payload": "customer_data"},
            tool_callable=send_to_us_analytics,
        )
        assert result.status == "VIOLATION"


# ─── Audit Log Tests ─────────────────────────────────────────────────────────


class TestAuditLog:
    """Tests for audit log tracking."""

    def test_safe_verification_logged(self, enforce_firewall):
        """SAFE verifications are logged."""
        enforce_firewall.verify_tool_call(
            tool_name="fetch_customer_eu",
            tool_args={"customer_id": "C42"},
            tool_callable=fetch_customer_eu,
        )
        assert len(enforce_firewall.audit_log) == 1
        assert enforce_firewall.audit_log[0].status == "SAFE"

    def test_violation_logged_in_audit_mode(self, audit_firewall, registry):
        """Violations are logged in audit mode."""
        registry.register(
            "customer_data",
            TaintedValue(value="EU PII", label=LABEL_EU_PII),
        )
        audit_firewall.taint_registry = registry

        audit_firewall.verify_tool_call(
            tool_name="send_to_us_analytics",
            tool_args={"payload": "customer_data"},
            tool_callable=send_to_us_analytics,
        )
        assert len(audit_firewall.audit_log) == 1
        assert audit_firewall.audit_log[0].status == "VIOLATION"

    def test_multiple_verifications_accumulated(self, enforce_firewall):
        """Multiple verifications are accumulated in order."""
        enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C1"},
            fetch_customer_eu,
        )
        enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C2"},
            fetch_customer_eu,
        )
        assert len(enforce_firewall.audit_log) == 2

    def test_timing_tracked(self, enforce_firewall):
        """Total verification time is tracked."""
        enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C1"},
            fetch_customer_eu,
        )
        assert enforce_firewall.total_verification_time_ms > 0


# ─── Tool Result Recording Tests ─────────────────────────────────────────────


class TestRecordToolResult:
    """Tests for recording tool results and taint registration."""

    def test_source_result_registered(self, enforce_firewall):
        """Source tool result is registered as a TaintedValue."""
        tv = enforce_firewall.record_tool_result(
            tool_name="fetch_customer_eu",
            tool_args={"customer_id": "C42"},
            tool_result="John Doe, Berlin",
            tool_callable=fetch_customer_eu,
        )

        assert tv is not None
        assert tv.label == LABEL_EU_PII
        assert tv.value == "John Doe, Berlin"

        # Should be in the registry
        assert enforce_firewall.taint_registry.lookup("fetch_customer_eu") is not None

    def test_string_result_double_registered(self, enforce_firewall):
        """String results are registered under both tool name and value."""
        enforce_firewall.record_tool_result(
            tool_name="fetch_customer_eu",
            tool_args={"customer_id": "C42"},
            tool_result="record_C42",
            tool_callable=fetch_customer_eu,
        )

        assert enforce_firewall.taint_registry.lookup("fetch_customer_eu") is not None
        assert enforce_firewall.taint_registry.lookup("record_C42") is not None

    def test_declassifier_result_registered(self, enforce_firewall):
        """Declassifier tool result is registered with downgraded label."""
        tv = enforce_firewall.record_tool_result(
            tool_name="extract_sentiment",
            tool_args={"text": "some text"},
            tool_result="positive",
            tool_callable=extract_sentiment,
        )

        assert tv is not None
        assert tv.label == LABEL_PUBLIC

    def test_sink_result_not_registered(self, enforce_firewall):
        """Sink tool results are NOT registered as tainted values."""
        tv = enforce_firewall.record_tool_result(
            tool_name="send_to_us_analytics",
            tool_args={"payload": "data"},
            tool_result="sent",
            tool_callable=send_to_us_analytics,
        )
        assert tv is None

    def test_undecorated_result_not_registered(self, enforce_firewall):
        """Undecorated tool results are NOT registered."""
        tv = enforce_firewall.record_tool_result(
            tool_name="undecorated_tool",
            tool_args={"x": "hello"},
            tool_result="processed",
            tool_callable=undecorated_tool,
        )
        assert tv is None


# ─── Stats Tests ──────────────────────────────────────────────────────────────


class TestFirewallStats:
    """Tests for firewall statistics."""

    def test_initial_stats(self, enforce_firewall):
        """Initial stats are zeroed."""
        stats = enforce_firewall.stats
        assert stats["total_verifications"] == 0
        assert stats["safe_count"] == 0
        assert stats["violation_count"] == 0
        assert stats["total_verification_time_ms"] == 0.0

    def test_stats_after_verification(self, enforce_firewall):
        """Stats update after verification."""
        enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C1"},
            fetch_customer_eu,
        )
        stats = enforce_firewall.stats
        assert stats["total_verifications"] == 1
        assert stats["safe_count"] == 1
        assert stats["mode"] == "enforce"

    def test_reset_clears_state(self, enforce_firewall):
        """Reset clears audit log and taint registry."""
        enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C1"},
            fetch_customer_eu,
        )
        enforce_firewall.record_tool_result(
            "fetch_customer_eu",
            {"customer_id": "C1"},
            "data",
            fetch_customer_eu,
        )

        enforce_firewall.reset()

        assert len(enforce_firewall.audit_log) == 0
        assert enforce_firewall.taint_registry.size == 0
        assert enforce_firewall.total_verification_time_ms == 0.0


# ─── End-to-End Firewall Lifecycle Tests ──────────────────────────────────────


class TestFirewallLifecycle:
    """End-to-end tests for the firewall verify → record lifecycle."""

    def test_source_then_safe_sink(self, enforce_firewall):
        """Source → EU sink lifecycle is safe end-to-end."""
        # Step 1: Verify source call
        result = enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C42"},
            fetch_customer_eu,
        )
        assert result.status == "SAFE"

        # Step 2: Record source result (registers taint)
        enforce_firewall.record_tool_result(
            "fetch_customer_eu",
            {"customer_id": "C42"},
            "John Doe, Berlin",
            fetch_customer_eu,
        )

        # Step 3: Verify EU sink call (EU data → EU sink = SAFE)
        result = enforce_firewall.verify_tool_call(
            "save_to_eu_db",
            {"data": "fetch_customer_eu"},
            save_to_eu_db,
        )
        assert result.status == "SAFE"

    def test_source_then_blocked_sink(self, enforce_firewall):
        """Source → US sink lifecycle blocks the cross-border flow."""
        # Step 1: Source
        enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C42"},
            fetch_customer_eu,
        )
        enforce_firewall.record_tool_result(
            "fetch_customer_eu",
            {"customer_id": "C42"},
            "John Doe, Berlin",
            fetch_customer_eu,
        )

        # Step 2: US sink → BLOCKED
        with pytest.raises(TaintViolationError):
            enforce_firewall.verify_tool_call(
                "send_to_us_analytics",
                {"payload": "fetch_customer_eu"},
                send_to_us_analytics,
            )

    def test_source_declassify_then_safe_sink(self, enforce_firewall):
        """Source → Declassify → US sink lifecycle is safe."""
        # Step 1: Source
        enforce_firewall.verify_tool_call(
            "fetch_customer_eu",
            {"customer_id": "C42"},
            fetch_customer_eu,
        )
        enforce_firewall.record_tool_result(
            "fetch_customer_eu",
            {"customer_id": "C42"},
            "John Doe, Berlin",
            fetch_customer_eu,
        )

        # Step 2: Declassify
        result = enforce_firewall.verify_tool_call(
            "extract_sentiment",
            {"text": "fetch_customer_eu"},
            extract_sentiment,
        )
        assert result.status == "SAFE"

        enforce_firewall.record_tool_result(
            "extract_sentiment",
            {"text": "fetch_customer_eu"},
            "positive",
            extract_sentiment,
        )

        # Step 3: US sink with declassified data → SAFE
        result = enforce_firewall.verify_tool_call(
            "send_to_us_analytics",
            {"payload": "extract_sentiment"},
            send_to_us_analytics,
        )
        assert result.status == "SAFE"
