"""
Unit tests for JurisAST Tainted Context and JurisASTDeps.

Tests the JurisASTDeps dataclass, label resolution from arguments,
verification tracking, and TaintRegistry integration.
"""

import pytest

from jurisast_core.config import JurisASTConfig
from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    LABEL_PUBLIC,
    LABEL_EU_PII,
    LABEL_EU_SENSITIVE_PII,
)
from jurisast_core.solver import VerificationResult
from jurisast_core.taint import TaintedValue, TaintRegistry

from jurisast_pydantic.tainted_context import JurisASTDeps


class TestJurisASTDepsConstruction:
    """Tests for JurisASTDeps construction and defaults."""

    def test_default_construction(self):
        """JurisASTDeps can be constructed with defaults."""
        deps = JurisASTDeps()
        assert deps.taint_registry is not None
        assert deps.agent_id.startswith("agent_")
        assert deps.session_id.startswith("session_")
        assert isinstance(deps.config, JurisASTConfig)
        assert deps.firewall is None
        assert deps.audit_log == []

    def test_custom_agent_id(self):
        """Custom agent_id is respected."""
        deps = JurisASTDeps(agent_id="fintech_agent")
        assert deps.agent_id == "fintech_agent"

    def test_shared_taint_registry(self):
        """Multiple deps instances can share a TaintRegistry."""
        registry = TaintRegistry()
        deps1 = JurisASTDeps(taint_registry=registry, agent_id="agent_1")
        deps2 = JurisASTDeps(taint_registry=registry, agent_id="agent_2")

        # They share the same registry
        assert deps1.taint_registry is deps2.taint_registry

        # Taint registered by one is visible to the other
        tv = TaintedValue.create(
            value="EU customer data",
            label=LABEL_EU_PII,
            source_tool="fetch_customer",
            agent_id="agent_1",
        )
        deps1.taint_registry.register("customer_data", tv)

        assert deps2.taint_registry.lookup("customer_data") is not None
        assert deps2.taint_registry.lookup("customer_data").label == LABEL_EU_PII

    def test_custom_config(self):
        """Custom config is threaded through."""
        config = JurisASTConfig(mode="audit")
        deps = JurisASTDeps(config=config)
        assert deps.config.mode == "audit"


class TestRegisterTaintedValue:
    """Tests for JurisASTDeps.register_tainted_value."""

    def test_register_creates_tainted_value(self):
        """register_tainted_value creates and returns a TaintedValue."""
        deps = JurisASTDeps(agent_id="test_agent")
        tv = deps.register_tainted_value(
            key="customer_record",
            value="John Doe, Berlin",
            label=LABEL_EU_PII,
            source_tool="fetch_customer",
        )

        assert isinstance(tv, TaintedValue)
        assert tv.value == "John Doe, Berlin"
        assert tv.label == LABEL_EU_PII
        assert len(tv.provenance) == 1
        assert tv.provenance[0].source_tool == "fetch_customer"
        assert tv.provenance[0].agent_id == "test_agent"

    def test_register_adds_to_registry(self):
        """register_tainted_value adds the value to the taint registry."""
        deps = JurisASTDeps()
        deps.register_tainted_value(
            key="my_key",
            value="data",
            label=LABEL_EU_PII,
            source_tool="tool",
        )

        assert deps.taint_registry.lookup("my_key") is not None

    def test_register_with_details(self):
        """Optional details are stored in provenance."""
        deps = JurisASTDeps(agent_id="test_agent")
        tv = deps.register_tainted_value(
            key="k",
            value="data",
            label=LABEL_EU_PII,
            source_tool="tool",
            details="Customer financial record from DB",
        )

        assert tv.provenance[0].details == "Customer financial record from DB"


class TestGetLabelForArgs:
    """Tests for JurisASTDeps.get_label_for_args."""

    def test_no_tainted_args_returns_public(self):
        """When no args reference tainted values, returns LABEL_PUBLIC."""
        deps = JurisASTDeps()
        label = deps.get_label_for_args({"name": "untainted"})
        assert label == LABEL_PUBLIC

    def test_single_tainted_arg(self):
        """Single tainted arg returns its label."""
        deps = JurisASTDeps()
        deps.taint_registry.register(
            "customer_data",
            TaintedValue(value="data", label=LABEL_EU_PII),
        )

        label = deps.get_label_for_args({"payload": "customer_data"})
        assert label == LABEL_EU_PII

    def test_multiple_tainted_args_joined(self):
        """Multiple tainted args returns the joined (LUB) label."""
        deps = JurisASTDeps()

        deps.taint_registry.register(
            "eu_data",
            TaintedValue(value="eu", label=LABEL_EU_PII),
        )
        us_label = SecurityLabel(
            jurisdiction=Jurisdiction.US,
            classification=Classification.CONFIDENTIAL,
        )
        deps.taint_registry.register(
            "us_data",
            TaintedValue(value="us", label=us_label),
        )

        label = deps.get_label_for_args({"a": "eu_data", "b": "us_data"})
        # Join: max jurisdiction = US(30), max classification = PII(30)
        assert label.jurisdiction == Jurisdiction.US
        assert label.classification == Classification.PII


class TestVerificationTracking:
    """Tests for JurisASTDeps verification audit tracking."""

    def test_initial_counts_zero(self):
        """Initial verification counts are zero."""
        deps = JurisASTDeps()
        assert deps.verification_count == 0
        assert deps.violation_count == 0
        assert deps.safe_count == 0

    def test_record_safe_verification(self):
        """Recording a SAFE verification increments safe_count."""
        deps = JurisASTDeps()
        deps.record_verification(
            VerificationResult(status="SAFE", latency_ms=1.0)
        )
        assert deps.verification_count == 1
        assert deps.safe_count == 1
        assert deps.violation_count == 0

    def test_record_violation(self):
        """Recording a VIOLATION increments violation_count."""
        deps = JurisASTDeps()
        deps.record_verification(
            VerificationResult(status="VIOLATION", latency_ms=2.0)
        )
        assert deps.verification_count == 1
        assert deps.violation_count == 1
        assert deps.safe_count == 0

    def test_mixed_results(self):
        """Mixed results are tracked correctly."""
        deps = JurisASTDeps()
        deps.record_verification(
            VerificationResult(status="SAFE", latency_ms=1.0)
        )
        deps.record_verification(
            VerificationResult(status="VIOLATION", latency_ms=2.0)
        )
        deps.record_verification(
            VerificationResult(status="SAFE", latency_ms=1.5)
        )

        assert deps.verification_count == 3
        assert deps.safe_count == 2
        assert deps.violation_count == 1
