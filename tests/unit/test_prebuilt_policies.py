"""
Unit Tests for Pre-built Policies and PolicyBuilder Integration.

Verifies:
- GDPR_DATA_SOVEREIGNTY
- EU_AI_ACT_COMPLIANCE
- PCI_DSS_COMPLIANCE
- PolicyBuilder custom policies
- JurisASTFirewall integration with policies active
"""

from __future__ import annotations

import pytest

from jurisast_core.ast_ir import ExecutionGraphBuilder
from jurisast_core.exceptions import TaintViolationError
from jurisast_core.labels import (
    LABEL_EU_PII,
    LABEL_EU_RESTRICTED,
    LABEL_EU_SENSITIVE_PII,
    LABEL_PUBLIC,
    Classification,
    Jurisdiction,
    SecurityLabel,
)
from jurisast_core.solver import Z3SolverEngine
from jurisast_policies import (
    EU_AI_ACT_COMPLIANCE,
    GDPR_DATA_SOVEREIGNTY,
    PCI_DSS_COMPLIANCE,
    PolicyBuilder,
)
from jurisast_pydantic.capability import JurisASTFirewall
from jurisast_pydantic.decorators import tainted_sink, tainted_source


class TestGDPRPolicy:
    """Verification tests for GDPR_DATA_SOVEREIGNTY policy."""

    def test_eu_pii_to_us_sink_blocked(self):
        builder = ExecutionGraphBuilder(agent_id="gdpr_agent")
        src = builder.add_source("get_eu_customer", LABEL_EU_PII)
        builder.add_sink(
            "us_analytics",
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(GDPR_DATA_SOVEREIGNTY, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("eu_pii_no_us_transfer" in c for c in result.violated_constraints)

    def test_eu_pii_to_eu_sink_allowed(self):
        builder = ExecutionGraphBuilder(agent_id="gdpr_agent")
        src = builder.add_source("get_eu_customer", LABEL_EU_PII)
        builder.add_sink(
            "eu_internal_analytics",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(GDPR_DATA_SOVEREIGNTY, graph)

        result = solver.verify()
        assert result.status == "SAFE"

    def test_eu_restricted_no_export_blocked(self):
        builder = ExecutionGraphBuilder(agent_id="gdpr_agent")
        src = builder.add_source("get_board_keys", LABEL_EU_RESTRICTED)
        builder.add_sink(
            "apac_backup",
            target_jurisdiction=Jurisdiction.APAC,
            max_classification=Classification.RESTRICTED,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(GDPR_DATA_SOVEREIGNTY, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("eu_restricted_no_export" in c for c in result.violated_constraints)


class TestEUAiActPolicy:
    """Verification tests for EU_AI_ACT_COMPLIANCE policy."""

    def test_biometric_data_to_external_blocked(self):
        biometric_label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"biometrics"}),
        )
        builder = ExecutionGraphBuilder(agent_id="ai_agent")
        src = builder.add_source("scan_face", biometric_label)
        builder.add_sink(
            "external_inference_api",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(EU_AI_ACT_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("biometric_data_isolation" in c for c in result.violated_constraints)

    def test_prohibited_social_scoring_blocked(self):
        scoring_label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.RESTRICTED,
        )
        builder = ExecutionGraphBuilder(agent_id="ai_agent")
        src = builder.add_source("compute_citizen_score", scoring_label)
        builder.add_sink(
            "partner_us_portal",
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.RESTRICTED,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(EU_AI_ACT_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("prohibited_social_scoring_guard" in c for c in result.violated_constraints)


class TestPCIDSSPolicy:
    """Verification tests for PCI_DSS_COMPLIANCE policy."""

    def test_cardholder_data_to_external_blocked(self):
        pan_label = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"pci_cardholder"}),
        )
        builder = ExecutionGraphBuilder(agent_id="fin_agent")
        src = builder.add_source("read_pan", pan_label)
        builder.add_sink(
            "external_crm",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.CONFIDENTIAL,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(PCI_DSS_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("cardholder_data_isolation" in c for c in result.violated_constraints)


class TestPolicyBuilder:
    """Tests for the custom PolicyBuilder API."""

    def test_custom_hipaa_policy(self):
        hipaa_policy = (
            PolicyBuilder("HIPAA_COMPLIANCE")
            .with_description("HIPAA Privacy Rule ePHI constraints")
            .with_version("2.0.0")
            .block_cross_border(
                name="phi_no_export",
                source=Jurisdiction.US,
                forbidden_sinks={Jurisdiction.EXTERNAL, Jurisdiction.APAC},
                min_classification=Classification.SENSITIVE_PII,
                regulation="HIPAA § 164.312",
            )
            .isolate_compartment(
                name="ehr_isolation",
                compartment="ehr_records",
                forbidden_sinks={Jurisdiction.EXTERNAL},
            )
            .build()
        )

        assert hipaa_policy.policy_name == "HIPAA_COMPLIANCE"
        assert len(hipaa_policy.constraints) == 2

        # Verify against graph
        builder = ExecutionGraphBuilder(agent_id="health_agent")
        src = builder.add_source(
            "fetch_patient",
            SecurityLabel(
                jurisdiction=Jurisdiction.US,
                classification=Classification.SENSITIVE_PII,
            ),
        )
        builder.add_sink(
            "export_apac",
            target_jurisdiction=Jurisdiction.APAC,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(hipaa_policy, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("phi_no_export" in c for c in result.violated_constraints)


class TestFirewallPolicyIntegration:
    """Tests verifying JurisASTFirewall with attached policies."""

    def test_firewall_enforces_gdpr_policy(self):
        firewall = JurisASTFirewall(
            policies=GDPR_DATA_SOVEREIGNTY,
            agent_id="firewall_test_agent",
        )

        @tainted_source(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        def fetch_eu_user() -> str:
            return "EU citizen data"

        @tainted_sink(
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PII,
        )
        def send_to_us(payload: str) -> str:
            return "sent"

        # Record source
        firewall.record_tool_result("fetch_eu_user", {}, "EU citizen data", fetch_eu_user)

        # Attempting to call send_to_us with EU citizen data should be BLOCKED by GDPR policy
        with pytest.raises(TaintViolationError) as exc_info:
            firewall.verify_tool_call(
                tool_name="send_to_us",
                tool_args={"payload": "EU citizen data"},
                tool_callable=send_to_us,
            )

        assert "eu_pii_no_us_transfer" in str(exc_info.value)
        assert firewall.stats["has_policies"] is True
        assert firewall.stats["violation_count"] == 1
