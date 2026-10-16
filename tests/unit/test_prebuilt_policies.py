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
    LABEL_APAC_PII,
    LABEL_APAC_RESTRICTED,
    LABEL_EU_PII,
    LABEL_EU_RESTRICTED,
    LABEL_EU_SENSITIVE_PII,
    LABEL_PUBLIC,
    LABEL_US_INTERNAL,
    LABEL_US_PII,
    LABEL_US_RESTRICTED,
    LABEL_US_SENSITIVE_PII,
    Classification,
    Jurisdiction,
    SecurityLabel,
)
from jurisast_core.solver import Z3SolverEngine
from jurisast_policies import (
    APAC_SOVEREIGNTY_COMPLIANCE,
    CCPA_CPRA_COMPLIANCE,
    COLORADO_AI_ACT_COMPLIANCE,
    DORA_COMPLIANCE,
    DPDPA_COMPLIANCE,
    EU_AI_ACT_COMPLIANCE,
    GDPR_DATA_SOVEREIGNTY,
    HIPAA_COMPLIANCE,
    ISO_42001_NIST_AI_RMF_COMPLIANCE,
    ITAR_EAR_COMPLIANCE,
    PCI_DSS_COMPLIANCE,
    PIPL_COMPLIANCE,
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



class TestHIPAAPolicy:
    """Verification tests for HIPAA_COMPLIANCE policy."""

    def test_phi_to_external_blocked(self):
        phi_label = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"phi"}),
        )
        builder = ExecutionGraphBuilder(agent_id="health_agent")
        src = builder.add_source("fetch_patient_ehr", phi_label)
        builder.add_sink(
            "external_analytics",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(HIPAA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("phi_no_external_export" in c for c in result.violated_constraints)

    def test_phi_within_clinical_boundary_allowed(self):
        phi_label = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"phi"}),
        )
        builder = ExecutionGraphBuilder(agent_id="health_agent")
        src = builder.add_source("fetch_patient_ehr", phi_label)
        builder.add_sink(
            "hospital_internal_db",
            target_jurisdiction=Jurisdiction.INTERNAL,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(HIPAA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"

    def test_phi_declassification_to_external_allowed(self):
        phi_label = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"phi"}),
        )
        builder = ExecutionGraphBuilder(agent_id="health_agent")
        src = builder.add_source("fetch_patient_ehr", phi_label)
        declass = builder.add_declassifier(
            input_node_id=src.node_id,
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=4,
        )
        builder.add_sink(
            "research_clearinghouse",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.PUBLIC,
            input_node_ids=[declass.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(HIPAA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"


class TestCCPAPolicy:
    """Verification tests for CCPA_CPRA_COMPLIANCE policy."""

    def test_sensitive_personal_information_to_external_blocked(self):
        spi_label = SecurityLabel(
            jurisdiction=Jurisdiction.US,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"spi"}),
        )
        builder = ExecutionGraphBuilder(agent_id="consumer_agent")
        src = builder.add_source("get_consumer_spi", spi_label)
        builder.add_sink(
            "third_party_ad_network",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(CCPA_CPRA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("sensitive_personal_information_isolation" in c for c in result.violated_constraints)

    def test_do_not_sell_pii_to_external_blocked(self):
        builder = ExecutionGraphBuilder(agent_id="consumer_agent")
        src = builder.add_source("get_california_user", LABEL_US_PII)
        builder.add_sink(
            "external_analytics",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(CCPA_CPRA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("do_not_sell_or_share_pii" in c for c in result.violated_constraints)

    def test_us_pii_within_us_allowed(self):
        builder = ExecutionGraphBuilder(agent_id="consumer_agent")
        src = builder.add_source("get_california_user", LABEL_US_PII)
        builder.add_sink(
            "internal_crm",
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(CCPA_CPRA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"


class TestDORAPolicy:
    """Verification tests for DORA_COMPLIANCE policy."""

    def test_core_banking_to_external_blocked(self):
        ledger_label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"core_banking"}),
        )
        builder = ExecutionGraphBuilder(agent_id="bank_agent")
        src = builder.add_source("read_core_ledger", ledger_label)
        builder.add_sink(
            "third_party_saas",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.CONFIDENTIAL,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(DORA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("critical_ict_financial_isolation" in c for c in result.violated_constraints)

    def test_core_banking_to_eu_internal_allowed(self):
        ledger_label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"core_banking"}),
        )
        builder = ExecutionGraphBuilder(agent_id="bank_agent")
        src = builder.add_source("read_core_ledger", ledger_label)
        builder.add_sink(
            "eu_financial_vault",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.CONFIDENTIAL,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(DORA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"


class TestAPACSovereigntyPolicy:
    """Verification tests for APAC_SOVEREIGNTY_COMPLIANCE (PIPL & DPDPA) policy."""

    def test_ciio_restricted_data_to_us_blocked(self):
        builder = ExecutionGraphBuilder(agent_id="apac_agent")
        src = builder.add_source("fetch_ciio_records", LABEL_APAC_RESTRICTED)
        builder.add_sink(
            "external_cloud_archive",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.RESTRICTED,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(APAC_SOVEREIGNTY_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("ciio_critical_data_localization" in c for c in result.violated_constraints)

    def test_dpdpa_restricted_to_external_blocked(self):
        dpdpa_label = SecurityLabel(
            jurisdiction=Jurisdiction.APAC,
            classification=Classification.PUBLIC,
            compartments=frozenset({"dpdpa_restricted"}),
        )
        builder = ExecutionGraphBuilder(agent_id="apac_agent")
        src = builder.add_source("fetch_minor_user", dpdpa_label)
        builder.add_sink(
            "external_analytics",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.PUBLIC,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(DPDPA_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("dpdpa_restricted_transfers_blocked" in c for c in result.violated_constraints)

    def test_apac_pii_within_apac_allowed(self):
        builder = ExecutionGraphBuilder(agent_id="apac_agent")
        src = builder.add_source("get_apac_customer", LABEL_APAC_PII)
        builder.add_sink(
            "domestic_datacenter",
            target_jurisdiction=Jurisdiction.APAC,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(APAC_SOVEREIGNTY_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"


class TestITAREARPolicy:
    """Verification tests for ITAR_EAR_COMPLIANCE defense export policy."""

    def test_defense_technical_data_to_foreign_blocked(self):
        itar_label = SecurityLabel(
            jurisdiction=Jurisdiction.US,
            classification=Classification.RESTRICTED,
            compartments=frozenset({"itar_defense_data"}),
        )
        builder = ExecutionGraphBuilder(agent_id="defense_agent")
        src = builder.add_source("read_usml_blueprint", itar_label)
        builder.add_sink(
            "foreign_partner_api",
            target_jurisdiction=Jurisdiction.APAC,
            max_classification=Classification.RESTRICTED,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(ITAR_EAR_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("defense_technical_data_absolute_isolation" in c for c in result.violated_constraints)

    def test_ear_dual_use_to_external_blocked(self):
        builder = ExecutionGraphBuilder(agent_id="defense_agent")
        src = builder.add_source("read_ccl_spec", LABEL_US_RESTRICTED)
        builder.add_sink(
            "external_telemetry",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.RESTRICTED,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(ITAR_EAR_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("ear_dual_use_technology_transfer_block" in c for c in result.violated_constraints)

    def test_defense_technical_data_within_us_allowed(self):
        itar_label = SecurityLabel(
            jurisdiction=Jurisdiction.US,
            classification=Classification.RESTRICTED,
            compartments=frozenset({"itar_defense_data"}),
        )
        builder = ExecutionGraphBuilder(agent_id="defense_agent")
        src = builder.add_source("read_usml_blueprint", itar_label)
        builder.add_sink(
            "us_dod_secure_cloud",
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.RESTRICTED,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(ITAR_EAR_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"


class TestColoradoAIActPolicy:
    """Verification tests for COLORADO_AI_ACT_COMPLIANCE policy."""

    def test_consequential_decision_biometrics_to_external_blocked(self):
        ai_profile_label = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"consequential_decision"}),
        )
        builder = ExecutionGraphBuilder(agent_id="hr_eval_agent")
        src = builder.add_source("evaluate_candidate_score", ai_profile_label)
        builder.add_sink(
            "unmonitored_recruiter_webhook",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(COLORADO_AI_ACT_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("consequential_decision_biometric_isolation" in c for c in result.violated_constraints)

    def test_consequential_decision_internal_allowed(self):
        ai_profile_label = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"consequential_decision"}),
        )
        builder = ExecutionGraphBuilder(agent_id="hr_eval_agent")
        src = builder.add_source("evaluate_candidate_score", ai_profile_label)
        builder.add_sink(
            "internal_hr_system",
            target_jurisdiction=Jurisdiction.INTERNAL,
            max_classification=Classification.SENSITIVE_PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(COLORADO_AI_ACT_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"


class TestISO42001NISTPolicy:
    """Verification tests for ISO_42001_NIST_AI_RMF_COMPLIANCE policy."""

    def test_model_weights_quarantined_from_external(self):
        model_label = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"model_weights"}),
        )
        builder = ExecutionGraphBuilder(agent_id="llm_ops_agent")
        src = builder.add_source("export_checkpoint", model_label)
        builder.add_sink(
            "public_huggingface_repo",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.CONFIDENTIAL,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(ISO_42001_NIST_AI_RMF_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("untrusted_ai_tool_quarantine" in c for c in result.violated_constraints)

    def test_safe_feature_extraction_declassification_allowed(self):
        builder = ExecutionGraphBuilder(agent_id="llm_ops_agent")
        src = builder.add_source("eval_user_inputs", LABEL_EU_PII)
        declass = builder.add_declassifier(
            input_node_id=src.node_id,
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=1,
        )
        builder.add_sink(
            "external_datadog_metric",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.PUBLIC,
            input_node_ids=[declass.node_id],
        )
        graph = builder.build()

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(ISO_42001_NIST_AI_RMF_COMPLIANCE, graph)

        result = solver.verify()
        assert result.status == "SAFE"


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

    def test_firewall_enforces_multi_regulatory_policies_simultaneously(self):
        multi_policies = [
            GDPR_DATA_SOVEREIGNTY,
            HIPAA_COMPLIANCE,
            ITAR_EAR_COMPLIANCE,
        ]
        firewall = JurisASTFirewall(
            policies=multi_policies,
            agent_id="multi_reg_agent",
        )

        @tainted_source(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"phi"}),
        )
        def fetch_patient_chart() -> str:
            return "Patient Diagnosis Record"

        @tainted_sink(
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.SENSITIVE_PII,
        )
        def send_to_external_webhook(data: str) -> str:
            return "posted"

        firewall.record_tool_result("fetch_patient_chart", {}, "Patient Diagnosis Record", fetch_patient_chart)

        with pytest.raises(TaintViolationError) as exc_info:
            firewall.verify_tool_call(
                tool_name="send_to_external_webhook",
                tool_args={"data": "Patient Diagnosis Record"},
                tool_callable=send_to_external_webhook,
            )

        assert "phi_no_external_export" in str(exc_info.value)
        assert firewall.stats["violation_count"] == 1

