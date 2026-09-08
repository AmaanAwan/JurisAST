"""
Unit Tests for Regulatory Policy Engine (policies.py).

Tests FlowConstraint, PolicySet, Z3 compilation, assumption generation,
and unsat core isolation of regulatory violations.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from jurisast_core.ast_ir import ExecutionGraphBuilder
from jurisast_core.exceptions import TaintViolationError
from jurisast_core.labels import (
    LABEL_EU_PII,
    LABEL_EU_SENSITIVE_PII,
    LABEL_PUBLIC,
    Classification,
    Jurisdiction,
    SecurityLabel,
)
from jurisast_core.policies import (
    ConstraintAction,
    FlowConstraint,
    PolicySet,
)
from jurisast_core.solver import Z3SolverEngine


class TestFlowConstraintModel:
    """Tests for FlowConstraint data model and behavior."""

    def test_create_valid_constraint(self):
        fc = FlowConstraint(
            name="test_rule",
            description="Test description",
            regulation="Reg 123",
            source_jurisdictions={Jurisdiction.EU},
            source_classification_min=Classification.PII,
            forbidden_sink_jurisdictions={Jurisdiction.US, Jurisdiction.EXTERNAL},
            action=ConstraintAction.BLOCK,
        )
        assert fc.name == "test_rule"
        assert fc.action == ConstraintAction.BLOCK
        assert fc.source_jurisdictions == {Jurisdiction.EU}
        assert fc.allow_declassified is True

    def test_immutability(self):
        fc = FlowConstraint(
            name="test_immut",
            description="Immutable test",
        )
        with pytest.raises(ValidationError):
            fc.name = "changed"  # type: ignore

    def test_matches_sink(self):
        fc = FlowConstraint(
            name="sink_matcher",
            description="Match US and External",
            forbidden_sink_jurisdictions={Jurisdiction.US, Jurisdiction.EXTERNAL},
            sink_classification_max=Classification.INTERNAL_ONLY,
        )
        # Matches forbidden jurisdiction
        assert fc.matches_sink(Jurisdiction.US, Classification.PUBLIC) is True
        assert fc.matches_sink(Jurisdiction.EXTERNAL, Classification.INTERNAL_ONLY) is True
        # Matches exceeding classification max
        assert fc.matches_sink(Jurisdiction.EU, Classification.CONFIDENTIAL) is True
        # Does not match allowed jurisdiction within max classification
        assert fc.matches_sink(Jurisdiction.EU, Classification.PUBLIC) is False


class TestPolicySetZ3Compilation:
    """Tests compiling PolicySet into Z3 constraints."""

    def test_policy_set_basic(self):
        policy = PolicySet(
            policy_name="TEST_POLICY",
            version="1.0.0",
            description="Test policy set",
        )
        fc = FlowConstraint(name="c1", description="desc")
        policy.add_constraint(fc)
        assert len(policy.constraints) == 1
        assert policy.get_constraint("c1") == fc
        assert policy.get_constraint("nonexistent") is None

    def test_compliant_graph_passes_policy(self):
        """EU data to EU sink complies with cross-border policy."""
        builder = ExecutionGraphBuilder(agent_id="test_agent")
        src = builder.add_source("fetch_eu", LABEL_EU_PII)
        builder.add_sink(
            "eu_endpoint",
            target_jurisdiction=Jurisdiction.EU,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        policy = PolicySet(
            policy_name="EU_CROSS_BORDER",
            constraints=[
                FlowConstraint(
                    name="no_us_export",
                    description="No EU PII to US",
                    source_jurisdictions={Jurisdiction.EU},
                    source_classification_min=Classification.PII,
                    forbidden_sink_jurisdictions={Jurisdiction.US},
                    action=ConstraintAction.BLOCK,
                )
            ],
        )

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        assumptions = solver.add_policy_constraints(policy, graph)

        result = solver.verify()
        assert result.status == "SAFE"
        # No constraints triggered for EU sink
        assert len(assumptions) == 0

    def test_violating_graph_blocked_by_policy(self):
        """EU PII to US sink is blocked by policy, identified in unsat core."""
        builder = ExecutionGraphBuilder(agent_id="test_agent")
        src = builder.add_source("fetch_eu", LABEL_EU_PII, node_id="src_eu")
        builder.add_sink(
            "us_endpoint",
            target_jurisdiction=Jurisdiction.US,
            # Even if sink accepts PII, the regulatory policy forbids EU data transfer
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
            node_id="snk_us",
        )
        graph = builder.build()

        policy = PolicySet(
            policy_name="EU_SOVEREIGNTY",
            constraints=[
                FlowConstraint(
                    name="eu_no_us",
                    description="EU PII cannot be transferred to US systems",
                    regulation="GDPR Art. 44",
                    source_jurisdictions={Jurisdiction.EU},
                    source_classification_min=Classification.PII,
                    forbidden_sink_jurisdictions={Jurisdiction.US},
                    action=ConstraintAction.BLOCK,
                )
            ],
        )

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        assumptions = solver.add_policy_constraints(policy, graph)

        assert len(assumptions) == 1
        assert "policy__EU_SOVEREIGNTY__eu_no_us" in assumptions[0]

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("policy__EU_SOVEREIGNTY__eu_no_us" in c for c in result.violated_constraints)
        assert any("GDPR Art. 44" in d for d in result.violation_details)

    def test_declassified_flow_passes_policy(self):
        """EU PII declassified to PUBLIC satisfies DECLASSIFY_REQUIRED policy."""
        builder = ExecutionGraphBuilder(agent_id="test_agent")
        src = builder.add_source("fetch_eu", LABEL_EU_PII, node_id="src_eu")
        dcl = builder.add_declassifier(
            input_node_id=src.node_id,
            output_type="bool",
            output_label=LABEL_PUBLIC,
            max_bits=1.0,
            node_id="dcl_node",
        )
        builder.add_sink(
            "external_analytics",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.PUBLIC,
            input_node_ids=[dcl.node_id],
            node_id="snk_ext",
        )
        graph = builder.build()

        policy = PolicySet(
            policy_name="EXTERNAL_GUARD",
            constraints=[
                FlowConstraint(
                    name="require_dcl",
                    description="EU PII requires declassification before external sink",
                    source_jurisdictions={Jurisdiction.EU},
                    source_classification_min=Classification.PII,
                    forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
                    allow_declassified=True,
                    action=ConstraintAction.DECLASSIFY_REQUIRED,
                )
            ],
        )

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(policy, graph)

        result = solver.verify()
        assert result.status == "SAFE"

    def test_audit_action_does_not_block(self):
        """Action=AUDIT does not generate blocking Z3 constraints."""
        builder = ExecutionGraphBuilder(agent_id="test_agent")
        src = builder.add_source("fetch_eu", LABEL_EU_PII)
        builder.add_sink(
            "us_endpoint",
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        policy = PolicySet(
            policy_name="AUDIT_POLICY",
            constraints=[
                FlowConstraint(
                    name="audit_only",
                    description="Audit flow",
                    source_jurisdictions={Jurisdiction.EU},
                    forbidden_sink_jurisdictions={Jurisdiction.US},
                    action=ConstraintAction.AUDIT,
                )
            ],
        )

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        assumptions = solver.add_policy_constraints(policy, graph)

        # Audit action produces no blocking assumptions
        assert len(assumptions) == 0

    def test_forbidden_compartment_blocks_flow(self):
        """Flow with forbidden compartment is blocked by policy."""
        label_with_cde = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"pci_cardholder"}),
        )
        builder = ExecutionGraphBuilder(agent_id="test_agent")
        src = builder.add_source("fetch_card", label_with_cde, node_id="src_card")
        builder.add_sink(
            "non_pci_sink",
            target_jurisdiction=Jurisdiction.EXTERNAL,
            max_classification=Classification.CONFIDENTIAL,
            input_node_ids=[src.node_id],
            node_id="snk_ext",
        )
        graph = builder.build()

        policy = PolicySet(
            policy_name="PCI_ISOLATION",
            constraints=[
                FlowConstraint(
                    name="no_cardholder_external",
                    description="PCI cardholder data cannot exit to external sinks",
                    forbidden_compartments=frozenset({"pci_cardholder"}),
                    forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
                    action=ConstraintAction.BLOCK,
                )
            ],
        )

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(policy, graph)

        result = solver.verify()
        assert result.status == "VIOLATION"
        assert any("no_cardholder_external" in c for c in result.violated_constraints)

    def test_verify_or_raise_with_policy_violation(self):
        """verify_or_raise raises TaintViolationError with policy constraint details."""
        builder = ExecutionGraphBuilder(agent_id="test_agent")
        src = builder.add_source("fetch_eu", LABEL_EU_PII)
        builder.add_sink(
            "us_endpoint",
            target_jurisdiction=Jurisdiction.US,
            max_classification=Classification.PII,
            input_node_ids=[src.node_id],
        )
        graph = builder.build()

        policy = PolicySet(
            policy_name="SOVEREIGNTY",
            constraints=[
                FlowConstraint(
                    name="block_us",
                    description="Block EU to US",
                    source_jurisdictions={Jurisdiction.EU},
                    forbidden_sink_jurisdictions={Jurisdiction.US},
                )
            ],
        )

        solver = Z3SolverEngine(timeout_ms=500)
        solver.encode_graph(graph)
        solver.add_policy_constraints(policy, graph)

        with pytest.raises(TaintViolationError) as exc_info:
            solver.verify_or_raise()

        assert "block_us" in str(exc_info.value)
