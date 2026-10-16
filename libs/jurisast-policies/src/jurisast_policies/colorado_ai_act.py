"""
Colorado Artificial Intelligence Act (SB 24-205) Policy Set for JurisAST.

Implements consumer protection constraints for high-risk AI systems in Colorado (effective 2026):
- Section 6-1-1702: Duty of care to protect consumers from algorithmic discrimination in consequential decisions
- Section 6-1-1703: Safeguards for sensitive demographic and protected class evaluation indicators
- Section 6-1-1704: Mandatory impact assessment, model transparency, and audit provenance logging
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

COLORADO_AI_ACT_COMPLIANCE = PolicySet(
    policy_name="COLORADO_AI_ACT_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces the Colorado Artificial Intelligence Act (SB 24-205). "
        "Restricts high-risk AI systems that make or substantially influence consequential decisions "
        "(employment, housing, lending, insurance, healthcare, legal services), preventing algorithmic "
        "discrimination and enforcing strict audit provenance."
    ),
    constraints=[
        FlowConstraint(
            name="consequential_decision_biometric_isolation",
            description="Sensitive demographic, biometric, or consumer profile data used for consequential decisions cannot flow to unmonitored external decision sinks",
            regulation="Colorado AI Act § 6-1-1702",
            source_classification_min=Classification.SENSITIVE_PII,
            forbidden_compartments=frozenset({
                "consequential_decision",
                "algorithmic_profile",
                "protected_class",
            }),
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="algorithmic_discrimination_restricted_guard",
            description="Restricted evaluation profiles and algorithmic discrimination risk factors cannot exit internal enterprise boundaries",
            regulation="Colorado AI Act § 6-1-1703",
            source_classification_min=Classification.RESTRICTED,
            forbidden_sink_jurisdictions={
                Jurisdiction.EXTERNAL,
                Jurisdiction.APAC,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="consequential_decision_audit_logging",
            description="Mandatory impact assessment logging, execution graph recording, and audit provenance for consequential decision workflows",
            regulation="Colorado AI Act § 6-1-1704",
            source_classification_min=Classification.PII,
            action=ConstraintAction.AUDIT,
        ),
    ],
)
