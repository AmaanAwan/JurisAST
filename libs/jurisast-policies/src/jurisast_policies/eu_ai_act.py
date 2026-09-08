"""
EU AI Act Compliance Policy Set for JurisAST.

Implements information flow constraints corresponding to the European Union AI Act:
- Article 5: Prohibited artificial intelligence practices (e.g. social scoring, untargeted scraping)
- Article 10: Data and data governance for high-risk AI systems (biometric, sensitive data isolation)
- Article 12: Record-keeping and automatic logging
- Article 14: Human oversight requirements
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

EU_AI_ACT_COMPLIANCE = PolicySet(
    policy_name="EU_AI_ACT_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces EU AI Act governance requirements on multi-agent execution graphs, "
        "preventing unauthorized dissemination of high-risk data, biometric indicators, "
        "and unmonitored decision flows."
    ),
    constraints=[
        FlowConstraint(
            name="biometric_data_isolation",
            description="Biometric and high-risk sensitive data cannot flow to unconstrained external endpoints",
            regulation="EU AI Act Article 10",
            source_classification_min=Classification.SENSITIVE_PII,
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            forbidden_compartments=frozenset({"biometrics"}),
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="prohibited_social_scoring_guard",
            description="Restricted evaluation profiles and behavior scoring data cannot exit internal boundaries",
            regulation="EU AI Act Article 5",
            source_classification_min=Classification.RESTRICTED,
            forbidden_sink_jurisdictions={
                Jurisdiction.EXTERNAL,
                Jurisdiction.US,
                Jurisdiction.APAC,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="high_risk_ai_audit_logging",
            description="High-risk AI processing involving PII must maintain full audit provenance",
            regulation="EU AI Act Article 12 / 14",
            source_classification_min=Classification.PII,
            action=ConstraintAction.AUDIT,
        ),
    ],
)
