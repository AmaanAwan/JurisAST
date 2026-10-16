"""
CCPA / CPRA Regulatory Policy Set for JurisAST.

Implements California Consumer Privacy Act and California Privacy Rights Act constraints:
- Cal. Civ. Code § 1798.121: Limiting use of Sensitive Personal Information (SPI)
- Cal. Civ. Code § 1798.120: Right to opt-out of sale or sharing of personal information
- Cal. Civ. Code § 1798.100(e): Duty of chain-of-custody and audit accountability
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

CCPA_CPRA_COMPLIANCE = PolicySet(
    policy_name="CCPA_CPRA_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces CCPA/CPRA data privacy constraints across autonomous agent workflows. "
        "Restricts Sensitive Personal Information (SPI) from third-party distribution, "
        "enforces 'Do Not Sell or Share' restrictions on external marketing/analytics sinks, "
        "and mandates audit tracking for consumer personal information."
    ),
    constraints=[
        FlowConstraint(
            name="sensitive_personal_information_isolation",
            description="Sensitive Personal Information (SPI: SSN, precise geolocation, biometrics, credentials) cannot be shared with external third-party sinks",
            regulation="CCPA/CPRA § 1798.121",
            source_classification_min=Classification.SENSITIVE_PII,
            forbidden_compartments=frozenset({"spi", "california_consumer_spi"}),
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="do_not_sell_or_share_pii",
            description="Consumer personal information cannot be transferred to external sinks without declassification/anonymization",
            regulation="CCPA/CPRA § 1798.120",
            source_jurisdictions={Jurisdiction.US},
            source_classification_min=Classification.PII,
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            allow_declassified=True,
            action=ConstraintAction.DECLASSIFY_REQUIRED,
        ),
        FlowConstraint(
            name="consumer_pii_audit_trail",
            description="Mandatory audit trail for California consumer personal information processing and agent tool handoffs",
            regulation="CCPA/CPRA § 1798.100(e)",
            source_classification_min=Classification.PII,
            action=ConstraintAction.AUDIT,
        ),
    ],
)

# Alias for convenience
CCPA_COMPLIANCE = CCPA_CPRA_COMPLIANCE
