"""
ITAR & EAR Defense Export Control Policy Set for JurisAST.

Implements strict defense and dual-use export control rules:
- ITAR 22 CFR § 120.10 & § 126.1: Technical data relating to United States Munitions List (USML) items
- EAR 15 CFR § 734.2(b): Deemed export and transfer of Commerce Control List (CCL) dual-use technology
- ITAR 22 CFR § 120.11: Absolute prohibition on declassification/public release without State Department authorization
- ITAR 22 CFR § 122.5: Mandatory 5-year cryptographic record-keeping and audit tracking
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

ITAR_EAR_COMPLIANCE = PolicySet(
    policy_name="ITAR_EAR_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces strict US defense export controls (ITAR 22 CFR 120-130 / EAR 15 CFR 730-774). "
        "Implements zero-tolerance containment for United States Munitions List (USML) technical data, "
        "defense articles, and Controlled Unclassified Information (CUI). "
        "Forbids any data egress outside the US sovereign boundary."
    ),
    constraints=[
        FlowConstraint(
            name="defense_technical_data_absolute_isolation",
            description="Defense technical data (USML items, military specs, munitions blueprints) is strictly prohibited from exiting US sovereign boundary",
            regulation="ITAR 22 CFR § 120.10 / § 126.1",
            forbidden_compartments=frozenset({"itar_defense_data", "usml_technical_data", "cui_specified"}),
            forbidden_sink_jurisdictions={
                Jurisdiction.EXTERNAL,
                Jurisdiction.APAC,
                Jurisdiction.EU,
                Jurisdiction.UK,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="ear_dual_use_technology_transfer_block",
            description="Restricted dual-use technology under Commerce Control List (CCL) cannot be transferred outside US jurisdiction",
            regulation="EAR 15 CFR § 734.2(b)",
            source_jurisdictions={Jurisdiction.US},
            source_classification_min=Classification.RESTRICTED,
            forbidden_sink_jurisdictions={
                Jurisdiction.EXTERNAL,
                Jurisdiction.APAC,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="defense_no_unauthorized_external_release",
            description="Defense technical data cannot flow to external sinks without explicit State Department public release clearance",
            regulation="ITAR 22 CFR § 120.11",
            forbidden_compartments=frozenset({"itar_defense_data"}),
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="itar_audit_logging",
            description="Mandatory cryptographic audit tracking for all defense technical data access and agent tool executions",
            regulation="ITAR 22 CFR § 122.5",
            source_classification_min=Classification.CONFIDENTIAL,
            action=ConstraintAction.AUDIT,
        ),
    ],
)

# Alias for convenience
ITAR_COMPLIANCE = ITAR_EAR_COMPLIANCE
