"""
APAC Sovereignty Policy Set (China PIPL & India DPDPA) for JurisAST.

Implements Asia-Pacific data sovereignty and cross-border constraints:
- China PIPL Article 38: Security assessment for cross-border personal information provision
- China PIPL Article 40: Critical Information Infrastructure Operator (CIIO) data localization
- India DPDPA 2023 Section 16: Restrictions on transfer of personal data outside India
- India DPDPA 2023 Section 8 / PIPL Article 55: Data fiduciary audit requirements
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

APAC_SOVEREIGNTY_COMPLIANCE = PolicySet(
    policy_name="APAC_SOVEREIGNTY_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces Asia-Pacific data sovereignty constraints under China PIPL and India DPDPA 2023. "
        "Restricts cross-border transfer of domestic PII, isolates Critical Information Infrastructure (CIIO) data, "
        "and enforces statutory audit and declassification requirements."
    ),
    constraints=[
        FlowConstraint(
            name="ciio_critical_data_localization",
            description="Critical Information Infrastructure (CIIO) restricted data cannot exit sovereign boundaries to US or EXTERNAL sinks",
            regulation="China PIPL Article 40",
            source_jurisdictions={Jurisdiction.APAC},
            source_classification_min=Classification.RESTRICTED,
            forbidden_sink_jurisdictions={
                Jurisdiction.US,
                Jurisdiction.EXTERNAL,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="pipl_cross_border_assessment_required",
            description="APAC personal information (PII) requires certified declassification before flowing to external sinks",
            regulation="China PIPL Article 38",
            source_jurisdictions={Jurisdiction.APAC},
            source_classification_min=Classification.PII,
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            allow_declassified=True,
            action=ConstraintAction.DECLASSIFY_REQUIRED,
        ),
        FlowConstraint(
            name="dpdpa_restricted_transfers_blocked",
            description="Restricted personal data and minor records under DPDPA cannot flow to unapproved external endpoints",
            regulation="India DPDPA Section 16",
            source_jurisdictions={Jurisdiction.APAC},
            forbidden_compartments=frozenset({"dpdpa_restricted", "minor_data"}),
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="apac_data_fiduciary_audit",
            description="Mandatory audit logging for data fiduciary processing and cross-border agent activities",
            regulation="India DPDPA Section 8 / China PIPL Article 55",
            source_jurisdictions={Jurisdiction.APAC},
            source_classification_min=Classification.PII,
            action=ConstraintAction.AUDIT,
        ),
    ],
)

# Standalone convenience policies
PIPL_COMPLIANCE = PolicySet(
    policy_name="PIPL_COMPLIANCE_v1",
    version="1.0.0",
    description="China Personal Information Protection Law (PIPL) compliance policy.",
    constraints=[
        c for c in APAC_SOVEREIGNTY_COMPLIANCE.constraints if "PIPL" in c.regulation
    ],
)

DPDPA_COMPLIANCE = PolicySet(
    policy_name="DPDPA_COMPLIANCE_v1",
    version="1.0.0",
    description="India Digital Personal Data Protection Act (DPDPA 2023) compliance policy.",
    constraints=[
        c for c in APAC_SOVEREIGNTY_COMPLIANCE.constraints if "DPDPA" in c.regulation
    ],
)
