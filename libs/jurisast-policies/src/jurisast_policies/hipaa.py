"""
HIPAA Regulatory Policy Set for JurisAST.

Implements Health Insurance Portability and Accountability Act (HIPAA) rules
for multi-agent healthcare and clinical workflows:
- Security Rule 45 CFR § 164.312(e)(1): Transmission security & ePHI isolation
- Privacy Rule 45 CFR § 164.502(b): Minimum Necessary standard & de-identification
- Security Rule 45 CFR § 164.312(b): Audit controls and activity logs
- Privacy Rule 45 CFR § 164.514: Safe Harbor de-identification requirements
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

HIPAA_COMPLIANCE = PolicySet(
    policy_name="HIPAA_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces HIPAA Privacy & Security Rules across multi-agent execution graphs. "
        "Isolates Protected Health Information (PHI/ePHI) within clinical boundaries, "
        "mandates Safe Harbor de-identification for external research/analytics, and "
        "enforces audit logging for all patient record access."
    ),
    constraints=[
        FlowConstraint(
            name="phi_no_external_export",
            description="Protected Health Information (PHI/ePHI) cannot flow to external or unvetted foreign sinks",
            regulation="HIPAA Security Rule § 164.312(e)(1)",
            forbidden_compartments=frozenset({"phi", "ephi", "clinical_record"}),
            forbidden_sink_jurisdictions={
                Jurisdiction.EXTERNAL,
                Jurisdiction.APAC,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="phi_declassification_minimum_necessary",
            description="Electronic Health Records (Sensitive PII) require de-identification before flowing to external sinks",
            regulation="HIPAA Privacy Rule § 164.502(b) / § 164.514",
            source_classification_min=Classification.SENSITIVE_PII,
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            allow_declassified=True,
            action=ConstraintAction.DECLASSIFY_REQUIRED,
        ),
        FlowConstraint(
            name="phi_audit_access_trail",
            description="All computational access, transmission, or transformation of patient records must be audit-logged",
            regulation="HIPAA Security Rule § 164.312(b)",
            source_classification_min=Classification.SENSITIVE_PII,
            action=ConstraintAction.AUDIT,
        ),
    ],
)
