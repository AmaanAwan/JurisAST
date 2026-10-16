"""
GDPR Regulatory Policy Set for JurisAST.

Implements General Data Protection Regulation (GDPR) constraints for multi-agent systems:
- Article 44: General principle for transfers of personal data to third countries
- Article 45: Transfers on the basis of an adequacy decision
- Article 9: Processing of special categories of personal data (Sensitive PII)
- Article 32: Security of processing (Restricted data isolation)
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

GDPR_DATA_SOVEREIGNTY = PolicySet(
    policy_name="GDPR_DATA_SOVEREIGNTY_v1",
    version="1.0.0",
    description=(
        "Enforces cross-border data transfer restrictions under GDPR Chapter V. "
        "Prevents EU citizen personal data (PII) and sensitive personal data (Art. 9) "
        "from flowing to non-adequate jurisdictions (e.g., US, APAC, EXTERNAL) without "
        "controlled declassification."
    ),
    constraints=[
        FlowConstraint(
            name="eu_pii_no_us_transfer",
            description="EU PII/Sensitive PII cannot flow to US external sinks without adequacy decision",
            regulation="GDPR Article 44 / 45",
            source_jurisdictions={Jurisdiction.EU},
            source_classification_min=Classification.PII,
            forbidden_sink_jurisdictions={Jurisdiction.US},
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="eu_restricted_no_export",
            description="EU Restricted data (keys, board secrets) cannot exit EU/INTERNAL boundary",
            regulation="GDPR Article 32",
            source_jurisdictions={Jurisdiction.EU},
            source_classification_min=Classification.RESTRICTED,
            forbidden_sink_jurisdictions={
                Jurisdiction.US,
                Jurisdiction.APAC,
                Jurisdiction.EXTERNAL,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="eu_pii_no_apac_transfer",
            description="EU PII/Sensitive PII cannot flow to APAC third countries without adequacy decision",
            regulation="GDPR Article 44 / 45",
            source_jurisdictions={Jurisdiction.EU},
            source_classification_min=Classification.PII,
            forbidden_sink_jurisdictions={Jurisdiction.APAC},
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="eu_pii_no_external_without_declassification",
            description="EU PII cannot reach any EXTERNAL sink without verified declassification",
            regulation="GDPR Article 44",
            source_jurisdictions={Jurisdiction.EU},
            source_classification_min=Classification.PII,
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            allow_declassified=True,
            action=ConstraintAction.DECLASSIFY_REQUIRED,
        ),
        FlowConstraint(
            name="eu_sensitive_pii_audit_all",
            description="All flows of EU Sensitive PII (Art. 9 special category data) must be audited",
            regulation="GDPR Article 9",
            source_jurisdictions={Jurisdiction.EU},
            source_classification_min=Classification.SENSITIVE_PII,
            action=ConstraintAction.AUDIT,
        ),
    ],
)
