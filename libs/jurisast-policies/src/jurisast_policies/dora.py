"""
DORA Regulatory Policy Set for JurisAST.

Implements the Digital Operational Resilience Act (Regulation (EU) 2022/2554)
for EU financial institutions and ICT third-party service providers:
- Article 28 / Article 30: ICT third-party risk management and core financial system isolation
- Article 29: Preliminary assessment and declassification for critical ICT service contracts
- Article 12: ICT-related incident detection, automatic logging, and monitoring
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

DORA_COMPLIANCE = PolicySet(
    policy_name="DORA_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces EU Digital Operational Resilience Act (DORA) constraints. "
        "Isolates critical ICT infrastructure and core banking ledgers from untrusted external providers, "
        "requires declassification for external telemetry, and mandates comprehensive ICT operational logging."
    ),
    constraints=[
        FlowConstraint(
            name="critical_ict_financial_isolation",
            description="Core banking ledgers and critical ICT infrastructure cannot flow to unvetted external or third-country ICT service providers",
            regulation="DORA Article 28 / Article 30",
            forbidden_compartments=frozenset({"core_banking", "ict_critical", "financial_ledger"}),
            forbidden_sink_jurisdictions={
                Jurisdiction.EXTERNAL,
                Jurisdiction.APAC,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="ict_third_party_declassification",
            description="Confidential financial ICT architecture and resilience metrics require declassification before transmission to external vendor telemetry",
            regulation="DORA Article 29",
            source_classification_min=Classification.CONFIDENTIAL,
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            allow_declassified=True,
            action=ConstraintAction.DECLASSIFY_REQUIRED,
        ),
        FlowConstraint(
            name="mandatory_ict_resilience_logging",
            description="Continuous audit logging and provenance recording of all ICT events, tool calls, and third-party interactions",
            regulation="DORA Article 12",
            source_classification_min=Classification.INTERNAL_ONLY,
            action=ConstraintAction.AUDIT,
        ),
    ],
)
