"""
PCI-DSS v4.0 Regulatory Policy Set for JurisAST.

Implements Payment Card Industry Data Security Standard (PCI-DSS v4.0) rules:
- Requirement 1.3: Network access to and from the cardholder data environment (CDE) is restricted
- Requirement 3.3: Sensitive authentication data (SAD) and PAN masking/bounding
- Requirement 3.4: Primary account numbers (PAN) secured everywhere it is stored/handled
- Requirement 10.2: Audit trails for all access to system components
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

PCI_DSS_COMPLIANCE = PolicySet(
    policy_name="PCI_DSS_COMPLIANCE_v4",
    version="1.0.0",
    description=(
        "Enforces PCI-DSS v4.0 cardholder data environment (CDE) boundary protections. "
        "Guarantees that primary account numbers (PAN), card verification values (CVV), "
        "and cardholder compartment data cannot be exfiltrated to non-PCI external sinks."
    ),
    constraints=[
        FlowConstraint(
            name="cardholder_data_isolation",
            description="Cardholder data (pci_cardholder compartment) cannot exit CDE to external sinks",
            regulation="PCI-DSS Requirement 1.3 / 3.4",
            forbidden_compartments=frozenset({"pci_cardholder", "cde"}),
            forbidden_sink_jurisdictions={
                Jurisdiction.EXTERNAL,
                Jurisdiction.US,
                Jurisdiction.APAC,
            },
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="financial_pan_no_public_sink",
            description="Sensitive financial data cannot flow to PUBLIC sinks without declassification (masking)",
            regulation="PCI-DSS Requirement 3.3",
            source_classification_min=Classification.SENSITIVE_PII,
            sink_classification_max=Classification.INTERNAL_ONLY,
            allow_declassified=True,
            action=ConstraintAction.DECLASSIFY_REQUIRED,
        ),
        FlowConstraint(
            name="cde_audit_logging",
            description="All cardholder and financial data access must be fully audit-logged",
            regulation="PCI-DSS Requirement 10.2",
            source_classification_min=Classification.CONFIDENTIAL,
            action=ConstraintAction.AUDIT,
        ),
    ],
)
