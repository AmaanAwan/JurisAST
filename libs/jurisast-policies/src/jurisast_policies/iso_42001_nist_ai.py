"""
ISO/IEC 42001 & NIST AI RMF Governance Policy Set for JurisAST.

Implements international AI management and risk governance controls:
- ISO/IEC 42001:2023 Annex A.6 & NIST AI RMF MANAGE-2.4: Untrusted tool and model quarantine
- ISO/IEC 42001:2023 Annex A.8 & NIST AI RMF MEASURE-2.6: Controlled feature extraction & declassification
- ISO/IEC 42001:2023 Clause 9 & NIST AI RMF GOVERN-1.2: Continuous provenance, monitoring, and auditability
"""

from __future__ import annotations

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet

ISO_42001_NIST_AI_RMF_COMPLIANCE = PolicySet(
    policy_name="ISO_42001_NIST_AI_RMF_COMPLIANCE_v1",
    version="1.0.0",
    description=(
        "Enforces global enterprise AI governance standards under ISO/IEC 42001:2023 and the NIST AI RMF 1.0. "
        "Prevents model weights, proprietary prompts, and confidential training data from leaking to unaccredited external endpoints, "
        "enforces Shannon entropy bounds on feature extraction, and guarantees auditable provenance across multi-agent workflows."
    ),
    constraints=[
        FlowConstraint(
            name="untrusted_ai_tool_quarantine",
            description="Sensitive training data, model weights, and confidential system prompts cannot flow to untrusted external execution sinks",
            regulation="ISO/IEC 42001 Annex A.6 / NIST AI RMF MANAGE-2.4",
            source_classification_min=Classification.CONFIDENTIAL,
            forbidden_compartments=frozenset({
                "model_weights",
                "prompt_template",
                "training_corpus",
            }),
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            action=ConstraintAction.BLOCK,
        ),
        FlowConstraint(
            name="safe_feature_extraction_declassification",
            description="Extraction of operational telemetry and evaluation metrics from sensitive personal data must be declassified under bounded entropy",
            regulation="ISO/IEC 42001 Annex A.8 / NIST AI RMF MEASURE-2.6",
            source_classification_min=Classification.PII,
            forbidden_sink_jurisdictions={Jurisdiction.EXTERNAL},
            allow_declassified=True,
            action=ConstraintAction.DECLASSIFY_REQUIRED,
        ),
        FlowConstraint(
            name="continuous_ai_governance_provenance",
            description="Comprehensive provenance tracking, formal verification logging, and DAG audit records for all agentic reasoning steps",
            regulation="ISO/IEC 42001 Clause 9 / NIST AI RMF GOVERN-1.2",
            source_classification_min=Classification.INTERNAL_ONLY,
            action=ConstraintAction.AUDIT,
        ),
    ],
)

# Convenient alias
AI_GOVERNANCE_COMPLIANCE = ISO_42001_NIST_AI_RMF_COMPLIANCE
