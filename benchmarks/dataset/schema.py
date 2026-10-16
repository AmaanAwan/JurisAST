"""
Formal Specification and Pydantic Schema for the Ultimate Regulatory Benchmark.

Defines:
- 11 Regulatory Frameworks (GDPR, EU AI Act, PCI-DSS, HIPAA, CCPA, DORA, APAC, ITAR, Colorado AI, ISO 42001)
- 10 Violation Types (Direct, Cross-Border, Compartment, Multi-Hop, Over-Budget, Join Collision, etc.)
- 5 Non-Violation Types (Intra-Sovereign, Clearance-Allowed, Shannon-Bounded, Safe Harbor, Public)
- Domain-Specific Declassification Categories with Shannon Information Bounds
- Typed BenchmarkCase and BenchmarkSuite specifications
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional
from pydantic import BaseModel, Field

from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel


# ─── 1. Regulatory Frameworks ──────────────────────────────────────────────────


class RegulationType(str, Enum):
    """The 11 major regulatory and AI governance frameworks supported by JurisAST."""
    GDPR = "GDPR"                                        # EU General Data Protection Regulation (Art. 44-49, 9, 5)
    EU_AI_ACT = "EU_AI_ACT"                              # EU AI Act (Art. 5 Prohibited AI, Art. 10/12 High-Risk AI)
    PCI_DSS = "PCI_DSS"                                  # PCI-DSS v4.0 Cardholder Data Environment (Req. 3.3, 3.4)
    HIPAA = "HIPAA"                                      # US Health Insurance Portability & Accountability Act (§ 164.312/514)
    CCPA_CPRA = "CCPA_CPRA"                              # California Consumer Privacy Act / CPRA (Cal. Civ. Code § 1798.121)
    DORA = "DORA"                                        # EU Digital Operational Resilience Act for Financial Entities (Art. 28-30)
    CHINA_PIPL = "CHINA_PIPL"                            # China Personal Information Protection Law (Art. 38, 40 CIIO)
    INDIA_DPDPA = "INDIA_DPDPA"                          # India Digital Personal Data Protection Act 2023 (Sec. 16)
    ITAR_EAR = "ITAR_EAR"                                # US Defense USML & Dual-Use Commerce CCL Export Controls
    COLORADO_AI_ACT = "COLORADO_AI_ACT"                  # Colorado AI Act SB 24-205 (Algorithmic Discrimination Protection)
    ISO_42001_NIST = "ISO_42001_NIST"                    # ISO/IEC 42001 & NIST AI Risk Management Framework 1.0


# ─── 2. Violation Categories (Including Edge Cases) ───────────────────────────


class ViolationType(str, Enum):
    """Categorization of regulatory violations and adversarial attack vectors."""
    # Standard Core Violations
    DIRECT_CROSS_BORDER_EXFILTRATION = "DIRECT_CROSS_BORDER_EXFILTRATION"
    """Direct transfer of sovereign data to non-adequate foreign jurisdiction (e.g. EU PII to US/EXTERNAL)."""

    CLASSIFICATION_EXCEEDED = "CLASSIFICATION_EXCEEDED"
    """Data sensitivity exceeds sink's maximum clearance (e.g. CONFIDENTIAL or SENSITIVE_PII to PUBLIC)."""

    COMPARTMENT_ISOLATION_BREACH = "COMPARTMENT_ISOLATION_BREACH"
    """Need-to-know compartment missing from sink clearance (e.g. {phi}, {core_banking}, {itar_defense_data})."""

    # Advanced / Adversarial Edge Cases
    MULTI_HOP_SWARM_LAUNDERING = "MULTI_HOP_SWARM_LAUNDERING"
    """Adversarial attempt to wash taint by passing data across 2+ intermediary helper agents."""

    SEMANTIC_TRANSFORM_PRESERVATION = "SEMANTIC_TRANSFORM_PRESERVATION"
    """LLM summarizes, translates, or reformats sensitive data; taint must not be dropped."""

    OVER_BUDGET_DECLASSIFICATION = "OVER_BUDGET_DECLASSIFICATION"
    """Declassification output exceeds allowable Shannon information budget (e.g., claiming 4 bits but outputting 128 bits)."""

    PSEUDO_ANONYMIZATION_LEAK = "PSEUDO_ANONYMIZATION_LEAK"
    """Partial masking where residual entropy permits direct re-identification of individuals or secrets."""

    PROHIBITED_PURPOSE_OVERRIDE = "PROHIBITED_PURPOSE_OVERRIDE"
    """Tool invocation for a legally banned purpose (e.g. social scoring, unauthorized consequential decisions, data sale)."""

    UNACCREDITED_AI_TOOL_DISPATCH = "UNACCREDITED_AI_TOOL_DISPATCH"
    """Proprietary model weights, training corpora, or system prompts dispatched to third-party unvetted execution sinks."""

    EDGE_CASE_JOIN_COLLISION = "EDGE_CASE_JOIN_COLLISION"
    """Contaminated data merged with clean data; joined output inherits highest taint lattice upper bound."""


# ─── 3. Non-Violation (Compliant) Categories ──────────────────────────────────


class NonViolationType(str, Enum):
    """Categorization of compliant, legally protected agent workflows."""
    INTRA_SOVEREIGN_PROCESSING = "INTRA_SOVEREIGN_PROCESSING"
    """Flow operates completely within the origin jurisdiction boundary (e.g. EU -> EU, US -> US, APAC -> APAC)."""

    DOMESTIC_CLEARANCE_ALLOWED = "DOMESTIC_CLEARANCE_ALLOWED"
    """Sink clearance dominates data classification and holds required compartments."""

    SHANNON_BOUNDED_DECLASSIFICATION = "SHANNON_BOUNDED_DECLASSIFICATION"
    """High-security data safely minimized via strict constrained decoding within entropy budget (I <= log2(N))."""

    SAFE_HARBOR_ANONYMIZED = "SAFE_HARBOR_ANONYMIZED"
    """Compliant de-identification stripping all 18 HIPAA identifiers or GDPR personal tags."""

    PUBLIC_OPEN_PIPELINE = "PUBLIC_OPEN_PIPELINE"
    """Public, unrestricted data (PUBLIC/INTERNAL) routed to public or third-party sinks."""

    CLEARED_MULTI_AGENT_CHAIN = "CLEARED_MULTI_AGENT_CHAIN"
    """Multi-agent swarm execution where all participating agents and sinks possess sufficient clearance."""


# ─── 4. Domain-Specific Declassification Schemes ──────────────────────────────


class DeclassificationDomain(str, Enum):
    """Domain-specific declassification mechanics."""
    HEALTHCARE_SAFE_HARBOR = "HEALTHCARE_SAFE_HARBOR"
    """HIPAA: ePHI/Patient EHR -> 1-bit boolean cohort trial eligibility (I <= 1.0 bit)."""

    FINTECH_TOKENIZATION = "FINTECH_TOKENIZATION"
    """PCI-DSS/DORA: Cardholder PAN/CVV -> 4-bit integer token or boolean fraud score (I <= 4.0 bits)."""

    CUSTOMER_SUPPORT_TRIAGE = "CUSTOMER_SUPPORT_TRIAGE"
    """GDPR/CCPA: EU/US Consumer PII -> 4-bit categorized support error code (I <= 4.0 bits)."""

    CORPORATE_STRATEGY_ANALYSIS = "CORPORATE_STRATEGY_ANALYSIS"
    """M&A/Board-only: Top-secret acquisition memo -> 2-bit market sentiment enum (I <= 2.0 bits)."""

    AI_GOVERNANCE_TELEMETRY = "AI_GOVERNANCE_TELEMETRY"
    """ISO 42001/NIST: Model weights/activations -> 1-bit drift/anomaly boolean flag (I <= 1.0 bit)."""

    CONSUMER_PRIVACY_AGGREGATION = "CONSUMER_PRIVACY_AGGREGATION"
    """CCPA/DPDPA: Consumer geolocation/SPI -> 3-bit coarse geographic state/region bucket (I <= 3.0 bits)."""

    DEFENSE_MANUAL_OVERRIDE_TOKEN = "DEFENSE_MANUAL_OVERRIDE_TOKEN"
    """ITAR/EAR: Technical munitions data CANNOT be auto-declassified; requires cryptographic human officer token."""


class DeclassificationSpec(BaseModel):
    """Specification of a safe, Shannon-bounded declassification channel."""
    domain: DeclassificationDomain
    source_classification: Classification
    target_classification: Classification
    output_type: str = Field(description="Constrained output type: bool, enum, int_range")
    cardinality: int = Field(description="Total count of possible discrete output states N")
    max_bits: float = Field(description="Theoretical Shannon mutual information limit log2(N)")
    description: str


# ─── 5. Benchmark Test Case Definition ─────────────────────────────────────────


class BenchmarkCase(BaseModel):
    """
    A single, mathematically specified benchmark test case.
    """
    case_id: str = Field(description="Unique identifier (e.g. TC_GDPR_001)")
    regulation: RegulationType
    is_violation: bool = Field(description="True if this case must be blocked, False if allowed")
    violation_type: Optional[ViolationType] = None
    non_violation_type: Optional[NonViolationType] = None
    declassification_spec: Optional[DeclassificationSpec] = None

    # Source & Sink Properties
    source_tool: str
    source_label: SecurityLabel
    sink_tool: str
    sink_target_jurisdiction: Jurisdiction
    sink_max_classification: Classification
    sink_compartments: FrozenSet[str] = frozenset()

    # Multi-Agent Complexity
    agent_chain_length: int = Field(default=1, description="Number of agents in the execution chain (1 to 4)")
    has_intermediary_transforms: bool = False

    # Regulatory Mapping Ground Truth
    policy_name: str
    expected_unsat_rules: List[str] = Field(default_factory=list)
    threat_narrative: str = Field(description="Real-world enterprise scenario description")
    edge_case_notes: Optional[str] = None


class BenchmarkSuiteCatalog(BaseModel):
    """
    Catalog of benchmark cases grouped by regulation and category.
    """
    suite_version: str = "2.0.0"
    cases: List[BenchmarkCase] = Field(default_factory=list)

    def get_by_regulation(self, regulation: RegulationType) -> List[BenchmarkCase]:
        return [c for c in self.cases if c.regulation == regulation]

    def get_violations(self) -> List[BenchmarkCase]:
        return [c for c in self.cases if c.is_violation]

    def get_compliant(self) -> List[BenchmarkCase]:
        return [c for c in self.cases if not c.is_violation]
