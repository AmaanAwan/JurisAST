# JurisAST — Regulatory Mapping & Compliance Framework

> **Formal translation of cross-border data sovereignty, privacy laws, and AI governance regulations into mathematical Information Flow Control (IFC) lattice invariants.**

> [!WARNING]
> ### ⚠️ Experimental Framework — Not Legal Advice
> JurisAST is an experimental open-source project in active development and early testing. The regulatory mappings provided here are mathematical abstractions for research and technical exploration. **This software has NOT been audited or certified by regulatory authorities, and has NOT yet been fully tested for production compliance.** Do not rely on it as legal advice or as your sole regulatory compliance control.

---

## 1. Regulatory Scope

| Regulation | Jurisdiction | Key Focus Areas |
|:---|:---|:---|
| **GDPR** (General Data Protection Regulation) | European Union / EEA | Articles 44–49 (Cross-Border Transfers), Article 5 (Data Minimization), Article 9 (Special Category Data) |
| **EU AI Act** (2025/2026 Enforcement) | European Union | Article 10 (Data Governance for High-Risk AI), Article 12 (Continuous Record-Keeping & Logging) |
| **UK GDPR & Data Protection Act** | United Kingdom | Post-Brexit adequacy transfer rules |
| **PCI-DSS v4.0** | Global / FinTech | Requirement 3 (Protect Stored Account Data & Prohibit External Exposure) |
| **HIPAA** (Health Insurance Portability & Accountability Act) | United States / Healthcare | § 164.312(e) (ePHI Transmission Security), § 164.502(b) (Minimum Necessary & De-identification) |
| **CCPA / CPRA** | United States (California) | § 1798.121 (Sensitive Personal Information SPI), § 1798.120 (Do Not Sell/Share PII) |
| **DORA** (Digital Operational Resilience Act) | European Union / FinTech | Articles 28–30 (ICT Third-Party Risk), Article 12 (ICT Operational Logging) |
| **APAC Sovereignty (China PIPL & India DPDPA)** | Asia-Pacific (China / India) | PIPL Art. 38/40 (CIIO Localization & Transfer Assessment), DPDPA Sec. 16 (Blacklisted Transfers) |
| **ITAR & EAR** | United States (Defense / Dual-Use) | 22 CFR 120-130 (USML Defense Data Non-Export), 15 CFR 734 (CCL Dual-Use Technology) |
| **Colorado AI Act (SB 24-205)** | United States (Colorado) | § 6-1-1702 (Consequential Decisions & Algorithmic Discrimination Prevention) |
| **ISO/IEC 42001 & NIST AI RMF 1.0** | Global / Enterprise AI | Annex A.6 / MANAGE-2.4 (Untrusted AI Tool Quarantine), Clause 9 (Continuous Provenance & Audit) |

---

## 2. GDPR Mapping to Information Flow Invariants

### 2.1 Article 44 & 45 (General Principle & Adequacy Decisions for Transfers)

- **Legal Mandate**: Personal data (PII) of EU citizens must not be transferred to third countries unless the destination jurisdiction provides an "adequate" level of data protection recognized by the European Commission.
- **JurisAST Formalization**:
  Let $\mathcal{A}_{EU} = \{\text{INTERNAL}, \text{EU}, \text{UK}\}$ denote the set of jurisdictions with active EU adequacy decisions.
  For any execution path from source $s$ to sink $k$:
  $$\forall s \in \text{Sources}, \quad (\text{Jurisdiction}(s) = \text{EU} \land \text{Classification}(s) \ge \text{PII}) \implies (\text{Jurisdiction}(k) \in \mathcal{A}_{EU})$$
- **Z3 Encoding**:
  ```python
  # Invariant: If data is EU PII, target jurisdiction must not exceed EU adequacy threshold
  solver.add(Implies(
      assumption,
      Implies(
          And(jurisdiction(source) == EU, classification(source) >= PII),
          jurisdiction(sink) <= EU  # Restricts destination to EU or INTERNAL
      )
  ))
  ```

### 2.2 Article 9 (Processing of Special Categories of Personal Data)

- **Legal Mandate**: Processing of financial, biometric, health, and sensitive personal data requires elevated safeguards and explicit prohibition from flowing to unrestricted external sinks.
- **JurisAST Formalization**:
  Special category data is assigned `Classification.SENSITIVE_PII` or `Classification.RESTRICTED`. Sinks accepting this data must possess clearance at or above this level:
  $$\forall s, \quad \text{Classification}(s) = \text{SENSITIVE}\_\text{PII} \implies \text{MaxClassification}(k) \ge \text{SENSITIVE}\_\text{PII}$$

### 2.3 Article 5(1)(c) (Data Minimization Principle)

- **Legal Mandate**: Personal data must be adequate, relevant, and limited to what is strictly necessary in relation to the purposes for which they are processed.
- **JurisAST Formalization (Symbolic Declassification)**:
  When an agent requires information derived from PII (e.g., customer sentiment, eligibility flag), the raw data must NOT be passed to downstream sinks. Instead, it must traverse a `DeclassifyNode` where the Shannon information transfer is strictly bounded:
  $$I(\text{Input}; \text{Output}) \le \log_2(|\mathcal{Y}|)$$
  Example: Downgrading an email containing PII to a `bool` sentiment flag limits mutual information transfer to at most 1 bit.

---

## 3. EU AI Act Mapping (Articles 10 & 12)

### 3.1 Article 10 (Data Governance & Provenance)

- **Legal Mandate**: High-risk AI systems must implement continuous data governance, ensuring training and operational data flows are traceable, verified, and free from unauthorized external contamination.
- **JurisAST Formalization**:
  Every runtime data object carries an immutable `TaintedValue[T]` wrapper containing a cryptographic audit log of all transformations (`ProvenanceRecord`).

### 3.2 Article 12 (Record-Keeping & Audit Logging)

- **Legal Mandate**: High-risk autonomous AI workflows must automatically generate comprehensive event logs throughout their lifecycle to enable post-market monitoring and forensic analysis.
- **JurisAST Formalization**:
  The `JurisASTFirewall` logs every verification decision (`VerificationResult`), including:
  1. Complete topological `ExecutionGraph` snapshots
  2. Z3 solver latency in milliseconds
  3. Identified Unsat Cores naming exact offending tool calls
  4. Full provenance history of all referenced variables

---

## 4. FinTech & PCI-DSS v4.0 Compliance

| PCI-DSS Requirement | Requirement Summary | JurisAST Technical Enforcement |
|:---|:---|:---|
| **Requirement 3.3** | Sensitive authentication data (SAD) must not be retained or exposed after authorization. | Labeled `Classification.RESTRICTED`; sinks writing to disk or logs are blocked by Z3. |
| **Requirement 3.4** | Primary Account Numbers (PAN) must be rendered unreadable anywhere they are stored. | Labeled `Classification.SENSITIVE_PII`; cross-border transmission without tokenization or declassification is rejected. |
| **Requirement 6.4** | Prevent unauthorized data modification and injection attacks in enterprise applications. | Dynamic taint tracking ensures injected instructions in payloads cannot force agents to emit cardholder data to attacker-controlled webhooks. |

---

## 5. Healthcare & Life Sciences (HIPAA Compliance)

| HIPAA Rule & Section | Legal Mandate | JurisAST Technical Enforcement |
|:---|:---|:---|
| **Security Rule § 164.312(e)(1)** | Guard against unauthorized access to Electronic Protected Health Information (ePHI) in transit. | Isolates `phi`, `ephi`, and `clinical_record` compartments from flowing to `EXTERNAL` or non-sovereign destinations (`phi_no_external_export`). |
| **Privacy Rule § 164.502(b) & § 164.514** | Minimum Necessary Standard & Safe Harbor De-identification. | Requires that ePHI (`SENSITIVE_PII`) traverse an entropy-bounded `DeclassifyNode` before transmission to external analytics or research repositories (`phi_declassification_minimum_necessary`). |
| **Security Rule § 164.312(b)** | Hardware, software, and procedural mechanisms that record and examine system activity. | Enforces `ConstraintAction.AUDIT` on all access and computational routing of patient records (`phi_audit_access_trail`). |

---

## 6. US Consumer Privacy (CCPA / CPRA Compliance)

| CCPA/CPRA Section | Legal Mandate | JurisAST Technical Enforcement |
|:---|:---|:---|
| **Cal. Civ. Code § 1798.121** | Consumer right to limit use and disclosure of Sensitive Personal Information (SPI: SSN, biometric, geolocation, credentials). | Strictly isolates `spi` and `california_consumer_spi` compartments from third-party or external egress (`sensitive_personal_information_isolation`). |
| **Cal. Civ. Code § 1798.120** | Consumer right to opt out of the sale or sharing of personal information. | Prohibits consumer personal data (`PII`) from routing to third-party commercial sinks without declassification/anonymization (`do_not_sell_or_share_pii`). |
| **Cal. Civ. Code § 1798.100(e)** | Chain of custody and audit accountability for consumer personal data. | Enforces mandatory audit logging (`ConstraintAction.AUDIT`) for all consumer profile transformations and tool invocations (`consumer_pii_audit_trail`). |

---

## 7. EU Financial Operational Resilience (DORA Compliance)

| DORA Article | Regulatory Mandate | JurisAST Technical Enforcement |
|:---|:---|:---|
| **Article 28 / Article 30** | ICT third-party risk management and core financial infrastructure isolation. | Strictly blocks `core_banking`, `ict_critical`, and `financial_ledger` compartments from reaching unvetted external or third-country ICT service providers (`critical_ict_financial_isolation`). |
| **Article 29** | Strict preliminary assessments and disclosure minimization before external vendor telemetry transmission. | Requires verified declassification on `Classification.CONFIDENTIAL` ICT resilience metrics before external dispatch (`ict_third_party_declassification`). |
| **Article 12** | Continuous incident detection, automatic event logging, and telemetry monitoring. | Enforces full audit provenance (`ConstraintAction.AUDIT`) on all internal ICT events and agent handoffs (`mandatory_ict_resilience_logging`). |

---

## 8. Asia-Pacific Data Sovereignty (China PIPL & India DPDPA)

| Regulation & Section | Statutory Requirement | JurisAST Technical Enforcement |
|:---|:---|:---|
| **China PIPL Article 40** | Critical Information Infrastructure Operators (CIIO) must store personal information collected within China locally. | Blocks APAC `Classification.RESTRICTED` data from egressing to `Jurisdiction.US` or `Jurisdiction.EXTERNAL` (`ciio_critical_data_localization`). |
| **China PIPL Article 38** | Certified security assessment and standard contract before cross-border personal info transfers. | Mandates symbolic declassification before APAC consumer `PII` can reach external sinks (`pipl_cross_border_assessment_required`). |
| **India DPDPA Section 16** | Restriction on transfer of personal data outside India to blacklisted jurisdictions. | Isolates `dpdpa_restricted` and `minor_data` compartments from external egress (`dpdpa_restricted_transfers_blocked`). |
| **DPDPA Section 8 / PIPL Article 55** | Data fiduciary audit trail and privacy impact assessment records. | Enforces continuous audit provenance on APAC data fiduciary pipelines (`apac_data_fiduciary_audit`). |

---

## 9. US Defense & Dual-Use Export Controls (ITAR & EAR)

| Regulation & Citation | Statutory Mandate | JurisAST Technical Enforcement |
|:---|:---|:---|
| **ITAR 22 CFR § 120.10 / § 126.1** | Defense technical data on the US Munitions List (USML) cannot be exported or accessed by foreign entities without State Department authorization. | Absolute containment: forbids `itar_defense_data`, `usml_technical_data`, and `cui_specified` from exiting `Jurisdiction.US` to `EXTERNAL`, `APAC`, `EU`, or `UK` (`defense_technical_data_absolute_isolation`). |
| **EAR 15 CFR § 734.2(b)** | Controlled dual-use technology on Commerce Control List (CCL) cannot be transferred outside US jurisdiction. | Prevents `Classification.RESTRICTED` US dual-use tech from reaching external sinks (`ear_dual_use_technology_transfer_block`). |
| **ITAR 22 CFR § 120.11** | Public release prohibition: defense data cannot be declassified without formal approval. | Hard-blocks external release of ITAR technical data even under summarization (`defense_no_unauthorized_external_release`). |
| **ITAR 22 CFR § 122.5** | Rigorous 5-year cryptographic audit record of all access and computational routing. | Enforces `ConstraintAction.AUDIT` on all confidential defense data operations (`itar_audit_logging`). |

---

## 10. State AI Legislation (Colorado AI Act SB 24-205)

| Section | Statutory Mandate | JurisAST Technical Enforcement |
|:---|:---|:---|
| **Section 6-1-1702** | Duty of care to protect consumers from algorithmic discrimination in consequential decisions (employment, housing, lending, healthcare). | Isolates `consequential_decision`, `algorithmic_profile`, and `protected_class` compartments from unmonitored external decision sinks (`consequential_decision_biometric_isolation`). |
| **Section 6-1-1703** | Restricted safeguards on risk factors that could lead to unfair demographic disparity. | Blocks `Classification.RESTRICTED` algorithmic discrimination risk profiles from external/APAC egress (`algorithmic_discrimination_restricted_guard`). |
| **Section 6-1-1704** | Mandatory annual impact assessment documentation, model transparency, and audit provenance. | Continuous audit logging for all consequential decision agent workflows (`consequential_decision_audit_logging`). |

---

## 11. International AI Governance (ISO/IEC 42001 & NIST AI RMF 1.0)

| Standard & Section | Control Mandate | JurisAST Technical Enforcement |
|:---|:---|:---|
| **ISO/IEC 42001 Annex A.6 / NIST AI RMF MANAGE-2.4** | Untrusted AI tool quarantine: protect model weights, proprietary prompts, and confidential training data. | Isolates `model_weights`, `prompt_template`, and `training_corpus` compartments from unaccredited external execution sinks (`untrusted_ai_tool_quarantine`). |
| **ISO/IEC 42001 Annex A.8 / NIST AI RMF MEASURE-2.6** | Safe feature extraction: telemetry and evaluation metrics derived from sensitive data must not leak operational secrets. | Enforces bounded Shannon entropy declassification before telemetry flows to external observability sinks (`safe_feature_extraction_declassification`). |
| **ISO/IEC 42001 Clause 9 / NIST AI RMF GOVERN-1.2** | Continuous governance: formal verification records, graph snapshots, and audit trail generation for all AI decisions. | Enforces mandatory audit logging and DAG verification capture (`continuous_ai_governance_provenance`). |

---

## 12. Regulatory Verification Matrix

| Regulatory Scenario | Source Label | Proposed Sink Target | Expected Outcome | JurisAST Action |
|:---|:---|:---|:---|:---|
| **1. EU Citizen Record to EU Database** | `EU / PII` | `EU / SENSITIVE_PII` | Compliant | **SAFE** (Allowed) |
| **2. EU Financial Record to US Analytics Webhook** | `EU / SENSITIVE_PII` | `US / PUBLIC` | GDPR Art. 44 Breach | **VIOLATION** (Blocked via Unsat Core) |
| **3. Summarized EU Record to External Sink** | `EU / PII` (summarized) | `EXTERNAL / PUBLIC` | GDPR Art. 44 Breach | **VIOLATION** (Taint propagates through summary) |
| **4. Declassified Sentiment to US Webhook** | `EU / PII` $\rightarrow$ `bool` | `US / PUBLIC` | GDPR Art. 5 Minimization | **SAFE** (Bounded to 1 bit) |
| **5. Patient EHR to External Webhook** | `INTERNAL / SENSITIVE_PII` (PHI) | `EXTERNAL / SENSITIVE_PII` | HIPAA § 164.312 Breach | **VIOLATION** (Blocked via Unsat Core) |
| **6. Declassified Safe-Harbor Code to External** | `INTERNAL / SENSITIVE_PII` $\rightarrow$ `PUBLIC` | `EXTERNAL / PUBLIC` | HIPAA § 164.514 Compliant | **SAFE** (Declassifier cleared) |
| **7. California Consumer SPI to Ad Network** | `US / SENSITIVE_PII` (SPI) | `EXTERNAL / SENSITIVE_PII` | CCPA § 1798.121 Breach | **VIOLATION** (Blocked via Unsat Core) |
| **8. Core Banking Ledger to External SaaS** | `EU / CONFIDENTIAL` (core_banking) | `EXTERNAL / CONFIDENTIAL` | DORA Art. 28 Breach | **VIOLATION** (Blocked via Unsat Core) |
| **9. China CIIO Restricted Data to US Cloud** | `APAC / RESTRICTED` | `US / RESTRICTED` | PIPL Art. 40 Breach | **VIOLATION** (Blocked via Unsat Core) |
| **10. ITAR Munitions Specs to Foreign Endpoint** | `US / RESTRICTED` (itar_defense_data) | `APAC / RESTRICTED` | ITAR § 120.10 Criminal Breach | **VIOLATION** (Blocked via Unsat Core) |
| **11. Consequential Hiring Score to Recruiter API** | `INTERNAL / SENSITIVE_PII` (consequential) | `EXTERNAL / SENSITIVE_PII` | Colorado AI Act § 6-1-1702 | **VIOLATION** (Blocked via Unsat Core) |
| **12. Model Weights to Public Repo** | `INTERNAL / CONFIDENTIAL` (model_weights) | `EXTERNAL / CONFIDENTIAL` | ISO 42001 / NIST RMF Breach | **VIOLATION** (Blocked via Unsat Core) |

---

## 13. Codified Policy Sets in `jurisast-policies`

All regulatory policies are implemented as ready-to-use `PolicySet` objects in `jurisast_policies`:

```python
from jurisast_policies import (
    # EU Data Sovereignty & AI Governance
    GDPR_DATA_SOVEREIGNTY,
    EU_AI_ACT_COMPLIANCE,
    DORA_COMPLIANCE,
    # FinTech & Payments
    PCI_DSS_COMPLIANCE,
    # Healthcare & Life Sciences
    HIPAA_COMPLIANCE,
    # US Consumer Privacy
    CCPA_CPRA_COMPLIANCE,
    # Asia-Pacific Sovereignty
    APAC_SOVEREIGNTY_COMPLIANCE,
    PIPL_COMPLIANCE,
    DPDPA_COMPLIANCE,
    # Defense & National Security
    ITAR_EAR_COMPLIANCE,
    # State AI Governance
    COLORADO_AI_ACT_COMPLIANCE,
    # International AI Standards
    ISO_42001_NIST_AI_RMF_COMPLIANCE,
    # Custom Builder
    PolicyBuilder,
)
```

---

## 7. Runnable Compliance Demonstrations

The abstract regulatory scenarios in Section 5 are implemented as complete, runnable Pydantic AI agents in [`examples/`](../examples/):

### Demo 2 — GDPR Article 44/46 Compliance ([`fintech_support_agent`](../examples/fintech_support_agent/))

Directly implements **Scenario 2** (EU Financial Record → US system blocked) and **Scenario 4** (declassified error code safely crosses the border). A FinTech support agent investigates an EU payment failure and is asked to create a Jira ticket for the US engineering team.

| Step | Regulatory Scenario | JurisAST Outcome |
|---|---|---|
| `fetch_eu_record()` | GDPR Art. 9 — Sensitive PII acquired | Source tainted `EU/SENSITIVE_PII` |
| `create_jira_ticket(full_record)` | **GDPR Art. 44 violation** — raw PII to US | 🚨 **BLOCKED** `TaintViolationError` |
| `extract_error_code(record)` | GDPR Art. 5(1)(c) — Data minimization | ✅ **SAFE** — 4-bit declassifier, no PII |
| `create_jira_ticket(error_code=4023)` | Compliant cross-border transfer | ✅ **SAFE** — `INTERNAL/PUBLIC` ≤ `US/INTERNAL_ONLY` |

```bash
# Simulate GDPR violation (Meta €1.2B-class risk):
python examples/fintech_support_agent/app.py --attack

# Show compliant flow with declassification:
python examples/fintech_support_agent/app.py
```

### Demo 1 — Enterprise Data Exfiltration Prevention ([`enterprise_ma_agent`](../examples/enterprise_ma_agent/))

Directly implements **Scenario 3** (summarized/forwarded confidential data blocked at external boundary) via prompt injection. An M&A agent reads board-level strategy documents and is tricked into emailing the verbatim content to a competitor.

| Step | Threat | JurisAST Outcome |
|---|---|---|
| `read_ma_document(DOC-001)` | Data loaded from internal Confluence | Source tainted `INTERNAL/CONFIDENTIAL` |
| `send_email(to="competitor@...")` | **Data exfiltration** — Confidential to External | 🚨 **BLOCKED** `TaintViolationError` |
| `extract_document_sentiment(doc)` | Safe declassification — 2-bit enum | ✅ **SAFE** — `INTERNAL/PUBLIC` output |
| `send_email(body=sentiment_label)` | Compliant external communication | ✅ **SAFE** — `PUBLIC ≤ PUBLIC` |

```bash
# Simulate prompt injection attack:
python examples/enterprise_ma_agent/app.py --attack

# Run full scenario suite:
python examples/enterprise_ma_agent/app.py --all
```
