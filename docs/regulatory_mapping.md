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

## 5. Regulatory Verification Matrix

| Regulatory Scenario | Source Label | Proposed Sink Target | Expected Outcome | JurisAST Action |
|:---|:---|:---|:---|:---|
| **1. EU Citizen Record to EU Database** | `EU / PII` | `EU / SENSITIVE_PII` | Compliant | **SAFE** (Allowed) |
| **2. EU Financial Record to US Analytics Webhook** | `EU / SENSITIVE_PII` | `US / PUBLIC` | GDPR Art. 44 Breach | **VIOLATION** (Blocked via Unsat Core) |
| **3. Summarized EU Record to External Sink** | `EU / PII` (summarized) | `EXTERNAL / PUBLIC` | GDPR Art. 44 Breach | **VIOLATION** (Taint propagates through summary) |
| **4. Declassified Sentiment to US Webhook** | `EU / PII` $\rightarrow$ `bool` | `US / PUBLIC` | GDPR Art. 5 Minimization | **SAFE** (Bounded to 1 bit) |
| **5. Multi-Hop Laundering (Agent A $\rightarrow$ B $\rightarrow$ C)** | `EU / PII` | `US / PUBLIC` | GDPR Art. 44 Evasion | **VIOLATION** (Handoff joins taint across swarm) |
| **6. Disjoint Compartment Flow (HR to Finance)** | `EU / CONFIDENTIAL` (HR) | `EU / CONFIDENTIAL` (Finance) | Need-to-Know Breach | **VIOLATION** (Lattice dominance fails on compartment subset) |

---

## 6. Codified Policy Sets in `jurisast-policies`

The theoretical invariants described above are packaged into executable, production-ready `PolicySet` definitions:

### 6.1 `GDPR_DATA_SOVEREIGNTY` (`jurisast_policies.gdpr`)
```python
from jurisast_policies import GDPR_DATA_SOVEREIGNTY

# Rules enforced:
# - eu_pii_no_us_transfer: Blocks EU PII/Sensitive PII from flowing to US external sinks (Art. 44/45).
# - eu_pii_no_external_without_declassification: Blocks EU PII from reaching EXTERNAL sinks unless declassified.
# - eu_sensitive_pii_audit_all: Generates audit logs for special category flows (Art. 9).
# - eu_restricted_no_export: Prevents EU board secrets and cryptographic keys from leaving EU boundary (Art. 32).
```

### 6.2 `EU_AI_ACT_COMPLIANCE` (`jurisast_policies.eu_ai_act`)
```python
from jurisast_policies import EU_AI_ACT_COMPLIANCE

# Rules enforced:
# - biometric_data_isolation: Forbids biometric/sensitive data from unmonitored external decision sinks (Art. 10).
# - prohibited_social_scoring_guard: Blocks restricted evaluation profiles from external egress (Art. 5).
# - high_risk_ai_audit_logging: Enforces mandatory lifecycle audit records for high-risk PII processing (Art. 12/14).
```

### 6.3 `PCI_DSS_COMPLIANCE` (`jurisast_policies.pci_dss`)
```python
from jurisast_policies import PCI_DSS_COMPLIANCE

# Rules enforced:
# - cardholder_data_isolation: Completely isolates pci_cardholder compartment from external sinks (Req. 1.3/3.4).
# - financial_pan_no_public_sink: Prohibits raw PAN/CVV from reaching public endpoints without masking (Req. 3.3).
# - cde_audit_logging: Mandates strict provenance and audit records for cardholder environment access (Req. 10.2).
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
