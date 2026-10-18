# JurisAST — Developer Quickstart Guide

> **Get up and running with formally verified Information Flow Control in under 5 minutes.**

> [!WARNING]
> **Development & Testing Notice**: JurisAST is an experimental project in active development. It has not yet been comprehensively tested across arbitrary production environments. Do not rely on this project for critical production compliance or security without independent verification.

---

## 1. Installation

Ensure you have Python 3.11+ installed.

```bash
# Clone repository
git clone https://github.com/Startups-Initiatives/JurisAST-Agents.git
cd JurisAST-Agents

# Activate virtual environment
.venv\Scripts\activate      # Windows
# source .venv/bin/activate  # Linux/macOS

# Install in editable development mode
pip install -e ".[dev]"
```

---

## 2. Basic Concepts: Labels & Taint

```python
from jurisast_core.labels import (
    Jurisdiction,
    Classification,
    SecurityLabel,
    LABEL_PUBLIC,
    LABEL_EU_PII,
)
from jurisast_core.taint import TaintedValue

# 1. Create a security label
custom_label = SecurityLabel(
    jurisdiction=Jurisdiction.EU,
    classification=Classification.SENSITIVE_PII,
    compartments=frozenset({"finance"}),
)

# 2. Wrap sensitive data in a TaintedValue
tainted_record = TaintedValue.create(
    value={"name": "Alice Dupont", "iban": "DE89370400440532013000"},
    label=LABEL_EU_PII,
    source_tool="fetch_customer_record",
    agent_id="retrieval_agent",
)

# 3. Create a field-sensitive composite record (Mitigating Over-Tainting)
from jurisast_core.taint import TaintedRecord

composite_report = TaintedRecord.create(
    data={
        "public_metrics": "Revenue up 12% YoY",
        "confidential_deal": "Hostile acquisition of Target X at $2B",
    },
    field_labels={
        "public_metrics": LABEL_PUBLIC,
        "confidential_deal": SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
        ),
    },
    source_tool="fetch_quarterly_report",
)

# Individual fields can be projected without inheriting record-wide confidential taint:
public_slice = composite_report.project("public_metrics")
print(f"Projected Public Label: {public_slice.label}")  # INTERNAL / PUBLIC!
```

---

## 3. Constructing an Execution Graph (AST IR)

```python
from jurisast_core.ast_ir import ExecutionGraphBuilder
from jurisast_core.labels import Jurisdiction, Classification, LABEL_EU_PII

builder = ExecutionGraphBuilder(agent_id="fintech_orchestrator")

# Step 1: Data source
src = builder.add_source(
    tool_name="fetch_bank_statement",
    label=LABEL_EU_PII,
    arguments={"account_id": "ACC_9921"},
)

# Step 2: Transform
xfm = builder.add_transform(
    operation="anonymize_and_aggregate",
    input_node_ids=[src.node_id],
    output_label=LABEL_EU_PII,
)

# Step 3: Sink (attempting to send to US analytics)
snk = builder.add_sink(
    tool_name="post_to_us_analytics",
    target_jurisdiction=Jurisdiction.US,
    max_classification=Classification.PUBLIC,
    input_node_ids=[xfm.node_id],
)

# Build & validate DAG structure
graph = builder.build()
print(f"Graph constructed with {len(graph.nodes)} nodes and {len(graph.edges)} edges.")
```

---

## 4. Verifying Compliance with the Z3 SMT Solver

```python
from jurisast_core.solver import Z3SolverEngine
from jurisast_core.exceptions import TaintViolationError

engine = Z3SolverEngine(timeout_ms=50)
engine.encode_graph(graph)

# Method A: Inspect verification result
result = engine.verify()
print(f"Status: {result.status}")
print(f"Latency: {result.latency_ms:.2f}ms")

if result.status == "VIOLATION":
    print(f"Blocked Violations: {result.violated_constraints}")
    print(f"Details: {result.violation_details}")

# Method B: Fail-closed enforcement (raises exception on violation)
try:
    engine.verify_or_raise()
except TaintViolationError as e:
    print(f"\n[SECURITY FIREWALL TRIGGERED]\n{e}")
```

---

## 5. Safe Workflows via Symbolic Declassification

```python
builder = ExecutionGraphBuilder(agent_id="fintech_orchestrator")

# 1. Retrieve EU PII
src = builder.add_source("fetch_bank_statement", LABEL_EU_PII)

# 2. Declassify through constrained boolean extraction (1 bit bound)
dcl = builder.add_declassifier(
    input_node_id=src.node_id,
    output_type="bool",
    output_label=LABEL_PUBLIC,
    max_bits=1.0,
    description="Extract loan_eligible flag (bool)",
)

# 3. Send declassified flag to US webhook
builder.add_sink(
    tool_name="post_to_us_analytics",
    target_jurisdiction=Jurisdiction.US,
    max_classification=Classification.PUBLIC,
    input_node_ids=[dcl.node_id],
)

safe_graph = builder.build()

engine.reset()
engine.encode_graph(safe_graph)
safe_result = engine.verify()

assert safe_result.status == "SAFE"
print(f"Declassified flow verified as SAFE in {safe_result.latency_ms:.2f}ms!")
```

---

## 6. Real-World Enforcement: The Pydantic AI Firewall

In production, agents invoke tools decorated with JurisAST security metadata. The `JurisASTFirewall` intercepts calls automatically:

```python
from jurisast_core.labels import Jurisdiction, Classification
from jurisast_policies import GDPR_DATA_SOVEREIGNTY
from jurisast_pydantic.capability import JurisASTFirewall
from jurisast_pydantic.decorators import tainted_source, tainted_sink, declassifier

# Initialize firewall with GDPR cross-border transfer policy
firewall = JurisASTFirewall(
    policies=GDPR_DATA_SOVEREIGNTY,
    agent_id="kyc_agent",
)

@tainted_source(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
def fetch_eu_profile(user_id: str) -> dict:
    """Fetch EU customer identity data."""
    return {"user_id": user_id, "name": "Elena Rostova", "country": "DE"}

@tainted_sink(target_jurisdiction=Jurisdiction.US, max_classification=Classification.PUBLIC)
def send_to_us_marketing(payload: str) -> str:
    """External webhook in the United States."""
    return "sent"

@declassifier(
    output_label=SecurityLabel(jurisdiction=Jurisdiction.INTERNAL, classification=Classification.PUBLIC),
    max_bits=1.0,
)
def is_account_active(user_id: str) -> bool:
    """Extract 1-bit boolean status."""
    return True

# 1. Agent fetches EU profile
user_data = fetch_eu_profile("usr_123")
firewall.record_tool_result("fetch_eu_profile", {}, "Elena Rostova", fetch_eu_profile)

# 2. Agent tries to send EU PII directly to US -> BLOCKED by JurisAST in <2ms!
try:
    firewall.verify_tool_call(
        tool_name="send_to_us_marketing",
        tool_args={"payload": "Elena Rostova"},
        tool_callable=send_to_us_marketing,
    )
except Exception as e:
    print(f"Successfully blocked illegal transfer: {e}")

# 3. Agent declassifies to boolean and sends -> ALLOWED!
active_flag = is_account_active("usr_123")
firewall.record_tool_result("is_account_active", {}, active_flag, is_account_active)

res = firewall.verify_tool_call(
    tool_name="send_to_us_marketing",
    tool_args={"payload": "true"},
    tool_callable=send_to_us_marketing,
)
assert res.status == "SAFE"
print(f"Compliant flow allowed in {res.latency_ms:.2f}ms!")
```

---

## 7. Defining Custom Enterprise Policies

Use `PolicyBuilder` to compose organizational or regional policies:

```python
from jurisast_policies import PolicyBuilder
from jurisast_core.labels import Jurisdiction, Classification

hipaa_policy = (
    PolicyBuilder("HEALTHCARE_HIPAA")
    .with_description("HIPAA Privacy Rule ePHI protections")
    .block_cross_border(
        name="phi_no_export",
        source=Jurisdiction.US,
        forbidden_sinks={Jurisdiction.EXTERNAL, Jurisdiction.APAC},
        min_classification=Classification.SENSITIVE_PII,
        regulation="HIPAA Security Rule § 164.312",
    )
    .isolate_compartment(
        name="ehr_isolation",
        compartment="electronic_health_record",
        forbidden_sinks={Jurisdiction.EXTERNAL},
    )
    .build()
)

# Attach to solver or firewall:
# firewall = JurisASTFirewall(policies=hipaa_policy, ...)
```

---

## 8. Defending Against Conversational Leaks & Using Field Projections

### A. Conversational Response Firewalling
Prevent agents from leaking sensitive facts directly in response text:

```python
from jurisast_core.labels import LABEL_PUBLIC
from jurisast_core.exceptions import TaintViolationError

# Agent generates a chat response after reading confidential data:
raw_model_response = "The target company is Apex Analytics at $2.4B."

try:
    # Verifies chat response against session taint for unprivileged visitor (PUBLIC)
    firewall.verify_chat_response(
        response_text=raw_model_response,
        user_clearance=LABEL_PUBLIC,
        user_id="visitor_user",
    )
except TaintViolationError as e:
    print(f"Intercepted conversational leak: {e}")

# Or automatically sanitize:
safe_text = firewall.sanitize_chat_response(raw_model_response, LABEL_PUBLIC)
print(safe_text)  # "[REDACTED: SENSITIVE DATA EXCEEDS USER CLEARANCE]"
```

### B. Slotted Templates & Human-in-the-Loop Attestation

```python
from pydantic import BaseModel
from typing import Literal
from jurisast_core.declassifier import SlottedTemplate, HumanDeclassificationAuthority

# 1. Finite Shannon-Bounded Template
class StatusSlots(BaseModel):
    project: Literal["Alpha", "Beta"]
    status: Literal["approved", "rejected"]

template = SlottedTemplate("Project {project} is {status}.", StatusSlots)
print(f"Max Channel Bits: {template.compute_max_bits():.2f} bits")
safe_summary = template.render({"project": "Alpha", "status": "approved"})

# 2. Cryptographic Human Attestation for Free-Text
token = HumanDeclassificationAuthority.create_attestation(
    content="M&A Deal approved by Board.",
    approver_id="compliance_officer_1",
    secret_key="shared-secret",
    target_label=LABEL_PUBLIC,
)
assert HumanDeclassificationAuthority.verify_attestation(token, "M&A Deal approved by Board.", "shared-secret")
```

---

## 9. Real-World Examples & Live Demonstrations

For complete, runnable Pydantic AI agent demos showing JurisAST protecting production-grade workflows, see the [`examples/`](../examples/) directory.

### Demo 1 — Live Gemini 2.5 Flash Validation
End-to-end verification of field projection, conversational leak defense, and cryptographic HITL attestation:
```bash
set GEMINI_API_KEY=your_key_here  # Windows
python examples/live_gemini_enhancements_demo.py
```

### Demo 2 — Enterprise M&A Knowledge Worker
**Industry:** Investment banking, M&A advisory, corporate legal  
**Pain point:** An internal LLM agent with access to confidential M&A strategy documents and an email tool. A prompt injection attack hidden in a document attempts to forward the board-level strategy to a competitor via email.  
**JurisAST action:** Blocks `send_email()` the instant it detects the body is tainted with `INTERNAL/CONFIDENTIAL` data. The email is never sent.

```bash
set GOOGLE_API_KEY=your_key_here  # Windows
python examples/enterprise_ma_agent/app.py --attack   # Watch JurisAST block it
python examples/enterprise_ma_agent/app.py            # See compliant flows too
```

### Demo 3 — Global FinTech Support Agent (GDPR)
**Industry:** FinTech (Revolut, Wise, Stripe), banking, healthcare  
**Regulation enforced:** GDPR Article 44/46 — EU citizen PII cannot flow to US servers without explicit safeguards  
**Pain point:** A support agent investigates an EU customer payment failure and needs to create a Jira ticket for the US engineering team. Naive agent includes name, IBAN, and transaction history in the ticket — a GDPR violation carrying up to €1.2B fine risk.  
**JurisAST action:** Blocks the raw `create_jira_ticket()` call. Enables a `@declassifier` tool (`extract_error_code`) that reduces the SENSITIVE_PII record to a single 4-bit integer error code — mathematically proven to carry no PII — which flows safely to the US Jira board.

```bash
set GOOGLE_API_KEY=your_key_here  # Windows
python examples/fintech_support_agent/app.py           # GDPR-safe declassification
python examples/fintech_support_agent/app.py --attack  # Raw PII to Jira — blocked
python examples/fintech_support_agent/app.py --all     # Full story
```

> See [`examples/README.md`](../examples/README.md) for the complete Before vs. After JurisAST breakdown.
