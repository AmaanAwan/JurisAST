# Demo 2: Global FinTech Customer Support Agent

## Real-World Context

**Where this is used:** Global FinTech companies (Revolut, Wise, Stripe, N26, Monzo) that process EU citizen payments and operate engineering teams in the United States.

**Real regulatory fines this prevents:**
| Company | Fine | Cause |
|---|---|---|
| Meta | **€1.2 billion** | EU→US data transfers (2023) |
| WhatsApp | **€225 million** | Opaque EU→US data sharing |
| Amazon | **€746 million** | EU data sovereignty violations |

---

## The Pain Point

A global FinTech company's support agent has two critical needs:
1. **Read EU customer records** to investigate payment failures (contains name, IBAN, transaction history — GDPR Art. 9 Sensitive PII).
2. **Create Jira tickets** for the US engineering team to fix bugs.

The problem: Jira runs on US servers. Sending EU Sensitive PII to US servers is a GDPR violation unless specific legal mechanisms (Standard Contractual Clauses, BCRs) are in place — and even then, the data must be minimized.

**With a naive LLM agent:**
```
fetch_eu_record() → "Name: Marie Dupont, IBAN: FR76..., Amount: €450"
                        ↓
create_jira_ticket(description="Customer Marie Dupont's IBAN FR76... failed")
                        ↓
               📤 US Jira servers receive raw EU PII
                        ↓
               💸 GDPR fine risk: €1M – €1.2B
```

---

## Before vs. After JurisAST

### ❌ Before JurisAST

```python
# No tainting. Data flows freely from EU DB to US Jira.

async def investigate_and_ticket(customer_id: str):
    record = await fetch_eu_record(customer_id)
    # LLM may helpfully include the full record in the Jira description
    await create_jira_ticket(
        description=f"Customer record: {record}"  # ← GDPR violation
    )
```

### ✅ After JurisAST: Declassification

The key insight is **Declassification** — the only legal, mathematically-bounded way to downgrade a security label:

```python
# Step 1: Tag the EU database as a SENSITIVE_PII source
@tainted_source(
    jurisdiction=Jurisdiction.EU,
    classification=Classification.SENSITIVE_PII,
)
def fetch_eu_customer_record(customer_id: str) -> str: ...

# Step 2: Provide a declassifier that extracts ONLY the error code
@declassifier(
    output_label=SecurityLabel(jurisdiction=Jurisdiction.INTERNAL,
                               classification=Classification.PUBLIC),
    max_bits=4.0,  # log2(16) — only an integer 0–9999
    output_type="int",
)
def extract_error_code(record_text: str) -> int:
    """Returns only the numeric error code. Zero PII."""
    ...

# Step 3: Tag Jira as US/INTERNAL_ONLY sink
@tainted_sink(
    target_jurisdiction=Jurisdiction.US,
    max_classification=Classification.INTERNAL_ONLY,
)
def create_jira_ticket(description: str) -> str: ...

# What JurisAST enforces:
#
# fetch_eu_record() → tainted: EU/SENSITIVE_PII
#
# extract_error_code(record) → ✅ SAFE: declassifier strips to INTERNAL/PUBLIC
#                              JurisAST verifies: 4 bits ≤ budget
#
# create_jira_ticket(error_code=4023) → ✅ SAFE: INTERNAL/PUBLIC → US/INTERNAL_ONLY
#
# create_jira_ticket(full_record) → 🚨 BLOCKED: EU/SENSITIVE_PII > US/INTERNAL_ONLY
```

---

## Information Flow Diagram

```
EU PostgreSQL DB ──┐
[EU/SENSITIVE_PII] │
                   ▼
            fetch_eu_record()  ← @tainted_source
                   │
                   ├──────────────────────────────────────► EU Slack #eu-support
                   │                                        [EU/SENSITIVE_PII → OK ✅]
                   │
                   ▼
          extract_error_code()  ← @declassifier
          [EU/SENSITIVE_PII → INTERNAL/PUBLIC]
          JurisAST: Shannon bound check (4 bits) ✅
                   │
                   ▼
           error_code = 4023
           [INTERNAL/PUBLIC]
                   │
                   ▼
          create_jira_ticket(error_code=4023)  ← @tainted_sink [US/INTERNAL_ONLY]
          JurisAST: PUBLIC ≤ INTERNAL_ONLY ✅ → ALLOWED
          📋 Ticket CORE-1000: "Payment failure error code: 4023"
          [No PII in US system. GDPR compliant.]
```

---

## How to Run

```bash
cd examples/fintech_support_agent
export GEMINI_API_KEY=your_key_here

# Default: Show the compliant declassification flow
python app.py

# Simulate a GDPR violation (agent tries to send raw PII to US Jira)
python app.py --attack

# Run both scenarios
python app.py --all
```

---

## What You'll See

**Compliant Flow (default):**
```
>>> USER: Investigate CUST-4421. Create a Jira ticket without PII.

<<< AGENT: I've created Jira ticket CORE-1000:
    - Error code 4023 extracted (GDPR-compliant declassification)
    - No customer name, IBAN, or email in the ticket
    - Full record posted to EU internal Slack only

🔐 JURISAST FIREWALL SESSION STATS
  Total Verifications: 5
  ✅ Safe: 5
  🚨 Violations Blocked: 0
  ⏱ Avg Verify Time: 2.3ms
```

**GDPR Violation Attempt:**
```
>>> USER: Include name, IBAN, and full transaction in the Jira ticket.

🚨🚨🚨 GDPR VIOLATION BLOCKED BY JURISAST 🚨🚨🚨

  TaintViolationError: IFC violation for tool 'create_jira_ticket':
    Data label EU/SENSITIVE_PII exceeds sink max US/INTERNAL_ONLY
    Violated constraints: ['jurisdiction_cross_border', 'gdpr_eu_to_us']

  ✅ The Jira ticket was NOT created with PII.
  ✅ EU SENSITIVE_PII never reached the US Jira system.
  💸 Estimated GDPR fine risk prevented: €1M–€1.2B
```
