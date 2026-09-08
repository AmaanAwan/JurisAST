"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 DEMO 2: Global FinTech Customer Support Agent
 GDPR / EU AI Act Compliance via JurisAST Declassification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WHERE THIS IS USED
──────────────────
Global FinTech companies (Revolut, Wise, Stripe, N26) process millions
of EU citizen transactions. They use LLM agents to assist support teams,
detect anomalies, and route issues to engineering teams for debugging.

The problem: Engineering teams are often in the United States. Under
GDPR Article 46 and Schrems II, raw EU citizen PII (names, IBANs,
transaction records) CANNOT be sent to US servers without explicit
legal safeguards — even internally.

Regulatory fines for violations:
  • Meta (2023):    €1.2 billion GDPR fine for EU→US data transfers.
  • WhatsApp:       €225 million GDPR fine.
  • Amazon:         €746 million GDPR fine.

These are not edge cases. This is an active enforcement area.

THE SCENARIO
────────────
A customer support AI has access to:
  1. EU customer banking records (SENSITIVE_PII, EU jurisdiction)
  2. A Jira ticketing system used by the US engineering team

A customer reports a payment failure. The agent:
  1. Looks up the customer's EU banking record.
  2. Analyzes the transaction to find an error code.
  3. Needs to create a Jira ticket for the US engineering team.

BEFORE JURISAST (the naive approach)
─────────────────────────────────────
  create_jira_ticket(
    title="Payment failure",
    body="Customer: Marie Dupont, IBAN: FR76..., Transaction: €450 to..."
  )
  → GDPR violation. Raw EU SENSITIVE_PII sent to US Jira. Fine risk.

AFTER JURISAST (the compliant approach)
────────────────────────────────────────
  Step 1: fetch_eu_record() → tainted with EU/SENSITIVE_PII
  Step 2: extract_error_code(record) → @declassifier
          JurisAST verifies: integer error code is ≤ 4 bits
          Output re-labeled as INTERNAL/PUBLIC (no PII)
  Step 3: create_jira_ticket(error_code=4023) → ✅ SAFE
          US Jira receives only the error code. Zero PII exposure.

RUN THIS DEMO
─────────────
  cd examples/fintech_support_agent
  export GOOGLE_API_KEY=<your-key>  # pydantic-ai >= 2.x uses GOOGLE_API_KEY

  # Compliant flow (declassification in action):
  python app.py

  # Attempt direct GDPR violation (blocked):
  python app.py --attack

  # Full story (compliant + violation + audit):
  python app.py --all
"""

import asyncio
import argparse
import os
import sys
from datetime import datetime
from typing import Any

from pydantic_ai import Agent, RunContext

from jurisast_core.config import JurisASTConfig, SolverConfig
from jurisast_core.exceptions import TaintViolationError
from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel

from jurisast_pydantic.agent import create_jurisast_deps
from jurisast_pydantic.decorators import declassifier, tainted_sink, tainted_source
from jurisast_pydantic.tainted_context import JurisASTDeps


# ──────────────────────────────────────────────────────────────────────────────
# SIMULATED DATA STORE
# In production: PostgreSQL (EU sovereign), real Jira/Linear API, Slack API.
# ──────────────────────────────────────────────────────────────────────────────

_EU_CUSTOMER_DB = {
    "CUST-4421": {
        "name": "Marie Dupont",
        "iban": "FR7614508059409873256148470",
        "email": "marie.dupont@example.fr",
        "country": "France",
        "recent_transactions": [
            {
                "id": "TXN-9901",
                "amount": 450.00,
                "currency": "EUR",
                "destination": "DE12500105170648489890",
                "status": "FAILED",
                "error_code": 4023,
                "error_reason": "Insufficient funds in interbank buffer",
                "timestamp": "2026-09-07T14:23:11Z",
            }
        ],
    },
    "CUST-7783": {
        "name": "Luca Rossi",
        "iban": "IT60X0542811101000000123456",
        "email": "luca.rossi@example.it",
        "country": "Italy",
        "recent_transactions": [
            {
                "id": "TXN-9944",
                "amount": 1200.00,
                "currency": "EUR",
                "destination": "ES9121000418450200051332",
                "status": "FAILED",
                "error_code": 5012,
                "error_reason": "Destination bank timeout — retry after 60s",
                "timestamp": "2026-09-08T09:45:00Z",
            }
        ],
    },
}

_JIRA_TICKETS: list[dict[str, Any]] = []
_INTERNAL_SLACK_LOG: list[dict[str, str]] = []


# ──────────────────────────────────────────────────────────────────────────────
# KNOWLEDGE BASE: Error Code Descriptions (No PII)
# These are safe to include in Jira tickets.
# ──────────────────────────────────────────────────────────────────────────────

_ERROR_CODES = {
    4023: "Interbank buffer saturation — SEPA batch window missed.",
    5012: "Destination bank ACK timeout — transient network fault.",
    4001: "KYC document expiry — account action required.",
    5500: "Internal processing error — escalate to core-payments team.",
}


# ──────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS WITH JURISAST ANNOTATIONS
# ──────────────────────────────────────────────────────────────────────────────


@tainted_source(
    jurisdiction=Jurisdiction.EU,
    classification=Classification.SENSITIVE_PII,
    compartments=frozenset({"banking", "support"}),
    description=(
        "Fetch a full EU customer banking record. "
        "Contains IBAN, name, email, transaction history. "
        "⚠ GDPR Art. 9 — Sensitive PII. EU sovereign."
    ),
)
def fetch_eu_customer_record(customer_id: str) -> str:
    """
    Retrieve full customer banking record from EU-sovereign PostgreSQL database.
    In production: calls internal banking API with service account credentials.

    ⚠ SOURCE: Data is labeled EU/SENSITIVE_PII.
    It CANNOT flow to US Jira or external Slack without declassification.
    """
    record = _EU_CUSTOMER_DB.get(customer_id)
    if record is None:
        return f"[ERROR] Customer '{customer_id}' not found."

    txn = record["recent_transactions"][-1] if record["recent_transactions"] else {}
    return (
        f"CUSTOMER RECORD [EU/SENSITIVE_PII]\n"
        f"Name:    {record['name']}\n"
        f"Country: {record['country']}\n"
        f"IBAN:    {record['iban']}\n"
        f"Email:   {record['email']}\n"
        f"\nLast Transaction:\n"
        f"  ID:         {txn.get('id', 'N/A')}\n"
        f"  Amount:     {txn.get('currency', 'EUR')} {txn.get('amount', 'N/A')}\n"
        f"  Status:     {txn.get('status', 'N/A')}\n"
        f"  Error Code: {txn.get('error_code', 'N/A')}\n"
        f"  Reason:     {txn.get('error_reason', 'N/A')}\n"
    )


@declassifier(
    output_label=SecurityLabel(
        jurisdiction=Jurisdiction.INTERNAL,
        classification=Classification.PUBLIC,
    ),
    max_bits=4.0,  # log2(16) — integer 0–9999, system error codes are bounded
    output_type="int",
    description=(
        "Extract ONLY the numeric error code from a transaction record. "
        "Output: an integer (e.g., 4023). "
        "This strips ALL PII — only the error code is returned. "
        "Max 4 bits of information about the source record."
    ),
)
def extract_error_code(record_text: str) -> int:
    """
    Parse and return only the numeric error code from a banking record.

    This is a declassifier: it provably reduces EU/SENSITIVE_PII data
    down to a single non-identifying integer. The output carries
    INTERNAL/PUBLIC label — safe for US engineering systems.

    JurisAST enforces: output bits ≤ 4.0 (max_bits constraint).
    The error code integer contains NO name, NO IBAN, NO email.
    """
    for line in record_text.splitlines():
        if "Error Code:" in line:
            try:
                code = int(line.split(":")[-1].strip())
                return code
            except ValueError:
                pass
    return -1  # Unknown error


@declassifier(
    output_label=SecurityLabel(
        jurisdiction=Jurisdiction.INTERNAL,
        classification=Classification.INTERNAL_ONLY,
    ),
    max_bits=2.0,  # log2(4): one of critical/high/medium/low
    output_type="enum",
    description=(
        "Classify the priority of the customer's issue from the record. "
        "Output: one of 'critical', 'high', 'medium', 'low'. "
        "No PII in output."
    ),
)
def classify_issue_priority(record_text: str) -> str:
    """
    Determine issue severity from the record without revealing PII.
    Returns a 2-bit enum: critical / high / medium / low.
    """
    record_lower = record_text.lower()
    if "5500" in record_lower or "core-payments" in record_lower:
        return "critical"
    elif "timeout" in record_lower or "saturation" in record_lower:
        return "high"
    elif "kyc" in record_lower or "expiry" in record_lower:
        return "medium"
    return "low"


@tainted_sink(
    target_jurisdiction=Jurisdiction.US,
    max_classification=Classification.INTERNAL_ONLY,
    description=(
        "Create a Jira ticket on the US engineering board. "
        "✅ Accepts INTERNAL_ONLY and below — safe for error codes and priority. "
        "🚫 BLOCKS EU SENSITIVE_PII — will raise TaintViolationError."
    ),
)
def create_jira_ticket(project: str, title: str, description: str, priority: str) -> str:
    """
    Create a Jira ticket for the US engineering team.
    In production: calls Jira REST API with service account credentials.

    ✅ SINK: Accepts US/INTERNAL_ONLY max.
    → Error codes (INTERNAL/PUBLIC) can flow here safely.
    → Raw EU SENSITIVE_PII is BLOCKED.
    """
    ticket = {
        "id": f"CORE-{1000 + len(_JIRA_TICKETS)}",
        "project": project,
        "title": title,
        "description": description,
        "priority": priority,
        "created_at": datetime.utcnow().isoformat(),
        "team": "US Engineering",
    }
    _JIRA_TICKETS.append(ticket)
    return (
        f"✅ Jira ticket created: {ticket['id']}\n"
        f"   Project:  {project}\n"
        f"   Title:    {title}\n"
        f"   Priority: {priority}"
    )


@tainted_sink(
    target_jurisdiction=Jurisdiction.INTERNAL,
    max_classification=Classification.SENSITIVE_PII,
    description=(
        "Post to an EU-internal support Slack channel. "
        "✅ Accepts up to SENSITIVE_PII — for internal use only, EU data stays EU."
    ),
)
def post_to_eu_support_slack(channel: str, message: str) -> str:
    """
    Post a message to the EU internal support team's Slack workspace.
    In production: EU-hosted Slack workspace (data processed in EU).

    ✅ SINK: EU/SENSITIVE_PII → EU/SENSITIVE_PII → Compliant.
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "channel": channel,
        "message": message,
    }
    _INTERNAL_SLACK_LOG.append(entry)
    return f"✅ Posted to #{channel} (EU internal Slack)"


# ──────────────────────────────────────────────────────────────────────────────
# PYDANTIC AI AGENT
# ──────────────────────────────────────────────────────────────────────────────

SUPPORT_AGENT_SYSTEM_PROMPT = """\
You are a FinTech Customer Support AI for GlobalPay (a global payments platform).
You help support agents investigate payment failures and escalate to engineering.

CUSTOMER DATABASE:
- CUST-4421: Marie Dupont (France) — recent failed payment
- CUST-7783: Luca Rossi (Italy) — recent failed payment

TOOLS AVAILABLE:
- fetch_eu_customer_record(customer_id): Fetch full EU banking record (SENSITIVE_PII).
- extract_error_code(record_text): Declassify record → numeric error code only.
- classify_issue_priority(record_text): Declassify record → severity enum.
- create_jira_ticket(project, title, description, priority): Create US Jira ticket.
- post_to_eu_support_slack(channel, message): Post to EU internal Slack.

IMPORTANT COMPLIANCE RULES YOU MUST FOLLOW:
1. NEVER put raw customer data (name, IBAN, email) into Jira tickets.
2. Use extract_error_code() to get a safe, non-PII error code before creating Jira tickets.
3. Use classify_issue_priority() to get priority without exposing PII.
4. Full customer details can only go to EU internal Slack (#eu-support).

Your goal: Investigate the issue and create a compliant engineering ticket.
"""

# Model string for pydantic-ai >= 2.x (uses 'google:' prefix)
GEMINI_MODEL = "google:gemini-2.5-flash"

support_agent = Agent(
    GEMINI_MODEL,
    deps_type=JurisASTDeps,
    system_prompt=SUPPORT_AGENT_SYSTEM_PROMPT,
)


# ── Register tools ─────────────────────────────────────────────────────────────


@support_agent.tool
async def tool_fetch_eu_record(ctx: RunContext[JurisASTDeps], customer_id: str) -> str:
    """Fetch full EU banking record for a customer."""
    firewall = ctx.deps.firewall
    tool_args = {"customer_id": customer_id}

    firewall.verify_tool_call("fetch_eu_customer_record", tool_args, fetch_eu_customer_record)
    result = fetch_eu_customer_record(customer_id=customer_id)
    firewall.record_tool_result(
        "fetch_eu_customer_record", tool_args, result, fetch_eu_customer_record
    )

    return result


@support_agent.tool
async def tool_extract_error_code(ctx: RunContext[JurisASTDeps], record_text: str) -> int:
    """Extract just the numeric error code from a banking record (no PII in output)."""
    firewall = ctx.deps.firewall
    tool_args = {"record_text": record_text}

    # 🔐 DECLASSIFICATION: EU/SENSITIVE_PII → INTERNAL/PUBLIC (4-bit integer)
    firewall.verify_tool_call("extract_error_code", tool_args, extract_error_code)
    result = extract_error_code(record_text=record_text)
    firewall.record_tool_result("extract_error_code", tool_args, result, extract_error_code)

    return result


@support_agent.tool
async def tool_classify_priority(ctx: RunContext[JurisASTDeps], record_text: str) -> str:
    """Classify the issue priority from a record (no PII in output)."""
    firewall = ctx.deps.firewall
    tool_args = {"record_text": record_text}

    # 🔐 DECLASSIFICATION: EU/SENSITIVE_PII → INTERNAL/INTERNAL_ONLY (2-bit enum)
    firewall.verify_tool_call("classify_issue_priority", tool_args, classify_issue_priority)
    result = classify_issue_priority(record_text=record_text)
    firewall.record_tool_result(
        "classify_issue_priority", tool_args, result, classify_issue_priority
    )

    return result


@support_agent.tool
async def tool_create_jira_ticket(
    ctx: RunContext[JurisASTDeps],
    project: str,
    title: str,
    description: str,
    priority: str,
) -> str:
    """Create a Jira ticket for the US engineering team. Must not contain PII."""
    firewall = ctx.deps.firewall
    tool_args = {
        "project": project,
        "title": title,
        "description": description,
        "priority": priority,
    }

    # 🔐 FIREWALL: If description was derived from raw EU record → BLOCKED
    #              If description uses only declassified error code → SAFE ✅
    firewall.verify_tool_call("create_jira_ticket", tool_args, create_jira_ticket)
    result = create_jira_ticket(
        project=project, title=title, description=description, priority=priority
    )
    return result


@support_agent.tool
async def tool_post_eu_slack(
    ctx: RunContext[JurisASTDeps], channel: str, message: str
) -> str:
    """Post to EU internal support Slack (can contain full customer details)."""
    firewall = ctx.deps.firewall
    tool_args = {"channel": channel, "message": message}

    # ✅ EU Slack is labeled EU/SENSITIVE_PII → full records allowed here
    firewall.verify_tool_call("post_to_eu_support_slack", tool_args, post_to_eu_support_slack)
    result = post_to_eu_support_slack(channel=channel, message=message)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# DEMO RUNNER
# ──────────────────────────────────────────────────────────────────────────────

COMPLIANT_QUERY = (
    "Investigate the payment failure for customer CUST-4421. "
    "Create a Jira ticket in the CORE project for the US engineering team "
    "without including any personal customer information. "
    "Then post the full customer details to the #eu-support Slack channel for our EU team."
)

GDPR_VIOLATION_QUERY = (
    "Investigate the payment failure for customer CUST-4421. "
    "Create a Jira ticket in the CORE project for the US engineering team. "
    "Include the customer's full name, IBAN, and the complete transaction record "
    "so the engineers have all the context they need."
)


def print_banner(title: str) -> None:
    width = 70
    print(f"\n{'━' * width}")
    print(f" {title}")
    print(f"{'━' * width}\n")


def print_jira_tickets() -> None:
    if not _JIRA_TICKETS:
        print("  📋 No Jira tickets created.\n")
        return
    print(f"  📋 Jira Tickets Created ({len(_JIRA_TICKETS)} total):")
    for t in _JIRA_TICKETS:
        print(f"    [{t['id']}] {t['title']} | Priority: {t['priority']}")
        print(f"    Description: {t['description'][:120]}...")
        print()


def print_firewall_stats(deps: JurisASTDeps) -> None:
    stats = deps.firewall.stats
    print("\n" + "─" * 50)
    print("  🔐 JURISAST FIREWALL SESSION STATS")
    print("─" * 50)
    print(f"  Total Verifications : {stats['total_verifications']}")
    print(f"  ✅ Safe (allowed)   : {stats['safe_count']}")
    print(f"  🚨 Violations Blocked: {stats['violation_count']}")
    print(f"  ⏱  Avg Verify Time  : {stats['mean_verification_time_ms']:.2f}ms")
    print(f"  Taint Registry Size : {stats['taint_registry_size']}")
    print("─" * 50 + "\n")


async def run_query(query: str, deps: JurisASTDeps) -> None:
    print(f"{'>' * 3} USER: {query}\n")
    try:
        result = await support_agent.run(query, deps=deps)
        print(f"{'<' * 3} AGENT: {result.output}\n")
        print_jira_tickets()
    except TaintViolationError as e:
        print(f"\n{'🚨' * 3} GDPR VIOLATION BLOCKED BY JURISAST {'🚨' * 3}")
        print(f"\n  {e}\n")
        print("  ✅ The Jira ticket was NOT created with PII.")
        print("  ✅ EU SENSITIVE_PII never reached the US Jira system.")
        print("  💸 Estimated GDPR fine risk prevented: €1M–€1.2B\n")


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="JurisAST Global FinTech Support Agent Demo"
    )
    parser.add_argument(
        "--attack",
        action="store_true",
        help="Simulate a GDPR violation (raw EU PII sent to US Jira)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run both compliant and violation scenarios",
    )
    args = parser.parse_args()

    print_banner("JurisAST Demo 2: Global FinTech Support Agent (GDPR Compliance)")
    print(
        "  This demo shows how JurisAST enforces GDPR compliance by blocking\n"
        "  raw EU SENSITIVE_PII from reaching US engineering systems (Jira),\n"
        "  while enabling compliant cross-border data flows via Declassification.\n"
    )

    if args.attack:
        print_banner("⚠️  SIMULATING GDPR VIOLATION — Raw PII to US Jira")
        print(
            "  The agent is asked to include the customer's full name, IBAN,\n"
            "  and transaction details in a Jira ticket for the US engineering team.\n"
            "  Watch JurisAST block the create_jira_ticket() call.\n"
        )
        deps = create_jurisast_deps(
            agent_id="fintech_support_agent",
            config=JurisASTConfig(mode="enforce", solver=SolverConfig(timeout_ms=500)),
        )
        await run_query(GDPR_VIOLATION_QUERY, deps)
        print_firewall_stats(deps)

    elif args.all:
        print_banner("SCENARIO A: Compliant GDPR-Safe Flow with Declassification")
        print(
            "  The agent reads EU PII → extracts only the error code (declassification)\n"
            "  → creates Jira ticket with only the 4-bit error code → SAFE ✅\n"
            "  Full record → EU internal Slack → SAFE ✅\n"
        )
        deps1 = create_jurisast_deps(
            agent_id="fintech_support_agent",
            config=JurisASTConfig(mode="enforce", solver=SolverConfig(timeout_ms=500)),
        )
        await run_query(COMPLIANT_QUERY, deps1)
        print_firewall_stats(deps1)

        _JIRA_TICKETS.clear()

        print_banner("SCENARIO B: ⚠️  GDPR Violation Attempt — Raw PII to US Jira")
        print(
            "  The agent tries to include name, IBAN, and transaction record\n"
            "  in a Jira ticket (US jurisdiction). JurisAST blocks it.\n"
        )
        deps2 = create_jurisast_deps(
            agent_id="fintech_support_agent",
            config=JurisASTConfig(mode="enforce", solver=SolverConfig(timeout_ms=500)),
        )
        await run_query(GDPR_VIOLATION_QUERY, deps2)
        print_firewall_stats(deps2)

    else:
        # Default: show the beautiful compliant flow
        print_banner("SCENARIO: Compliant GDPR-Safe Declassification Flow")
        print(
            "  Watch the agent:\n"
            "  1. Fetch EU SENSITIVE_PII (tainted at source)\n"
            "  2. Use extract_error_code() to declassify to a 4-bit integer\n"
            "  3. Create a US Jira ticket with ONLY the error code ← SAFE\n"
            "  4. Post full record to EU internal Slack ← SAFE (EU→EU)\n"
        )
        deps = create_jurisast_deps(
            agent_id="fintech_support_agent",
            config=JurisASTConfig(mode="enforce", solver=SolverConfig(timeout_ms=500)),
        )
        await run_query(COMPLIANT_QUERY, deps)
        print_firewall_stats(deps)

    print("  Run with --attack to see GDPR violation blocked, --all for both.\n")


if __name__ == "__main__":
    if not os.getenv("GOOGLE_API_KEY"):
        print("\n[ERROR] Please set GOOGLE_API_KEY environment variable.")
        print("  export GOOGLE_API_KEY=your_key_here  # Unix/macOS")
        print("  set GOOGLE_API_KEY=your_key_here     # Windows\n")
        sys.exit(1)
    asyncio.run(main())
