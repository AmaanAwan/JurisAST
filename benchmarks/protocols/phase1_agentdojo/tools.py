"""
Standardized Multi-Suite Tools for AgentDojo Benchmark.

Directly mirrors the AgentDojo tools across Banking, Slack, and Travel suites
(Debenedetti et al., NeurIPS 2024), providing standard function signatures.
"""

from __future__ import annotations

from typing import Any, Dict, List
from benchmarks.protocols.phase1_agentdojo.environment import (
    BankingEnvironment,
    SlackEnvironment,
    TravelEnvironment,
)


# ═════════════════════════════════════════════════════════════════════════════
# 1. BANKING SUITE TOOLS
# ═════════════════════════════════════════════════════════════════════════════

def tool_get_balance(env: BankingEnvironment, account_id: str) -> Dict[str, Any]:
    """Retrieve the current available balance for a bank account."""
    acc = env.accounts.get(account_id)
    if not acc:
        return {"success": False, "error": f"Account '{account_id}' does not exist"}
    return {
        "success": True,
        "account_id": account_id,
        "owner": acc.owner_name,
        "iban": acc.iban,
        "balance": acc.balance,
        "currency": acc.currency,
    }


def tool_get_transaction_history(env: BankingEnvironment, account_id: str) -> Dict[str, Any]:
    """Retrieve past ledger transactions involving the user's account."""
    acc = env.accounts.get(account_id)
    if not acc:
        return {"success": False, "error": f"Account '{account_id}' not found"}

    user_iban = acc.iban
    matching = [
        {
            "tx_id": tx.tx_id,
            "timestamp": tx.timestamp,
            "source_iban": tx.source_iban,
            "recipient_iban": tx.recipient_iban,
            "amount": tx.amount,
            "memo": tx.memo,
        }
        for tx in env.transactions
        if tx.source_iban == user_iban or tx.recipient_iban == user_iban
    ]
    return {"success": True, "account_id": account_id, "transactions": matching}


def tool_get_pending_bills(env: BankingEnvironment, account_id: str) -> Dict[str, Any]:
    """Retrieve incoming pending bills and invoices payable by the user."""
    bills_list = [
        {
            "bill_id": b.bill_id,
            "sender_name": b.sender_name,
            "sender_iban": b.sender_iban,
            "amount": b.amount,
            "due_date": b.due_date,
            "memo": b.memo,
            "status": b.status,
        }
        for b in env.bills.values()
    ]
    return {"success": True, "pending_bills": bills_list}


def tool_transfer_funds(
    env: BankingEnvironment,
    source_account_id: str,
    recipient_iban: str,
    amount: float,
    memo: str,
) -> Dict[str, Any]:
    """Transfer funds from a user account to a destination IBAN."""
    return env.execute_transfer(
        source_account_id=source_account_id,
        recipient_iban=recipient_iban,
        amount=amount,
        memo=memo,
    )


def tool_send_external_webhook(
    env: BankingEnvironment,
    url: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Dispatch data payload to an external network endpoint."""
    return env.dispatch_webhook(url=url, payload=payload)


# ═════════════════════════════════════════════════════════════════════════════
# 2. SLACK SUITE TOOLS
# ═════════════════════════════════════════════════════════════════════════════

def tool_slack_read_channel(env: SlackEnvironment, channel_id: str) -> Dict[str, Any]:
    """Read message history from a Slack channel."""
    ch = env.channels.get(channel_id)
    if not ch:
        return {"success": False, "error": f"Channel {channel_id} not found"}
    msgs = [
        {"msg_id": m.msg_id, "sender": m.sender_id, "text": m.text, "time": m.timestamp}
        for m in env.messages
        if m.channel_id == channel_id
    ]
    return {"success": True, "channel_name": ch.name, "classification": ch.classification, "messages": msgs}


def tool_slack_post_message(
    env: SlackEnvironment,
    sender_id: str,
    channel_id: str,
    text: str,
) -> Dict[str, Any]:
    """Post a message into a Slack channel."""
    return env.post_message(sender_id=sender_id, channel_id=channel_id, text=text)


def tool_slack_send_webhook(
    env: SlackEnvironment,
    url: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Exfiltrate data to an external webhook from Slack."""
    log = env.post_message(sender_id="bot", channel_id=SlackEnvironment.GENERAL_CHANNEL, text=f"[Dispatched to {url}]")
    env.egress_logs.append(log)  # type: ignore
    return {"success": True, "url": url}


# ═════════════════════════════════════════════════════════════════════════════
# 3. TRAVEL SUITE TOOLS
# ═════════════════════════════════════════════════════════════════════════════

def tool_travel_get_profile(env: TravelEnvironment, user_id: str) -> Dict[str, Any]:
    """Retrieve user corporate travel profile and payment credentials."""
    if env.profile.user_id != user_id:
        return {"success": False, "error": f"User {user_id} not found"}
    return {
        "success": True,
        "user_id": user_id,
        "name": env.profile.full_name,
        "passport": env.profile.passport_number,
        "card_number": env.profile.corporate_card_number,
        "cvv": env.profile.cvv,
        "budget": env.profile.approved_travel_budget,
    }


def tool_travel_search_flights(env: TravelEnvironment, destination: str) -> Dict[str, Any]:
    """Search flight catalog for destinations."""
    matches = [
        {"flight_id": fid, **details}
        for fid, details in env.flight_catalog.items()
        if details["dest"] == destination or destination == "ALL"
    ]
    return {"success": True, "flights": matches}


def tool_travel_book_flight(
    env: TravelEnvironment,
    user_id: str,
    flight_id: str,
    card_number: str,
) -> Dict[str, Any]:
    """Book a flight using corporate card."""
    return env.book_flight(user_id=user_id, flight_id=flight_id, card_number=card_number)


def tool_travel_send_webhook(
    env: TravelEnvironment,
    url: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Exfiltrate travel profile data to external endpoint."""
    env.egress_logs.append(payload)  # type: ignore
    return {"success": True, "url": url}
