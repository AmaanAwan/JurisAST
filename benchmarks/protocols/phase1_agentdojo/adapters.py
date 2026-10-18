"""
JurisAST Information Flow Control Adapters for AgentDojo Multi-Suite Benchmark.

Wraps raw tools with symbolic taint tracking and SMT verification across:
1. Banking & Finance Suite
2. Slack Collaborative Workspace Suite
3. Travel & Corporate Reservations Suite
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from jurisast_core.ast_ir import DataSourceNode, ExecutionGraph, SinkNode, TransformNode
from jurisast_core.exceptions import TaintViolationError
from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel
from jurisast_core.solver import Z3SolverEngine
from benchmarks.protocols.phase1_agentdojo.environment import (
    BankingEnvironment,
    SlackEnvironment,
    TravelEnvironment,
)
from benchmarks.protocols.phase1_agentdojo.tools import (
    tool_get_balance,
    tool_get_pending_bills,
    tool_get_transaction_history,
    tool_send_external_webhook,
    tool_slack_post_message,
    tool_slack_read_channel,
    tool_slack_send_webhook,
    tool_transfer_funds,
    tool_travel_book_flight,
    tool_travel_get_profile,
    tool_travel_search_flights,
    tool_travel_send_webhook,
)


@dataclass
class ToolExecutionVerification:
    """Telemetry outcome of a tool execution security check."""

    tool_name: str
    is_authorized: bool
    solver_status: str  # "SAFE", "VIOLATION", "TIMEOUT"
    latency_ms: float
    blocked_reason: Optional[str] = None


class BaseProtectedToolkit:
    """Shared SMT verification engine for tool execution."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def _verify_flow(
        self,
        source_label: SecurityLabel,
        sink_tool: str,
        sink_jurisdiction: Jurisdiction,
        sink_max_classification: Classification,
        operation_name: str = "agent_dispatch",
    ) -> ToolExecutionVerification:
        src = DataSourceNode(
            node_id="src_data",
            tool_name=f"{sink_tool}_source",
            label=source_label,
        )
        xfm = TransformNode(
            node_id="xfm_processing",
            operation=operation_name,
            input_node_ids=["src_data"],
            output_label=source_label,
        )
        snk = SinkNode(
            node_id="snk_egress",
            tool_name=sink_tool,
            input_node_ids=["xfm_processing"],
            target_jurisdiction=sink_jurisdiction,
            max_classification=sink_max_classification,
        )
        graph = ExecutionGraph(
            graph_id=f"flow_{int(time.time() * 1000)}",
            agent_id=self.agent_id,
            nodes=[src, xfm, snk],
            edges=[("src_data", "xfm_processing"), ("xfm_processing", "snk_egress")],
        )

        solver = Z3SolverEngine(timeout_ms=50)
        solver.encode_graph(graph)

        start = time.perf_counter()
        res = solver.verify()
        latency_ms = (time.perf_counter() - start) * 1000.0

        is_authorized = (res.status == "SAFE")
        reason = None
        if not is_authorized:
            reason = f"Security Violation: Source classification {source_label.classification.name} exceeds sink clearance {sink_max_classification.name}"

        return ToolExecutionVerification(
            tool_name=sink_tool,
            is_authorized=is_authorized,
            solver_status=res.status,
            latency_ms=latency_ms,
            blocked_reason=reason,
        )


# ═════════════════════════════════════════════════════════════════════════════
# 1. PROTECTED BANKING TOOLKIT
# ═════════════════════════════════════════════════════════════════════════════

class ProtectedBankingToolkit(BaseProtectedToolkit):
    """JurisAST-hardened Banking Toolkit."""

    def __init__(self, env: BankingEnvironment, agent_id: str = "banking_assistant_agent") -> None:
        super().__init__(agent_id=agent_id)
        self.env = env
        self.verified_payees = {
            BankingEnvironment.UTILITY_IBAN: "Electric Utility Inc.",
            BankingEnvironment.LANDLORD_IBAN: "Metro Housing LLC",
            BankingEnvironment.ALICE_IBAN: "Alice Smith",
        }

    def get_balance(self, account_id: str) -> Dict[str, Any]:
        res = tool_get_balance(self.env, account_id)
        res["_security_label"] = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"banking_balance"}),
        )
        return res

    def get_transaction_history(self, account_id: str) -> Dict[str, Any]:
        res = tool_get_transaction_history(self.env, account_id)
        res["_security_label"] = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"banking_ledger", "pii"}),
        )
        return res

    def transfer_funds(
        self,
        source_account_id: str,
        recipient_iban: str,
        amount: float,
        memo: str,
        source_label: Optional[SecurityLabel] = None,
    ) -> Dict[str, Any]:
        active_label = source_label or SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"banking_balance"}),
        )

        is_verified_payee = recipient_iban in self.verified_payees
        sink_jurisdiction = Jurisdiction.INTERNAL if is_verified_payee else Jurisdiction.EXTERNAL
        sink_max_clearance = Classification.CONFIDENTIAL if is_verified_payee else Classification.PUBLIC

        verif = self._verify_flow(
            source_label=active_label,
            sink_tool="transfer_funds",
            sink_jurisdiction=sink_jurisdiction,
            sink_max_classification=sink_max_clearance,
            operation_name=f"transfer_to_{recipient_iban[:8]}",
        )

        if not verif.is_authorized:
            raise TaintViolationError(
                f"Unauthorized transfer blocked: Recipient IBAN {recipient_iban} is not an authorized internal cleared payee. {verif.blocked_reason}"
            )

        res = tool_transfer_funds(self.env, source_account_id, recipient_iban, amount, memo)
        res["_verification"] = verif
        return res

    def send_external_webhook(
        self,
        url: str,
        payload: Dict[str, Any],
        source_label: Optional[SecurityLabel] = None,
    ) -> Dict[str, Any]:
        active_label = source_label or SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"banking_ledger"}),
        )
        verif = self._verify_flow(
            source_label=active_label,
            sink_tool="send_external_webhook",
            sink_jurisdiction=Jurisdiction.EXTERNAL,
            sink_max_classification=Classification.PUBLIC,
            operation_name="external_webhook_egress",
        )
        if not verif.is_authorized:
            raise TaintViolationError(f"Unauthorized webhook exfiltration blocked to {url}. {verif.blocked_reason}")
        res = tool_send_external_webhook(self.env, url, payload)
        res["_verification"] = verif
        return res


# ═════════════════════════════════════════════════════════════════════════════
# 2. PROTECTED SLACK TOOLKIT
# ═════════════════════════════════════════════════════════════════════════════

class ProtectedSlackToolkit(BaseProtectedToolkit):
    """JurisAST-hardened Slack Collaborative Toolkit."""

    def __init__(self, env: SlackEnvironment, agent_id: str = "slack_assistant_agent") -> None:
        super().__init__(agent_id=agent_id)
        self.env = env

    def read_channel(self, channel_id: str) -> Dict[str, Any]:
        res = tool_slack_read_channel(self.env, channel_id)
        ch_class = res.get("classification", "PUBLIC")
        if ch_class == "RESTRICTED":
            label = SecurityLabel(jurisdiction=Jurisdiction.INTERNAL, classification=Classification.RESTRICTED, compartments=frozenset({"executive_secrets"}))
        elif ch_class == "CONFIDENTIAL":
            label = SecurityLabel(jurisdiction=Jurisdiction.INTERNAL, classification=Classification.CONFIDENTIAL, compartments=frozenset({"finance"}))
        else:
            label = SecurityLabel(jurisdiction=Jurisdiction.INTERNAL, classification=Classification.PUBLIC, compartments=frozenset())
        res["_security_label"] = label
        return res

    def post_message(
        self,
        sender_id: str,
        channel_id: str,
        text: str,
        source_label: Optional[SecurityLabel] = None,
    ) -> Dict[str, Any]:
        ch = self.env.channels.get(channel_id)
        if not ch:
            return {"success": False, "error": f"Channel {channel_id} not found"}

        # Target clearance matches channel classification
        if ch.classification == "RESTRICTED":
            sink_clearance = Classification.RESTRICTED
        elif ch.classification == "CONFIDENTIAL":
            sink_clearance = Classification.CONFIDENTIAL
        else:
            sink_clearance = Classification.PUBLIC

        active_label = source_label or SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.PUBLIC,
            compartments=frozenset(),
        )

        verif = self._verify_flow(
            source_label=active_label,
            sink_tool="slack_post_message",
            sink_jurisdiction=Jurisdiction.INTERNAL,
            sink_max_classification=sink_clearance,
            operation_name=f"post_to_{ch.name}",
        )

        if not verif.is_authorized:
            raise TaintViolationError(
                f"Unauthorized Slack post blocked: Attempted to post {active_label.classification.name} content into {ch.name} ({sink_clearance.name} clearance). {verif.blocked_reason}"
            )

        res = tool_slack_post_message(self.env, sender_id, channel_id, text)
        res["_verification"] = verif
        return res

    def send_webhook(
        self,
        url: str,
        payload: Dict[str, Any],
        source_label: Optional[SecurityLabel] = None,
    ) -> Dict[str, Any]:
        active_label = source_label or SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"slack_private"}),
        )
        verif = self._verify_flow(
            source_label=active_label,
            sink_tool="slack_send_webhook",
            sink_jurisdiction=Jurisdiction.EXTERNAL,
            sink_max_classification=Classification.PUBLIC,
            operation_name="slack_webhook_egress",
        )
        if not verif.is_authorized:
            raise TaintViolationError(f"Unauthorized Slack webhook exfiltration blocked to {url}. {verif.blocked_reason}")
        res = tool_slack_send_webhook(self.env, url, payload)
        res["_verification"] = verif
        return res


# ═════════════════════════════════════════════════════════════════════════════
# 3. PROTECTED TRAVEL TOOLKIT
# ═════════════════════════════════════════════════════════════════════════════

class ProtectedTravelToolkit(BaseProtectedToolkit):
    """JurisAST-hardened Corporate Travel Toolkit."""

    def __init__(self, env: TravelEnvironment, agent_id: str = "travel_assistant_agent") -> None:
        super().__init__(agent_id=agent_id)
        self.env = env

    def get_profile(self, user_id: str) -> Dict[str, Any]:
        res = tool_travel_get_profile(self.env, user_id)
        res["_security_label"] = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"passport", "pci_cardholder"}),
        )
        return res

    def book_flight(
        self,
        user_id: str,
        flight_id: str,
        card_number: str,
        source_label: Optional[SecurityLabel] = None,
    ) -> Dict[str, Any]:
        flight = self.env.flight_catalog.get(flight_id)
        is_approved = flight.get("is_approved", False) if flight else False

        sink_jurisdiction = Jurisdiction.INTERNAL if is_approved else Jurisdiction.EXTERNAL
        sink_max_clearance = Classification.RESTRICTED if is_approved else Classification.PUBLIC

        active_label = source_label or SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.RESTRICTED,
            compartments=frozenset({"pci_cardholder"}),
        )

        verif = self._verify_flow(
            source_label=active_label,
            sink_tool="travel_book_flight",
            sink_jurisdiction=sink_jurisdiction,
            sink_max_classification=sink_max_clearance,
            operation_name=f"book_flight_{flight_id}",
        )

        if not verif.is_authorized:
            raise TaintViolationError(
                f"Unauthorized travel booking blocked: Flight {flight_id} is not an authorized business trip destination. {verif.blocked_reason}"
            )

        res = tool_travel_book_flight(self.env, user_id, flight_id, card_number)
        res["_verification"] = verif
        return res

    def send_webhook(
        self,
        url: str,
        payload: Dict[str, Any],
        source_label: Optional[SecurityLabel] = None,
    ) -> Dict[str, Any]:
        active_label = source_label or SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"passport"}),
        )
        verif = self._verify_flow(
            source_label=active_label,
            sink_tool="travel_send_webhook",
            sink_jurisdiction=Jurisdiction.EXTERNAL,
            sink_max_classification=Classification.PUBLIC,
            operation_name="travel_webhook_egress",
        )
        if not verif.is_authorized:
            raise TaintViolationError(f"Unauthorized travel credential exfiltration blocked to {url}. {verif.blocked_reason}")
        res = tool_travel_send_webhook(self.env, url, payload)
        res["_verification"] = verif
        return res
