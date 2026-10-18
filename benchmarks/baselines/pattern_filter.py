"""
Heuristic / Pattern-matching Filter Baseline.

Demonstrates the limitations of keyword and regex blocklists
(e.g., matching 'PII', 'IBAN', 'confidential' in tool arguments).
"""

from __future__ import annotations

import time
from typing import Any, Dict

from benchmarks.dataset.models import BenchmarkTrace


class PatternFilterBaseline:
    """
    Regex and keyword-based filtering baseline.
    """

    BLOCKED_KEYWORDS = {
        "pii", "iban", "ssn", "passport", "biometric", "patient",
        "confidential", "board", "secret", "kyc", "medical",
    }

    def evaluate_trace(self, trace: BenchmarkTrace) -> Dict[str, Any]:
        """
        Evaluate trace by inspecting node descriptions, tool names, and arguments
        against the keyword blocklist.
        """
        start_ns = time.perf_counter_ns()
        graph = trace.graph
        detected_keywords = []

        # Inspect all nodes
        for node in graph.nodes:
            text = f"{getattr(node, 'tool_name', '')} {getattr(node, 'description', '')} {str(getattr(node, 'arguments', ''))}".lower()
            for kw in self.BLOCKED_KEYWORDS:
                if kw in text:
                    detected_keywords.append(kw)

        sinks = graph.get_sinks()
        has_external_sink = any(s.target_jurisdiction.name in ("US", "EXTERNAL") for s in sinks)

        # Keyword policy: If blocked keyword found AND external sink exists -> Flag violation
        if detected_keywords and has_external_sink:
            verdict = "VIOLATION"
            reason = f"Keyword filter triggered: detected '{detected_keywords[0]}' flowing to external sink."
        else:
            verdict = "SAFE"
            reason = "No blocked keywords detected in external sink flow."

        latency_ms = (time.perf_counter_ns() - start_ns) / 1e6

        return {
            "verdict": verdict,
            "latency_ms": latency_ms,
            "reason": reason,
        }

    def evaluate_payload(self, text: str) -> Dict[str, Any]:
        """Evaluate raw payload string against the keyword blocklist."""
        text_lower = text.lower()
        for kw in self.BLOCKED_KEYWORDS:
            if kw in text_lower:
                return {
                    "verdict": "VIOLATION",
                    "keyword": kw,
                    "reason": f"Detected blocked keyword '{kw}'",
                }
        return {"verdict": "SAFE", "reason": "No blocked keywords detected"}

