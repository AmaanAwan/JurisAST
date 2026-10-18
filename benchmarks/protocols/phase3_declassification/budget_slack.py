"""
Channel Budget Slack Computation Engine for Phase 3 Benchmarking.

Mathematical Invariant:
    For every declassification channel, the budget slack is defined as:
        Δ = Max Allowed Bits - log₂(|Y|)
    where |Y| is the cardinality of the discrete output space Y.

    When Δ >= 0, the channel satisfies the information capacity constraint.
    When Δ < 0 (or output_type has unbounded cardinality |Y| = ∞), the channel
    violates non-interference and MUST be rejected by the execution firewall.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Tuple, Type

from pydantic import BaseModel

from jurisast_core.declassifier import DeclassificationBoundary
from jurisast_core.exceptions import DeclassificationDeniedError


@dataclass(frozen=True)
class DeclassificationTestCase:
    """Specification of an empirical declassification test case."""

    case_id: str
    description: str
    output_type: Any
    max_allowed_bits: float
    payload: Any
    is_adversarial: bool
    expected_status: Literal["SAFE", "REJECTED"]
    adversarial_technique: Optional[str] = None


@dataclass
class DeclassificationTestResult:
    """Outcome of evaluating a single declassification test case."""

    case_id: str
    description: str
    max_allowed_bits: float
    output_bits: float
    budget_slack: float  # Δ = max_allowed_bits - output_bits
    is_adversarial: bool
    expected_status: Literal["SAFE", "REJECTED"]
    actual_status: Literal["SAFE", "REJECTED"]
    rejection_reason: Optional[str] = None
    latency_us: float = 0.0

    @property
    def passed(self) -> bool:
        """True if the system's verdict matched ground truth."""
        return self.expected_status == self.actual_status

    @property
    def is_leak_fn(self) -> bool:
        """
        True if the test was adversarial (leak) but the system marked it SAFE.
        This represents a CRITICAL FALSE NEGATIVE (illegal secret exfiltration).
        """
        return self.expected_status == "REJECTED" and self.actual_status == "SAFE"

    @property
    def is_false_alarm_fp(self) -> bool:
        """
        True if the test was safe and within budget, but system rejected it.
        """
        return self.expected_status == "SAFE" and self.actual_status == "REJECTED"


class ChannelBudgetSlackCalculator:
    """
    Computes information capacity slack and validates declassification channel safety.
    """

    @staticmethod
    def compute_capacity(output_type: Any) -> float:
        """
        Compute Shannon entropy bound log₂(|Y|) in bits for output_type.
        Returns float('inf') if type is unbounded.
        """
        try:
            return DeclassificationBoundary.compute_max_bits(output_type)
        except (ValueError, TypeError):
            return float("inf")

    @classmethod
    def compute_slack(cls, output_type: Any, max_allowed_bits: float) -> Tuple[float, float]:
        """
        Compute (output_bits, slack Δ).
        Δ = max_allowed_bits - output_bits
        """
        output_bits = cls.compute_capacity(output_type)
        if math.isinf(output_bits):
            slack = -float("inf")
        else:
            slack = max_allowed_bits - output_bits
        return output_bits, slack

    @classmethod
    def evaluate_test_case(cls, test_case: DeclassificationTestCase) -> DeclassificationTestResult:
        """
        Evaluate a test case against the execution firewall.

        Enforces two-layer defense:
            1. Static type channel capacity: Δ >= 0.
            2. Runtime value strict validation: payload strictly matches declared type without coercion.
        """
        start_ns = time.perf_counter_ns()
        output_bits, slack = cls.compute_slack(test_case.output_type, test_case.max_allowed_bits)

        actual_status: Literal["SAFE", "REJECTED"] = "SAFE"
        rejection_reason: Optional[str] = None

        # Layer 1: Static Shannon Budget Check (Δ < 0)
        if slack < 0.0 or math.isinf(output_bits):
            actual_status = "REJECTED"
            rejection_reason = (
                f"Channel budget exceeded: Δ = {slack:.2f} bits "
                f"(Allowed: {test_case.max_allowed_bits:.2f} bits, Output: {output_bits:.2f} bits)"
            )
        else:
            # Layer 2: Runtime Pydantic Strict Mode Validation
            try:
                DeclassificationBoundary.validate_runtime_value(
                    value=test_case.payload,
                    output_type=test_case.output_type,
                )
                actual_status = "SAFE"
            except (DeclassificationDeniedError, Exception) as exc:
                actual_status = "REJECTED"
                rejection_reason = f"Runtime strict validation failure: {exc}"

        latency_us = (time.perf_counter_ns() - start_ns) / 1000.0

        return DeclassificationTestResult(
            case_id=test_case.case_id,
            description=test_case.description,
            max_allowed_bits=test_case.max_allowed_bits,
            output_bits=output_bits,
            budget_slack=slack,
            is_adversarial=test_case.is_adversarial,
            expected_status=test_case.expected_status,
            actual_status=actual_status,
            rejection_reason=rejection_reason,
            latency_us=latency_us,
        )
