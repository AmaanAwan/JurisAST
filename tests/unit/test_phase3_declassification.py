"""
Unit and Property Tests for Phase 3: Information-Theoretic Declassification Stress Testing.
"""

from __future__ import annotations

import pytest
from benchmarks.protocols.phase3_declassification.runner import DeclassificationStressRunner
from benchmarks.protocols.phase3_declassification.budget_slack import ChannelBudgetSlackCalculator, DeclassificationTestCase


def test_phase3_pilot_batch_zero_false_negatives():
    """Verify that pilot batch achieves 100% safety recall and zero illegal leaks."""
    runner = DeclassificationStressRunner(seed=42)
    metrics = runner.run_pilot()

    assert metrics.total_cases == 50
    assert metrics.safety_recall == 1.0, f"Safety recall must be 1.0, got {metrics.safety_recall}"
    assert metrics.fn == 0, f"Expected 0 illegal data leaks, found {metrics.fn}"
    assert metrics.attack_success_rate == 0.0
    assert metrics.accuracy == 1.0


def test_phase3_budget_slack_mathematical_bounds():
    """Verify mathematical calculation of slack Δ across boundary conditions."""
    # Boolean: Capacity = 1.0 bit
    _, slack_pos = ChannelBudgetSlackCalculator.compute_slack(bool, max_allowed_bits=2.0)
    assert slack_pos == 1.0  # Δ = 2.0 - 1.0 = +1.0

    _, slack_exact = ChannelBudgetSlackCalculator.compute_slack(bool, max_allowed_bits=1.0)
    assert slack_exact == 0.0  # Δ = 1.0 - 1.0 = 0.0

    _, slack_neg = ChannelBudgetSlackCalculator.compute_slack(bool, max_allowed_bits=0.5)
    assert slack_neg == -0.5  # Δ = 0.5 - 1.0 = -0.5

    # Unbounded string: Capacity = inf -> Δ = -inf
    _, slack_unbounded = ChannelBudgetSlackCalculator.compute_slack(str, max_allowed_bits=10.0)
    assert slack_unbounded == -float("inf")


def test_phase3_adversarial_enum_payload_smuggle():
    """Verify enum string smuggling is strictly rejected."""
    runner = DeclassificationStressRunner(seed=42)
    cases = [c for c in runner.fuzzer.generate_pilot_batch() if "SMUGGLE" in c.case_id]
    assert len(cases) > 0
    for c in cases:
        res = ChannelBudgetSlackCalculator.evaluate_test_case(c)
        assert res.actual_status == "REJECTED"
        assert res.is_leak_fn is False
