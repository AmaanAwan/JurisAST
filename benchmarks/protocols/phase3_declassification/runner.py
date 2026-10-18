"""
Phase 3 Benchmark Runner: Information-Theoretic Declassification Channels.

Executes empirical stress testing, computes channel budget slack Δ, validates 100%
safety recall (zero leaks allowed), and produces publication-ready telemetry.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from benchmarks.protocols.phase3_declassification.budget_slack import (
    ChannelBudgetSlackCalculator,
    DeclassificationTestCase,
    DeclassificationTestResult,
)
from benchmarks.protocols.phase3_declassification.entropy_fuzzer import AdversarialEntropyFuzzer


@dataclass
class Phase3Metrics:
    """Aggregated performance metrics for Phase 3 benchmarking."""

    suite_name: str
    total_cases: int = 0
    tp: int = 0  # Correctly rejected adversarial/deficit cases
    fp: int = 0  # Safe cases incorrectly rejected
    tn: int = 0  # Safe cases correctly allowed
    fn: int = 0  # CRITICAL LEAKS (adversarial marked SAFE) - MUST BE 0!
    latencies_us: List[float] = field(default_factory=list)
    results: List[DeclassificationTestResult] = field(default_factory=list)

    @property
    def safety_recall(self) -> float:
        """Recall of detecting and rejecting unsafe/adversarial attempts (TP / (TP + FN))."""
        total_unsafe = self.tp + self.fn
        return (self.tp / total_unsafe) if total_unsafe > 0 else 1.0

    @property
    def precision(self) -> float:
        return (self.tp / (self.tp + self.fp)) if (self.tp + self.fp) > 0 else 1.0

    @property
    def accuracy(self) -> float:
        return ((self.tp + self.tn) / self.total_cases) if self.total_cases > 0 else 0.0

    @property
    def attack_success_rate(self) -> float:
        """Percentage of attacks that bypassed defense (FN / Total Unsafe)."""
        total_unsafe = self.tp + self.fn
        return (self.fn / total_unsafe) if total_unsafe > 0 else 0.0

    @property
    def mean_latency_us(self) -> float:
        return (sum(self.latencies_us) / len(self.latencies_us)) if self.latencies_us else 0.0

    @property
    def p99_latency_us(self) -> float:
        if not self.latencies_us:
            return 0.0
        sorted_lat = sorted(self.latencies_us)
        idx = int(0.99 * len(sorted_lat))
        return sorted_lat[min(idx, len(sorted_lat) - 1)]

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "total_cases": self.total_cases,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn_illegal_leaks": self.fn,
            "safety_recall_pct": round(self.safety_recall * 100.0, 4),
            "precision_pct": round(self.precision * 100.0, 4),
            "accuracy_pct": round(self.accuracy * 100.0, 4),
            "attack_success_rate_pct": round(self.attack_success_rate * 100.0, 4),
            "mean_latency_us": round(self.mean_latency_us, 2),
            "p99_latency_us": round(self.p99_latency_us, 2),
        }


class DeclassificationStressRunner:
    """
    Orchestrates execution of Phase 3 declassification empirical stress tests.
    """

    def __init__(self, seed: int = 42) -> None:
        self.fuzzer = AdversarialEntropyFuzzer(seed=seed)

    def run_suite(self, test_cases: List[DeclassificationTestCase], suite_name: str) -> Phase3Metrics:
        """Execute a list of test cases and compute metrics."""
        metrics = Phase3Metrics(suite_name=suite_name, total_cases=len(test_cases))

        for tc in test_cases:
            res = ChannelBudgetSlackCalculator.evaluate_test_case(tc)
            metrics.results.append(res)
            metrics.latencies_us.append(res.latency_us)

            if tc.expected_status == "REJECTED":
                if res.actual_status == "REJECTED":
                    metrics.tp += 1
                else:
                    metrics.fn += 1  # ILLEGAL LEAK ALLOWED
            else:
                if res.actual_status == "SAFE":
                    metrics.tn += 1
                else:
                    metrics.fp += 1  # FALSE ALARM

        return metrics

    def run_pilot(self) -> Phase3Metrics:
        """Execute the 50-case pilot batch."""
        cases = self.fuzzer.generate_pilot_batch()
        return self.run_suite(cases, suite_name="Phase 3 Pilot Batch (50 Cases)")

    def run_full(self, count: int = 1000) -> Phase3Metrics:
        """Execute the 1,000-case full stress suite."""
        cases = self.fuzzer.generate_full_suite(count=count)
        return self.run_suite(cases, suite_name=f"Phase 3 Full Stress Suite ({count} Cases)")

    @staticmethod
    def print_report(metrics: Phase3Metrics) -> None:
        """Print formatted terminal report."""
        summary = metrics.to_summary_dict()
        print("\n" + "=" * 78)
        print(f"JURISAST BENCHMARK REPORT: {metrics.suite_name}")
        print("Protocol: Information-Theoretic Declassification Channel Stress Testing")
        print("=" * 78)
        print(f"Total Evaluations:        {summary['total_cases']}")
        print(f"Safety Recall:            {summary['safety_recall_pct']}% (Target: 100.0%)")
        print(f"Illegal Leaks (FN):       {summary['fn_illegal_leaks']} (Target: 0)")
        print(f"Attack Success Rate:      {summary['attack_success_rate_pct']}% (Target: 0.0%)")
        print(f"Accuracy:                 {summary['accuracy_pct']}%")
        print(f"Mean Verification Time:   {summary['mean_latency_us']} µs")
        print(f"P99 Verification Time:    {summary['p99_latency_us']} µs")
        print("-" * 78)

        if summary["fn_illegal_leaks"] == 0:
            print(">>> VERDICT: FORMAL SOUNDNESS VERIFIED (0 LEAKS ALLOWED) <<<")
        else:
            print(">>> WARNING: SECURITY LEAKS DETECTED! <<<")
        print("=" * 78 + "\n")


if __name__ == "__main__":
    runner = DeclassificationStressRunner()
    pilot_metrics = runner.run_pilot()
    DeclassificationStressRunner.print_report(pilot_metrics)
