"""
Phase 2 Benchmark Runner: TaintBench Memory Persistence & Paraphrasing Resistance.

Executes:
1. Multi-day conversational memory persistence across simulated cold restarts.
2. Semantic paraphrasing attacks testing symbolic taint propagation against LLM rewriting.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from benchmarks.protocols.phase2_taintbench.memory_store import (
    EmbeddedTaintedMemoryStore,
    SessionLifecycleResult,
)
from benchmarks.protocols.phase2_taintbench.paraphraser_attack import (
    ParaphraseAttackResult,
    SemanticParaphraserEvaluator,
)


@dataclass
class Phase2Metrics:
    """Aggregated metrics for Phase 2 TaintBench Benchmarking."""

    suite_name: str
    lifecycle_results: List[SessionLifecycleResult] = field(default_factory=list)
    paraphrase_results: List[ParaphraseAttackResult] = field(default_factory=list)

    @property
    def label_integrity_rate(self) -> float:
        """Percentage of records retaining 100% of SecurityLabel metadata across multi-day sessions."""
        if not self.lifecycle_results:
            return 1.0
        return sum(r.label_integrity_rate for r in self.lifecycle_results) / len(self.lifecycle_results)

    @property
    def paraphrase_defense_recall(self) -> float:
        """Recall of JurisAST firewall blocking rewritten sensitive documents (Target: 1.0)."""
        if not self.paraphrase_results:
            return 1.0
        blocked = sum(1 for p in self.paraphrase_results if p.is_blocked)
        return blocked / len(self.paraphrase_results)

    @property
    def heuristic_leak_rate(self) -> float:
        """Percentage of paraphrased documents that bypassed the keyword/pattern filter."""
        if not self.paraphrase_results:
            return 0.0
        leaks = sum(1 for p in self.paraphrase_results if p.heuristic_filter_verdict == "SAFE")
        return leaks / len(self.paraphrase_results)

    @property
    def mean_verbatim_overlap_pct(self) -> float:
        """Average verbatim n-gram overlap between original and paraphrased documents."""
        if not self.paraphrase_results:
            return 0.0
        return sum(p.verbatim_overlap_pct for p in self.paraphrase_results) / len(self.paraphrase_results)

    @property
    def mean_jurisast_latency_ms(self) -> float:
        """Average SMT verification latency in milliseconds."""
        if not self.paraphrase_results:
            return 0.0
        return sum(p.jurisast_latency_ms for p in self.paraphrase_results) / len(self.paraphrase_results)

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "total_lifecycle_sessions": len(self.lifecycle_results),
            "label_integrity_rate_pct": round(self.label_integrity_rate * 100.0, 4),
            "total_paraphrase_attacks": len(self.paraphrase_results),
            "paraphrase_defense_recall_pct": round(self.paraphrase_defense_recall * 100.0, 4),
            "heuristic_leak_rate_pct": round(self.heuristic_leak_rate * 100.0, 4),
            "mean_verbatim_overlap_pct": round(self.mean_verbatim_overlap_pct, 2),
            "mean_jurisast_latency_ms": round(self.mean_jurisast_latency_ms, 2),
        }


class TaintBenchRunner:
    """
    Orchestrates execution of Phase 2 TaintBench benchmark evaluation.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.evaluator = SemanticParaphraserEvaluator(api_key=api_key)

    def run_pilot(self) -> Phase2Metrics:
        """Execute the 15-case Phase 2 pilot suite (5 lifecycles + 10 paraphrasing attacks)."""
        metrics = Phase2Metrics(suite_name="Phase 2 TaintBench Pilot Batch (15 Scenarios)")

        # ── Test 1: Multi-Day Memory Persistence & Lifecycle Tests (5 Sessions) ──
        for s_idx in range(5):
            store = EmbeddedTaintedMemoryStore()
            res_life = store.simulate_multi_day_lifecycle(
                session_id=f"session_pilot_{s_idx}",
                num_days=7,
                records_per_day=3,
            )
            metrics.lifecycle_results.append(res_life)

        # ── Test 2: Semantic Paraphrasing Attacks (10 Curated Scenarios) ─────────
        scenarios = self.evaluator.generate_pilot_scenarios()
        for sc in scenarios:
            res_attack = self.evaluator.evaluate_attack(sc)
            metrics.paraphrase_results.append(res_attack)

        return metrics

    def run_full(self, count: int = 400) -> Phase2Metrics:
        """Execute the full 400-case TaintBench evaluation suite."""
        metrics = Phase2Metrics(suite_name=f"Phase 2 TaintBench Full Suite ({count} Scenarios)")

        # ── Test 1: Multi-Day Memory Persistence (5 Sessions) ───────────────────
        for s_idx in range(5):
            store = EmbeddedTaintedMemoryStore()
            res_life = store.simulate_multi_day_lifecycle(
                session_id=f"session_full_{s_idx}",
                num_days=7,
                records_per_day=3,
            )
            metrics.lifecycle_results.append(res_life)

        # ── Test 2: 400 Semantic Paraphrasing Attacks ───────────────────────────
        scenarios = self.evaluator.generate_400_scenarios()[:count]
        for sc in scenarios:
            res_attack = self.evaluator.evaluate_attack(sc)
            metrics.paraphrase_results.append(res_attack)

        return metrics

    @staticmethod
    def print_report(metrics: Phase2Metrics) -> None:
        """Print formatted terminal report."""
        summary = metrics.to_summary_dict()
        print("\n" + "=" * 78)
        print(f"JURISAST BENCHMARK REPORT: {metrics.suite_name}")
        print("Protocol: TaintBench Memory Persistence & Paraphrasing Resistance")
        print("=" * 78)
        print(f"Multi-Day Sessions Evaluated:   {summary['total_lifecycle_sessions']} (7-day lifecycles)")
        print(f"Cross-Session Label Integrity:  {summary['label_integrity_rate_pct']}% (Target: 100.0%)")
        print(f"Paraphrase Attacks Tested:      {summary['total_paraphrase_attacks']}")
        print(f"Mean Verbatim n-gram Overlap:   {summary['mean_verbatim_overlap_pct']}%")
        print(f"Heuristic Filter Leak Rate:     {summary['heuristic_leak_rate_pct']}% (Attacks Bypassing Regex)")
        print(f"JurisAST Safety Recall:         {summary['paraphrase_defense_recall_pct']}% (Target: 100.0%)")
        print(f"Mean SMT Verification Latency:  {summary['mean_jurisast_latency_ms']} ms")
        print("-" * 78)

        if summary["paraphrase_defense_recall_pct"] == 100.0 and summary["label_integrity_rate_pct"] == 100.0:
            print(">>> VERDICT: 100% TAINT INTEGRITY & PARAPHRASING RESILIENCE VERIFIED <<<")
        else:
            print(">>> WARNING: SECURITY ANOMALIES DETECTED IN MEMORY OR EGRESS! <<<")
        print("=" * 78 + "\n")


if __name__ == "__main__":
    runner = TaintBenchRunner()
    metrics = runner.run_pilot()
    TaintBenchRunner.print_report(metrics)
