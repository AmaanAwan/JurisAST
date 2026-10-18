"""
Phase 4 Benchmark Runner: Adaptive White-Box Red-Teaming.

Executes white-box stress testing covering:
1. SMT 50 ms timeout fail-closed enforcement.
2. Cyclic graph dependency poisoning (Kahn's algorithm detection).
3. Pydantic strict mode type coercion exploits.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List

from benchmarks.protocols.phase4_redteam.coercion_fuzzer import (
    CoercionExploitResult,
    TypeCoercionExploitFuzzer,
)
from benchmarks.protocols.phase4_redteam.cycle_injector import (
    CycleInjectionResult,
    CyclicGraphInjector,
)
from benchmarks.protocols.phase4_redteam.timeout_bombs import (
    SMTTimeoutBombGenerator,
    TimeoutStressResult,
)


@dataclass
class Phase4Metrics:
    """Aggregated metrics for Phase 4 Adaptive Red-Teaming."""

    suite_name: str
    timeout_tests: List[TimeoutStressResult] = field(default_factory=list)
    cycle_tests: List[CycleInjectionResult] = field(default_factory=list)
    coercion_tests: List[CoercionExploitResult] = field(default_factory=list)

    @property
    def total_attacks(self) -> int:
        return len(self.timeout_tests) + len(self.cycle_tests) + len(self.coercion_tests)

    @property
    def fail_closed_rate(self) -> float:
        """Percentage of timeout stress tests that strictly failed closed."""
        if not self.timeout_tests:
            return 1.0
        passed = sum(1 for t in self.timeout_tests if t.failed_closed)
        return passed / len(self.timeout_tests)

    @property
    def cycle_detection_rate(self) -> float:
        """Percentage of cyclic graph poisoning attempts caught cleanly."""
        if not self.cycle_tests:
            return 1.0
        passed = sum(1 for c in self.cycle_tests if c.detected_cleanly)
        return passed / len(self.cycle_tests)

    @property
    def coercion_rejection_rate(self) -> float:
        """Percentage of loose type coercion exploits blocked."""
        if not self.coercion_tests:
            return 1.0
        passed = sum(1 for x in self.coercion_tests if x.rejected)
        return passed / len(self.coercion_tests)

    @property
    def overall_security_recall(self) -> float:
        """Overall safety recall across all white-box red-teaming vectors."""
        passed_timeouts = sum(1 for t in self.timeout_tests if t.failed_closed)
        passed_cycles = sum(1 for c in self.cycle_tests if c.detected_cleanly)
        passed_coercions = sum(1 for x in self.coercion_tests if x.rejected)
        total = self.total_attacks
        return ((passed_timeouts + passed_cycles + passed_coercions) / total) if total > 0 else 1.0

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "total_adversarial_vectors": self.total_attacks,
            "fail_closed_rate_pct": round(self.fail_closed_rate * 100.0, 4),
            "cycle_detection_rate_pct": round(self.cycle_detection_rate * 100.0, 4),
            "coercion_rejection_rate_pct": round(self.coercion_rejection_rate * 100.0, 4),
            "overall_security_recall_pct": round(self.overall_security_recall * 100.0, 4),
        }


class WhiteBoxRedTeamRunner:
    """
    Orchestrates Phase 4 adaptive red-teaming benchmark evaluation.
    """

    def run_pilot(self) -> Phase4Metrics:
        """Execute the Phase 4 pilot batch of curated white-box attacks."""
        metrics = Phase4Metrics(suite_name="Phase 4 White-Box Red-Teaming Pilot")

        # ── Vector 1: SMT Solver Timeout Bombs ────────────────────────────
        # Test 1: 5 ms hard timeout with 9 holes
        t1 = SMTTimeoutBombGenerator.execute_timeout_test(
            test_id="PH4_PILOT_SMT_001_5MS_LIMIT",
            num_holes=9,
            timeout_ms=5,
        )
        metrics.timeout_tests.append(t1)

        # Test 2: 10 ms timeout with 9 holes
        t2 = SMTTimeoutBombGenerator.execute_timeout_test(
            test_id="PH4_PILOT_SMT_002_10MS_LIMIT",
            num_holes=9,
            timeout_ms=10,
        )
        metrics.timeout_tests.append(t2)

        # Test 3: 50 ms standard deadline with 9 holes
        t3 = SMTTimeoutBombGenerator.execute_timeout_test(
            test_id="PH4_PILOT_SMT_003_50MS_DEADLINE",
            num_holes=9,
            timeout_ms=50,
        )
        metrics.timeout_tests.append(t3)

        # ── Vector 2: Cyclic Dependency Poisoning ─────────────────────────
        c_self = CyclicGraphInjector.create_self_loop()
        res_self = CyclicGraphInjector.evaluate_graph("PH4_PILOT_CYCLE_001_SELF", c_self, "SELF_LOOP", 1)
        metrics.cycle_tests.append(res_self)

        c_2node = CyclicGraphInjector.create_two_node_cycle()
        res_2node = CyclicGraphInjector.evaluate_graph("PH4_PILOT_CYCLE_002_2NODE", c_2node, "2_NODE_CYCLE", 2)
        metrics.cycle_tests.append(res_2node)

        c_swarm = CyclicGraphInjector.create_multi_agent_swarm_cycle(hops=5)
        res_swarm = CyclicGraphInjector.evaluate_graph("PH4_PILOT_CYCLE_003_SWARM", c_swarm, "SWARM_CYCLE", 5)
        metrics.cycle_tests.append(res_swarm)

        c_subgraph = CyclicGraphInjector.create_disconnected_cycle_in_dag()
        res_subgraph = CyclicGraphInjector.evaluate_graph("PH4_PILOT_CYCLE_004_DISCONNECTED", c_subgraph, "DISCONNECTED_CYCLE", 2)
        metrics.cycle_tests.append(res_subgraph)

        # ── Vector 3: Pydantic Strict Coercion Exploits ───────────────────
        exploits = TypeCoercionExploitFuzzer.generate_pilot_exploits()
        for exp_id, desc, target_type, payload in exploits:
            res_coercion = TypeCoercionExploitFuzzer.evaluate_exploit(
                exploit_id=exp_id,
                description=desc,
                target_type=target_type,
                payload=payload,
            )
            metrics.coercion_tests.append(res_coercion)

        return metrics

    @staticmethod
    def print_report(metrics: Phase4Metrics) -> None:
        """Print formatted terminal summary report."""
        summary = metrics.to_summary_dict()
        print("\n" + "=" * 78)
        print(f"JURISAST BENCHMARK REPORT: {metrics.suite_name}")
        print("Protocol: Adaptive Red-Teaming Under White-Box Adversary Model")
        print("=" * 78)
        print(f"Total Adversarial Attack Vectors: {summary['total_adversarial_vectors']}")
        print(f"SMT Timeout Fail-Closed Rate:     {summary['fail_closed_rate_pct']}% (Target: 100.0%)")
        print(f"Cycle Detection Recall:           {summary['cycle_detection_rate_pct']}% (Target: 100.0%)")
        print(f"Coercion Exploit Rejection Rate:  {summary['coercion_rejection_rate_pct']}% (Target: 100.0%)")
        print(f"Overall White-Box Defense Recall: {summary['overall_security_recall_pct']}% (Target: 100.0%)")
        print("-" * 78)

        if summary["overall_security_recall_pct"] == 100.0:
            print(">>> VERDICT: 100% WHITE-BOX ADVERSARIAL RESILIENCE VERIFIED <<<")
        else:
            print(">>> WARNING: ADVERSARIAL VULNERABILITIES DETECTED! <<<")
        print("=" * 78 + "\n")


if __name__ == "__main__":
    runner = WhiteBoxRedTeamRunner()
    metrics = runner.run_pilot()
    WhiteBoxRedTeamRunner.print_report(metrics)
