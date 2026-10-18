"""
Unit and Property Tests for Phase 4: Adaptive White-Box Red-Teaming.
"""

from __future__ import annotations

import pytest
from benchmarks.protocols.phase4_redteam.runner import WhiteBoxRedTeamRunner
from benchmarks.protocols.phase4_redteam.timeout_bombs import SMTTimeoutBombGenerator
from benchmarks.protocols.phase4_redteam.cycle_injector import CyclicGraphInjector
from benchmarks.protocols.phase4_redteam.coercion_fuzzer import TypeCoercionExploitFuzzer
from jurisast_core.exceptions import ASTConstructionError, SolverTimeoutError


def test_phase4_pilot_batch_100_percent_defense():
    """Verify that white-box red-teaming pilot achieves 100% defense recall."""
    runner = WhiteBoxRedTeamRunner()
    metrics = runner.run_pilot()

    assert metrics.fail_closed_rate == 1.0, f"Fail-closed rate must be 1.0, got {metrics.fail_closed_rate}"
    assert metrics.cycle_detection_rate == 1.0, f"Cycle detection must be 1.0, got {metrics.cycle_detection_rate}"
    assert metrics.coercion_rejection_rate == 1.0, f"Coercion rejection must be 1.0, got {metrics.coercion_rejection_rate}"
    assert metrics.overall_security_recall == 1.0


def test_phase4_smt_timeout_fail_closed_at_50ms():
    """Verify that pathological Pigeonhole graphs strictly fail closed at 50 ms."""
    res = SMTTimeoutBombGenerator.execute_timeout_test(
        test_id="TEST_SMT_TIMEOUT_50MS",
        num_holes=9,
        timeout_ms=50,
    )
    assert res.solver_status == "TIMEOUT"
    assert res.failed_closed is True
    assert "timeout" in (res.error_message or "").lower()


def test_phase4_cyclic_dependency_graph_poisoning():
    """Verify that Kahn's algorithm detects cycles and raises ASTConstructionError."""
    # Self-loop
    c_self = CyclicGraphInjector.create_self_loop()
    with pytest.raises(ASTConstructionError) as exc_self:
        c_self.topological_order()
    assert "Cycle detected" in str(exc_self.value)

    # 2-node cycle
    c_2node = CyclicGraphInjector.create_two_node_cycle()
    with pytest.raises(ASTConstructionError) as exc_2node:
        c_2node.topological_order()
    assert "Cycle detected" in str(exc_2node.value)

    # Multi-agent swarm cycle
    c_swarm = CyclicGraphInjector.create_multi_agent_swarm_cycle(hops=5)
    with pytest.raises(ASTConstructionError) as exc_swarm:
        c_swarm.topological_order()
    assert "Cycle detected" in str(exc_swarm.value)


def test_phase4_pydantic_type_coercion_rejection():
    """Verify that loose coercions and duck-typed objects are rejected strictly."""
    exploits = TypeCoercionExploitFuzzer.generate_pilot_exploits()
    assert len(exploits) >= 10

    for exp_id, desc, target_type, payload in exploits:
        res = TypeCoercionExploitFuzzer.evaluate_exploit(
            exploit_id=exp_id,
            description=desc,
            target_type=target_type,
            payload=payload,
        )
        assert res.rejected is True, f"Exploit {exp_id} ({desc}) was NOT rejected!"
