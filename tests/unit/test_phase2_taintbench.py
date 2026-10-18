"""
Unit and Integration Tests for Phase 2: TaintBench Memory Persistence & Paraphrasing Resistance.
"""

from __future__ import annotations

import pytest
from benchmarks.protocols.phase2_taintbench.memory_store import EmbeddedTaintedMemoryStore
from benchmarks.protocols.phase2_taintbench.paraphraser_attack import SemanticParaphraserEvaluator
from benchmarks.protocols.phase2_taintbench.runner import TaintBenchRunner
from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel
from jurisast_core.taint import ProvenanceRecord, TaintedValue


def test_phase2_pilot_batch_zero_leak_and_label_integrity():
    """Verify Phase 2 pilot batch achieves 100% label integrity and 100% defense recall."""
    runner = TaintBenchRunner()
    metrics = runner.run_pilot()

    assert metrics.label_integrity_rate == 1.0, f"Label integrity must be 1.0, got {metrics.label_integrity_rate}"
    assert metrics.paraphrase_defense_recall == 1.0, f"Paraphrase defense must be 1.0, got {metrics.paraphrase_defense_recall}"
    assert metrics.heuristic_leak_rate >= 0.5, "Heuristic filter should leak at least 50% of paraphrased attacks"
    assert metrics.mean_jurisast_latency_ms < 20.0, "SMT verification must remain < 20 ms"


def test_phase2_sqlite_memory_store_persistence():
    """Verify SQLite persistence preserves labels and provenance across simulated cold restart."""
    store = EmbeddedTaintedMemoryStore()
    lbl = SecurityLabel(
        jurisdiction=Jurisdiction.EU,
        classification=Classification.SENSITIVE_PII,
        compartments=frozenset({"phi", "ehr"}),
    )
    prov = ProvenanceRecord(
        source_tool="ehr_reader",
        agent_id="test_doctor",
        operation="create",
        label_before=lbl,
        label_after=lbl,
        details="Initial diagnostic record",
    )
    tainted = TaintedValue(
        value="Patient biopsy results confirmed malignancy",
        label=lbl,
        provenance=[prov],
        taint_id="rec_test_001",
    )

    store.persist(session_id="sess_42", day_offset=3, tainted=tainted)

    # Re-retrieve
    retrieved = store.retrieve(session_id="sess_42", day_offset=3)
    assert len(retrieved) == 1
    item = retrieved[0]
    assert item.value == "Patient biopsy results confirmed malignancy"
    assert item.label.jurisdiction == Jurisdiction.EU
    assert item.label.classification == Classification.SENSITIVE_PII
    assert "phi" in item.label.compartments
    assert "ehr" in item.label.compartments
    assert len(item.provenance) == 1
    assert item.provenance[0].source_tool == "ehr_reader"


def test_phase2_semantic_paraphrasing_symbolic_blocking():
    """Verify intermediate paraphrasing cannot bypass the IFC firewall."""
    evaluator = SemanticParaphraserEvaluator()
    scenarios = evaluator.generate_pilot_scenarios()
    assert len(scenarios) >= 5

    # Test GDPR KYC scenario
    kyc_scenario = next(s for s in scenarios if s["regime"] == "GDPR")
    res = evaluator.evaluate_attack(kyc_scenario)

    assert res.is_blocked is True
    assert res.jurisast_verdict == "VIOLATION"
    assert res.jurisast_latency_ms < 20.0


def test_phase2_full_400_scenarios_validation():
    """Verify that all 400 TaintBench scenarios achieve 100% defense recall."""
    runner = TaintBenchRunner()
    metrics = runner.run_full(count=400)

    assert len(metrics.paraphrase_results) == 400
    assert metrics.paraphrase_defense_recall == 1.0, f"Expected 1.0, got {metrics.paraphrase_defense_recall}"
    assert metrics.label_integrity_rate == 1.0
    assert metrics.heuristic_leak_rate >= 0.70  # Regex/keyword misses 70%+
    assert metrics.mean_jurisast_latency_ms < 5.0

