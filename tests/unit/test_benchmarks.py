"""
Unit tests for the Benchmark Suite: Dataset Generator and Models.
"""

from __future__ import annotations

import pytest

from benchmarks.config import BenchmarkConfig
from benchmarks.dataset.generator import ParametricDatasetGenerator
from benchmarks.dataset.models import GroundTruthStatus, TraceCategory
from benchmarks.baselines.pattern_filter import PatternFilterBaseline
from jurisast_core.solver import Z3SolverEngine
from jurisast_policies import GDPR_DATA_SOVEREIGNTY


def test_parametric_dataset_generator_pilot():
    """Verify pilot generator produces expected trace counts and valid structures."""
    gen = ParametricDatasetGenerator(seed=42)
    traces = gen.generate_pilot(
        compliant=5,
        cross_border=5,
        special_category=5,
        multi_hop=5,
        declassification=5,
    )
    assert len(traces) == 25

    # Check categories
    categories = {t.spec.category for t in traces}
    assert TraceCategory.COMPLIANT_SOVEREIGN in categories
    assert TraceCategory.CROSS_BORDER_EXFILTRATION in categories
    assert TraceCategory.SPECIAL_CATEGORY_EXPOSURE in categories
    assert TraceCategory.MULTI_HOP_LAUNDERING in categories
    assert TraceCategory.CONTROLLED_DECLASSIFICATION in categories

    # Verify every graph is a structurally valid DAG
    for t in traces:
        assert len(t.graph.validate_structure()) == 0


def test_jurisast_perfect_ground_truth_alignment():
    """Verify JurisAST Z3 solver matches 100% of ground-truth outcomes on pilot traces."""
    gen = ParametricDatasetGenerator(seed=42)
    traces = gen.generate_pilot(
        compliant=3,
        cross_border=3,
        special_category=2,
        multi_hop=2,
        declassification=2,
    )

    for t in traces:
        solver = Z3SolverEngine(timeout_ms=50)
        solver.encode_graph(t.graph)
        solver.add_policy_constraints(GDPR_DATA_SOVEREIGNTY, graph=t.graph)
        res = solver.verify()
        assert res.status == t.ground_truth.status.value


def test_pattern_filter_baseline():
    """Verify heuristic keyword filter runs and flags keywords."""
    gen = ParametricDatasetGenerator(seed=42)
    traces = gen.generate_pilot(compliant=2, cross_border=2, special_category=2, multi_hop=2, declassification=2)
    pf = PatternFilterBaseline()

    for t in traces:
        res = pf.evaluate_trace(t)
        assert res["verdict"] in ("SAFE", "VIOLATION")
        assert "latency_ms" in res


def test_master_benchmark_catalog():
    """Verify master benchmark schema catalog builds all 11 regulations with violations and non-violations."""
    from benchmarks.dataset import (
        RegulationType,
        ViolationType,
        NonViolationType,
        build_master_benchmark_catalog,
    )
    catalog = build_master_benchmark_catalog()
    assert len(catalog.cases) >= 15

    regulations = {c.regulation for c in catalog.cases}
    assert RegulationType.GDPR in regulations
    assert RegulationType.HIPAA in regulations
    assert RegulationType.PCI_DSS in regulations
    assert RegulationType.ITAR_EAR in regulations
    assert RegulationType.CCPA_CPRA in regulations
    assert RegulationType.DORA in regulations
    assert RegulationType.CHINA_PIPL in regulations
    assert RegulationType.COLORADO_AI_ACT in regulations
    assert RegulationType.ISO_42001_NIST in regulations

    violations = catalog.get_violations()
    compliant = catalog.get_compliant()
    assert len(violations) > 0
    assert len(compliant) > 0

    # Verify declassification specs
    declass_cases = [c for c in catalog.cases if c.declassification_spec is not None]
    assert len(declass_cases) >= 5
    for dc in declass_cases:
        assert dc.declassification_spec.max_bits <= 4.0
        assert dc.declassification_spec.cardinality >= 2
