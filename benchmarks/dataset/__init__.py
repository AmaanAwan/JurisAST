"""
Dataset models and parametric trace generator for JurisAST benchmarks.
"""

from benchmarks.dataset.models import (
    BenchmarkTrace,
    GroundTruthStatus,
    TraceCategory,
    TraceGroundTruth,
    TraceSpec,
)
from benchmarks.dataset.generator import ParametricDatasetGenerator
from benchmarks.dataset.schema import (
    BenchmarkCase,
    BenchmarkSuiteCatalog,
    DeclassificationDomain,
    DeclassificationSpec,
    NonViolationType,
    RegulationType,
    ViolationType,
)
from benchmarks.dataset.cases_catalog import build_master_benchmark_catalog

__all__ = [
    "BenchmarkTrace",
    "GroundTruthStatus",
    "TraceCategory",
    "TraceGroundTruth",
    "TraceSpec",
    "ParametricDatasetGenerator",
    "RegulationType",
    "ViolationType",
    "NonViolationType",
    "DeclassificationDomain",
    "DeclassificationSpec",
    "BenchmarkCase",
    "BenchmarkSuiteCatalog",
    "build_master_benchmark_catalog",
]
