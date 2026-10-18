"""
Phase 3 Protocol: Information-Theoretic Declassification Channels Stress Testing.

Evaluates Shannon information capacity bounds, channel budget slack (Δ = Max Allowed Bits - log₂(|Y|)),
and execution firewall rejection of synthetic adversarial entropy expansion payloads.
"""

from __future__ import annotations

import benchmarks.protocols  # Ensures sys.path is configured for local libs

from benchmarks.protocols.phase3_declassification.budget_slack import (
    ChannelBudgetSlackCalculator,
    DeclassificationTestCase,
    DeclassificationTestResult,
)
from benchmarks.protocols.phase3_declassification.entropy_fuzzer import (
    AdversarialEntropyFuzzer,
    PayloadType,
)
from benchmarks.protocols.phase3_declassification.runner import (
    DeclassificationStressRunner,
    Phase3Metrics,
)

__all__ = [
    "ChannelBudgetSlackCalculator",
    "DeclassificationTestCase",
    "DeclassificationTestResult",
    "AdversarialEntropyFuzzer",
    "PayloadType",
    "DeclassificationStressRunner",
    "Phase3Metrics",
]
