"""
Phase 2 Protocol: TaintBench Memory Persistence & Semantic Paraphrasing Resistance.

Evaluates:
1. Cross-session label persistence in embedded local vector/relational memory stores.
2. Multi-day conversational lifecycle label integrity.
3. Resilience against semantic paraphrasing attacks where an intermediate agent
   completely rewrites sensitive documents into alternative prose before sink dispatch.
"""

from __future__ import annotations

import benchmarks.protocols  # Ensures sys.path is configured for local libs

from benchmarks.protocols.phase2_taintbench.memory_store import (
    EmbeddedTaintedMemoryStore,
    MemoryRecord,
    SessionLifecycleResult,
)
from benchmarks.protocols.phase2_taintbench.paraphraser_attack import (
    ParaphraseAttackResult,
    SemanticParaphraserEvaluator,
)
from benchmarks.protocols.phase2_taintbench.runner import (
    Phase2Metrics,
    TaintBenchRunner,
)

__all__ = [
    "EmbeddedTaintedMemoryStore",
    "MemoryRecord",
    "SessionLifecycleResult",
    "ParaphraseAttackResult",
    "SemanticParaphraserEvaluator",
    "Phase2Metrics",
    "TaintBenchRunner",
]
