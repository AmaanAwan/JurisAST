"""
Phase 4 Protocol: Adaptive White-Box Red-Teaming.

Evaluates system resilience against a white-box adversary with full knowledge of
lattice structure, regulatory policies, and SMT configurations.
Attacks evaluated:
1. SMT Solver Timeout Bombs (Verifying fail-closed at 50 ms deadline).
2. Cyclic Dependency Graph Poisoning (Verifying Kahn's cycle detection).
3. Pydantic Strict Mode Coercion Exploits.
"""

from __future__ import annotations

import benchmarks.protocols  # Ensures sys.path is configured for local libs

from benchmarks.protocols.phase4_redteam.timeout_bombs import (
    SMTTimeoutBombGenerator,
    TimeoutStressResult,
)
from benchmarks.protocols.phase4_redteam.cycle_injector import (
    CyclicGraphInjector,
    CycleInjectionResult,
)
from benchmarks.protocols.phase4_redteam.coercion_fuzzer import (
    TypeCoercionExploitFuzzer,
    CoercionExploitResult,
)
from benchmarks.protocols.phase4_redteam.runner import (
    WhiteBoxRedTeamRunner,
    Phase4Metrics,
)

__all__ = [
    "SMTTimeoutBombGenerator",
    "TimeoutStressResult",
    "CyclicGraphInjector",
    "CycleInjectionResult",
    "TypeCoercionExploitFuzzer",
    "CoercionExploitResult",
    "WhiteBoxRedTeamRunner",
    "Phase4Metrics",
]
