"""
JurisAST Standardized Benchmarking Protocols.

Phase 1: AgentDojo Standardized Evaluation (Dynamic tool wrapping, state-based checkers)
Phase 2: TaintBench Memory Contamination (Vector & relational stores, semantic paraphrasing)
Phase 3: Information-Theoretic Declassification Channels Stress Testing
Phase 4: Adaptive White-Box Red-Teaming (SMT timeout bombs, cyclic graphs, type coercion)
"""

from __future__ import annotations

import os
import sys

# Ensure local libs are discoverable on sys.path
_CORE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"))
_PYDANTIC_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "libs", "jurisast-pydantic", "src"))
_POLICIES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "libs", "jurisast-policies", "src"))
_ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

for p in [_CORE_PATH, _PYDANTIC_PATH, _POLICIES_PATH, _ROOT_PATH]:
    if p not in sys.path:
        sys.path.insert(0, p)
