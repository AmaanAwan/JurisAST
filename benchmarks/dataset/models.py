"""
Data models for the JurisAST Benchmark dataset.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

from jurisast_core.ast_ir import ExecutionGraph


class TraceCategory(str, Enum):
    """Classification category for an execution trace."""
    COMPLIANT_SOVEREIGN = "COMPLIANT_SOVEREIGN"
    CROSS_BORDER_EXFILTRATION = "CROSS_BORDER_EXFILTRATION"
    SPECIAL_CATEGORY_EXPOSURE = "SPECIAL_CATEGORY_EXPOSURE"
    MULTI_HOP_LAUNDERING = "MULTI_HOP_LAUNDERING"
    CONTROLLED_DECLASSIFICATION = "CONTROLLED_DECLASSIFICATION"
    INJECAGENT_ATTACK = "INJECAGENT_ATTACK"
    BIPIA_ATTACK = "BIPIA_ATTACK"


class GroundTruthStatus(str, Enum):
    """Expected outcome from a formally sound security firewall."""
    SAFE = "SAFE"
    VIOLATION = "VIOLATION"


class TraceGroundTruth(BaseModel):
    """Mathematically verified ground truth for a trace."""
    status: GroundTruthStatus
    category: TraceCategory
    violated_rules: List[str] = Field(default_factory=list)
    description: str
    expected_blocked_nodes: List[str] = Field(default_factory=list)


class TraceSpec(BaseModel):
    """Specification defining trace parameters."""
    trace_id: str
    category: TraceCategory
    num_agents: int = 1
    num_tool_calls: int = 2
    has_cross_border_flow: bool = False
    has_pii: bool = False
    has_declassification: bool = False
    is_adversarial: bool = False
    adversarial_technique: Optional[str] = None


class BenchmarkTrace(BaseModel):
    """A benchmark item comprising graph, specification, and ground truth."""
    spec: TraceSpec
    graph: ExecutionGraph
    ground_truth: TraceGroundTruth
