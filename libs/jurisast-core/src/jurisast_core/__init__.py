"""
JurisAST Core — Information Flow Control Engine

Provides the foundational primitives for formally verified information flow control:
- Security label lattice (jurisdiction × classification × compartments)
- Taint containers with provenance tracking
- AST intermediate representation for execution graphs
- Z3 SMT solver interface for non-interference proofs
- Regulatory policy definitions and compilation
- Symbolic declassification with information bounding
"""

from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    label_from_metadata,
)
from jurisast_core.taint import (
    ProvenanceRecord,
    TaintedValue,
)
from jurisast_core.ast_ir import (
    ASTNode,
    AgentHandoffNode,
    DataSourceNode,
    DeclassifyNode,
    ExecutionGraph,
    ExecutionGraphBuilder,
    SinkNode,
    TransformNode,
)
from jurisast_core.solver import (
    VerificationResult,
    Z3SolverEngine,
)
from jurisast_core.exceptions import (
    ASTConstructionError,
    DeclassificationDeniedError,
    JurisASTError,
    PolicyCompilationError,
    SolverTimeoutError,
    TaintViolationError,
)
from jurisast_core.config import JurisASTConfig
from jurisast_core.policies import (
    ConstraintAction,
    FlowConstraint,
    PolicySet,
)
from jurisast_core.declassifier import DeclassificationBoundary

__all__ = [
    # Labels
    "Classification",
    "Jurisdiction",
    "SecurityLabel",
    "label_from_metadata",
    # Taint
    "ProvenanceRecord",
    "TaintedValue",
    # AST IR
    "ASTNode",
    "DataSourceNode",
    "TransformNode",
    "SinkNode",
    "DeclassifyNode",
    "AgentHandoffNode",
    "ExecutionGraph",
    "ExecutionGraphBuilder",
    # Solver
    "Z3SolverEngine",
    "VerificationResult",
    # Policies
    "ConstraintAction",
    "FlowConstraint",
    "PolicySet",
    # Declassification
    "DeclassificationBoundary",
    # Exceptions
    "JurisASTError",
    "TaintViolationError",
    "DeclassificationDeniedError",
    "PolicyCompilationError",
    "SolverTimeoutError",
    "ASTConstructionError",
    # Config
    "JurisASTConfig",
]

__version__ = "0.1.0"
