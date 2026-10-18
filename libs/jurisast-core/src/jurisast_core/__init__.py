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
    TaintedRecord,
    TaintedValue,
    TaintRegistry,
)
from jurisast_core.ast_ir import (
    ASTNode,
    AgentHandoffNode,
    ChatOutputSinkNode,
    DataSourceNode,
    DeclassifyNode,
    ExecutionGraph,
    ExecutionGraphBuilder,
    HumanAttestedDeclassifyNode,
    ProjectionNode,
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
from jurisast_core.declassifier import (
    AttestationToken,
    CompartmentScrubber,
    DeclassificationBoundary,
    HumanDeclassificationAuthority,
    SlottedTemplate,
)

__all__ = [
    # Labels
    "Classification",
    "Jurisdiction",
    "SecurityLabel",
    "label_from_metadata",
    # Taint
    "ProvenanceRecord",
    "TaintedRecord",
    "TaintedValue",
    "TaintRegistry",
    # AST IR
    "ASTNode",
    "DataSourceNode",
    "TransformNode",
    "ProjectionNode",
    "SinkNode",
    "ChatOutputSinkNode",
    "DeclassifyNode",
    "HumanAttestedDeclassifyNode",
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
    "AttestationToken",
    "CompartmentScrubber",
    "DeclassificationBoundary",
    "HumanDeclassificationAuthority",
    "SlottedTemplate",
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
