"""
JurisAST Configuration Management.

Provides a centralized configuration model for the JurisAST engine,
including solver timeouts, enforcement modes, and audit settings.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SolverConfig(BaseModel):
    """Configuration for the Z3 SMT solver engine."""

    timeout_ms: int = Field(
        default=50,
        ge=1,
        le=10000,
        description=(
            "Maximum time in milliseconds for Z3 to solve a single verification query. "
            "Default 50ms targets <20ms typical solve time. Fail-closed on timeout."
        ),
    )
    use_incremental: bool = Field(
        default=True,
        description=(
            "Use assumption-based incremental solving for better performance. "
            "Preserves learned lemmas across checks. Disable only for debugging."
        ),
    )
    extract_unsat_core: bool = Field(
        default=True,
        description=(
            "When a violation is detected, extract the minimal unsat core "
            "to identify exactly which policy constraints were violated."
        ),
    )


class AuditConfig(BaseModel):
    """Configuration for audit logging and provenance tracking."""

    enabled: bool = Field(
        default=True,
        description="Enable/disable audit logging of verification results.",
    )
    log_safe_executions: bool = Field(
        default=False,
        description=(
            "Whether to log SAFE verification results in addition to violations. "
            "Useful for compliance audits but increases log volume."
        ),
    )
    retain_z3_models: bool = Field(
        default=False,
        description=(
            "Retain Z3 models (satisfying assignments) for safe executions. "
            "Memory-intensive; enable only for debugging."
        ),
    )
    max_provenance_depth: int = Field(
        default=100,
        ge=1,
        description="Maximum provenance chain length before truncation warning.",
    )


class JurisASTConfig(BaseModel):
    """
    Root configuration for the JurisAST engine.

    Controls the enforcement mode, solver behavior, and audit settings.
    Thread this through agent dependencies via RunContext.

    Enforcement Modes:
        - "enforce": Block violating tool calls (raise TaintViolationError)
        - "audit": Log violations but allow execution (for shadow deployment)
        - "permissive": Log only, no blocking (for development/testing)
    """

    mode: Literal["enforce", "audit", "permissive"] = Field(
        default="enforce",
        description=(
            "Enforcement mode. 'enforce' blocks violations, 'audit' logs only, "
            "'permissive' is for development."
        ),
    )
    solver: SolverConfig = Field(
        default_factory=SolverConfig,
        description="Z3 solver configuration.",
    )
    audit: AuditConfig = Field(
        default_factory=AuditConfig,
        description="Audit logging configuration.",
    )
    fail_closed: bool = Field(
        default=True,
        description=(
            "If True, treat solver timeouts and errors as violations (fail-closed). "
            "If False, allow execution on solver errors (fail-open). "
            "MUST be True for production deployments."
        ),
    )
    default_untainted_label_classification: str = Field(
        default="PUBLIC",
        description=(
            "Default classification for data that does not match any tainted source. "
            "Must be a valid Classification enum member name."
        ),
    )
    default_untainted_label_jurisdiction: str = Field(
        default="INTERNAL",
        description=(
            "Default jurisdiction for data that does not match any tainted source. "
            "Must be a valid Jurisdiction enum member name."
        ),
    )

    model_config = {"frozen": False}  # Config is mutable for runtime updates
