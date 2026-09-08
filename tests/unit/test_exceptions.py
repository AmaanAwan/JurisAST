"""
Unit tests for the JurisAST exception hierarchy.

Tests cover:
- Exception construction with structured metadata
- Inheritance hierarchy
- String representation
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"
))

from jurisast_core.exceptions import (
    JurisASTError,
    TaintViolationError,
    DeclassificationDeniedError,
    PolicyCompilationError,
    SolverTimeoutError,
    TaintRegistryError,
    ASTConstructionError,
)
from jurisast_core.labels import (
    LABEL_EU_PII,
    LABEL_PUBLIC,
)


class TestExceptionHierarchy:
    """Verify the inheritance chain."""

    def test_all_inherit_from_jurisast_error(self):
        assert issubclass(TaintViolationError, JurisASTError)
        assert issubclass(DeclassificationDeniedError, JurisASTError)
        assert issubclass(PolicyCompilationError, JurisASTError)
        assert issubclass(SolverTimeoutError, JurisASTError)
        assert issubclass(TaintRegistryError, JurisASTError)
        assert issubclass(ASTConstructionError, JurisASTError)

    def test_all_inherit_from_exception(self):
        assert issubclass(JurisASTError, Exception)

    def test_blanket_catch(self):
        with pytest.raises(JurisASTError):
            raise TaintViolationError("test")

        with pytest.raises(JurisASTError):
            raise SolverTimeoutError("test")


class TestTaintViolationError:
    """Tests for TaintViolationError."""

    def test_basic_construction(self):
        err = TaintViolationError("EU PII cannot flow to US sink")
        assert str(err).startswith("TaintViolationError:")

    def test_with_labels(self):
        err = TaintViolationError(
            "GDPR violation detected",
            data_label=LABEL_EU_PII,
            sink_label=LABEL_PUBLIC,
            policy_name="eu_pii_no_us_transfer",
        )
        assert err.data_label == LABEL_EU_PII
        assert err.sink_label == LABEL_PUBLIC
        assert err.policy_name == "eu_pii_no_us_transfer"

    def test_with_violated_constraints(self):
        err = TaintViolationError(
            "violation",
            violated_constraints=["constraint_1", "constraint_2"],
        )
        assert len(err.violated_constraints) == 2

    def test_str_includes_policy_name(self):
        err = TaintViolationError(
            "test",
            policy_name="GDPR_DATA_SOVEREIGNTY",
        )
        assert "GDPR_DATA_SOVEREIGNTY" in str(err)

    def test_metadata_attribute(self):
        err = TaintViolationError(
            "test",
            data_label=LABEL_EU_PII,
            policy_name="test_policy",
        )
        assert "data_label" in err.metadata
        assert "policy_name" in err.metadata


class TestDeclassificationDeniedError:

    def test_construction(self):
        err = DeclassificationDeniedError(
            "Output type exceeds information budget",
            source_label=LABEL_EU_PII,
            target_label=LABEL_PUBLIC,
            max_bits_allowed=1.0,
            actual_bits=8.0,
        )
        assert err.source_label == LABEL_EU_PII
        assert err.max_bits_allowed == 1.0
        assert err.actual_bits == 8.0


class TestPolicyCompilationError:

    def test_construction(self):
        err = PolicyCompilationError(
            "Contradictory constraints",
            policy_name="GDPR_v1",
            constraint_name="invalid_rule",
        )
        assert err.policy_name == "GDPR_v1"
        assert err.constraint_name == "invalid_rule"


class TestSolverTimeoutError:

    def test_construction(self):
        err = SolverTimeoutError(
            "Z3 exceeded 50ms timeout",
            timeout_ms=50,
            solver_result="unknown",
        )
        assert err.timeout_ms == 50
        assert err.solver_result == "unknown"
