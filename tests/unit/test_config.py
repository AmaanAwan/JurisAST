"""
Unit tests for JurisAST configuration (config.py).
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"
))

from jurisast_core.config import JurisASTConfig, SolverConfig, AuditConfig


class TestSolverConfig:

    def test_defaults(self):
        config = SolverConfig()
        assert config.timeout_ms == 50
        assert config.use_incremental is True
        assert config.extract_unsat_core is True

    def test_custom_timeout(self):
        config = SolverConfig(timeout_ms=100)
        assert config.timeout_ms == 100

    def test_timeout_min_bound(self):
        with pytest.raises(Exception):
            SolverConfig(timeout_ms=0)

    def test_timeout_max_bound(self):
        with pytest.raises(Exception):
            SolverConfig(timeout_ms=20000)


class TestAuditConfig:

    def test_defaults(self):
        config = AuditConfig()
        assert config.enabled is True
        assert config.log_safe_executions is False
        assert config.retain_z3_models is False
        assert config.max_provenance_depth == 100


class TestJurisASTConfig:

    def test_defaults(self):
        config = JurisASTConfig()
        assert config.mode == "enforce"
        assert config.fail_closed is True
        assert config.solver.timeout_ms == 50
        assert config.audit.enabled is True

    def test_audit_mode(self):
        config = JurisASTConfig(mode="audit")
        assert config.mode == "audit"

    def test_permissive_mode(self):
        config = JurisASTConfig(mode="permissive")
        assert config.mode == "permissive"

    def test_invalid_mode(self):
        with pytest.raises(Exception):
            JurisASTConfig(mode="invalid")  # type: ignore

    def test_nested_config_override(self):
        config = JurisASTConfig(
            solver=SolverConfig(timeout_ms=200, use_incremental=False),
            audit=AuditConfig(log_safe_executions=True),
        )
        assert config.solver.timeout_ms == 200
        assert config.solver.use_incremental is False
        assert config.audit.log_safe_executions is True
