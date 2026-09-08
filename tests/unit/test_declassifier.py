"""
Unit Tests for Symbolic Declassification Engine (declassifier.py).

Tests Shannon mutual information entropy bounds, type cardinality calculations,
strict runtime validation, and secure label downgrading.
"""

from __future__ import annotations

import math
from enum import Enum
from typing import Annotated, Literal

import pytest
from pydantic import BaseModel, Field

from jurisast_core.declassifier import DeclassificationBoundary
from jurisast_core.exceptions import DeclassificationDeniedError
from jurisast_core.labels import (
    LABEL_EU_PII,
    LABEL_PUBLIC,
    Classification,
    Jurisdiction,
    SecurityLabel,
)
from jurisast_core.taint import TaintedValue


class SentimentEnum(Enum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NEUTRAL = "neutral"
    MIXED = "mixed"


class BinaryDecision(Enum):
    ALLOW = 1
    DENY = 0


class SimpleRatingModel(BaseModel):
    is_valid: bool
    rating: Literal["low", "medium", "high", "critical"]


class NestedEvaluationModel(BaseModel):
    decision: BinaryDecision
    sub_rating: SimpleRatingModel


class TestShannonEntropyCalculations:
    """Tests for DeclassificationBoundary.compute_max_bits."""

    def test_bool_is_one_bit(self):
        assert DeclassificationBoundary.compute_max_bits(bool) == 1.0

    def test_enum_bits(self):
        # 2 members: log2(2) = 1.0
        assert DeclassificationBoundary.compute_max_bits(BinaryDecision) == 1.0
        # 4 members: log2(4) = 2.0
        assert DeclassificationBoundary.compute_max_bits(SentimentEnum) == 2.0

    def test_literal_bits(self):
        # 4 choices: log2(4) = 2.0
        lit_type = Literal["a", "b", "c", "d"]
        assert DeclassificationBoundary.compute_max_bits(lit_type) == 2.0

        # 3 choices: log2(3) ≈ 1.58496
        lit_3 = Literal["red", "green", "blue"]
        assert math.isclose(
            DeclassificationBoundary.compute_max_bits(lit_3),
            math.log2(3),
            rel_tol=1e-5,
        )

    def test_bounded_integer_range(self):
        # [0, 15] has 16 possible values -> log2(16) = 4.0 bits
        range_16 = Annotated[int, Field(ge=0, le=15)]
        assert DeclassificationBoundary.compute_max_bits(range_16) == 4.0

        # [1, 1] has 1 value -> log2(1) = 0.0 bits
        range_1 = Annotated[int, Field(ge=1, le=1)]
        assert DeclassificationBoundary.compute_max_bits(range_1) == 0.0

        # [0, 255] has 256 values -> 8.0 bits (1 byte)
        range_256 = Annotated[int, Field(ge=0, le=255)]
        assert DeclassificationBoundary.compute_max_bits(range_256) == 8.0

    def test_structured_model_bits(self):
        # bool (1.0) + 4-literal (2.0) = 3.0 bits
        bits = DeclassificationBoundary.compute_max_bits(SimpleRatingModel)
        assert bits == 3.0

    def test_nested_model_bits(self):
        # BinaryDecision (1.0) + SimpleRatingModel (3.0) = 4.0 bits
        bits = DeclassificationBoundary.compute_max_bits(NestedEvaluationModel)
        assert bits == 4.0

    def test_reject_unbounded_str(self):
        with pytest.raises(ValueError, match="is unbounded"):
            DeclassificationBoundary.compute_max_bits(str)

    def test_reject_unbounded_float(self):
        with pytest.raises(ValueError, match="is unbounded"):
            DeclassificationBoundary.compute_max_bits(float)

    def test_reject_unbounded_int(self):
        with pytest.raises(ValueError, match="is unbounded"):
            DeclassificationBoundary.compute_max_bits(int)

    def test_reject_unbounded_dict(self):
        with pytest.raises(ValueError, match="is unbounded"):
            DeclassificationBoundary.compute_max_bits(dict)

    def test_reject_unbounded_list(self):
        with pytest.raises(ValueError, match="is unbounded"):
            DeclassificationBoundary.compute_max_bits(list)


class TestDeclassificationValidation:
    """Tests for validate_declassification and validate_runtime_value."""

    def test_validate_declassification_budget(self):
        # SentimentEnum needs 2.0 bits
        assert DeclassificationBoundary.validate_declassification(SentimentEnum, 2.0) is True
        assert DeclassificationBoundary.validate_declassification(SentimentEnum, 3.0) is True
        assert DeclassificationBoundary.validate_declassification(SentimentEnum, 1.5) is False

    def test_runtime_value_validation_success(self):
        DeclassificationBoundary.validate_runtime_value(True, bool)
        DeclassificationBoundary.validate_runtime_value(SentimentEnum.POSITIVE, SentimentEnum)
        DeclassificationBoundary.validate_runtime_value(
            SimpleRatingModel(is_valid=True, rating="critical"),
            SimpleRatingModel,
        )

    def test_runtime_value_validation_failure(self):
        with pytest.raises(DeclassificationDeniedError):
            # String instead of bool
            DeclassificationBoundary.validate_runtime_value("not_a_bool", bool)

        with pytest.raises(DeclassificationDeniedError):
            # Invalid literal choice
            DeclassificationBoundary.validate_runtime_value("invalid_choice", Literal["a", "b"])


class TestDeclassifyValueMethod:
    """Tests for DeclassificationBoundary.declassify_value."""

    def test_successful_declassification(self):
        raw_data = "EU Customer SSN: 123-45-6789"
        tainted = TaintedValue.create(
            value=raw_data,
            label=LABEL_EU_PII,
            source_tool="db_fetch",
            agent_id="agent_1",
        )

        declassified = DeclassificationBoundary.declassify_value(
            tainted_value=tainted,
            output_value=True,
            output_type=bool,
            output_label=LABEL_PUBLIC,
            max_allowed_bits=1.0,
            agent_id="agent_1",
            tool_name="is_account_active",
        )

        assert declassified.value is True
        assert declassified.label == LABEL_PUBLIC
        assert len(declassified.provenance) == 2
        assert declassified.provenance[-1].operation == "declassify"
        assert declassified.provenance[-1].label_before == LABEL_EU_PII
        assert declassified.provenance[-1].label_after == LABEL_PUBLIC

    def test_budget_exceeded_raises_error(self):
        tainted = TaintedValue.create(
            value="secret",
            label=LABEL_EU_PII,
            source_tool="db",
            agent_id="a1",
        )
        with pytest.raises(DeclassificationDeniedError, match="exceeds the allowed budget"):
            DeclassificationBoundary.declassify_value(
                tainted_value=tainted,
                output_value=SentimentEnum.POSITIVE,
                output_type=SentimentEnum,  # Requires 2.0 bits
                output_label=LABEL_PUBLIC,
                max_allowed_bits=1.0,  # Only allows 1.0 bit
                agent_id="a1",
                tool_name="sentiment_tool",
            )

    def test_unbounded_type_raises_error(self):
        tainted = TaintedValue.create(
            value="secret",
            label=LABEL_EU_PII,
            source_tool="db",
            agent_id="a1",
        )
        with pytest.raises(DeclassificationDeniedError, match="is unbounded"):
            DeclassificationBoundary.declassify_value(
                tainted_value=tainted,
                output_value="summary text",
                output_type=str,
                output_label=LABEL_PUBLIC,
                max_allowed_bits=100.0,
                agent_id="a1",
                tool_name="summarizer",
            )
