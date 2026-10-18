"""
Pydantic Type Coercion Exploit Suite for Phase 4 Red-Teaming.

Evaluates whether white-box adversaries can bypass security boundaries by exploiting
loose type coercion (e.g. passing strings as booleans, floating-point lossy truncation,
or duck-typed classes implementing __bool__ / __int__).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional, Type
from pydantic import BaseModel, Field

from jurisast_core.declassifier import DeclassificationBoundary
from jurisast_core.exceptions import DeclassificationDeniedError


@dataclass
class CoercionExploitResult:
    """Outcome of a Pydantic strict coercion exploit attempt."""

    exploit_id: str
    target_type_name: str
    exploit_technique: str
    injected_payload_repr: str
    rejected: bool  # True if DeclassificationDeniedError / ValidationError was raised
    error_message: Optional[str] = None


# Mock classes for duck-typing bypass attempts
class DuckTypedBool:
    """Adversarial object attempting to masquerade as boolean via __bool__."""
    def __init__(self, value: bool = True) -> None:
        self.value = value
    def __bool__(self) -> bool:
        return self.value
    def __repr__(self) -> str:
        return f"DuckTypedBool({self.value})"


class DuckTypedInt:
    """Adversarial object attempting to masquerade as integer via __int__."""
    def __init__(self, value: int = 42) -> None:
        self.value = value
    def __int__(self) -> int:
        return self.value
    def __repr__(self) -> str:
        return f"DuckTypedInt({self.value})"


class SampleAuditDecision(str, Enum):
    APPROVED = "APPROVED"
    FLAGGED = "FLAGGED"


class SampleAuditRecord(BaseModel):
    decision: SampleAuditDecision
    risk_score: Annotated[int, Field(ge=0, le=100)]


class TypeCoercionExploitFuzzer:
    """
    Fuzzes runtime validation boundaries with subtle type coercion exploits.
    """

    @classmethod
    def generate_pilot_exploits(cls) -> List[Tuple[str, str, Any, Any]]:
        """
        Returns list of (exploit_id, description, target_type, adversarial_payload).
        """
        BoundedInt = Annotated[int, Field(ge=0, le=100)]

        exploits = [
            # 1. String to Bool loose coercion
            (
                "COERCE_001_STR_TRUE_TO_BOOL",
                "String 'true' passed to bool channel (testing strict rejection of string-to-bool)",
                bool,
                "true",
            ),
            (
                "COERCE_002_STR_ONE_TO_BOOL",
                "String '1' passed to bool channel",
                bool,
                "1",
            ),
            (
                "COERCE_003_INT_ZERO_TO_BOOL",
                "Integer 0 passed to bool channel (testing strict rejection of int-to-bool)",
                bool,
                0,
            ),
            (
                "COERCE_004_DUCK_TYPED_BOOL",
                "DuckTypedBool object attempting __bool__ bypass",
                bool,
                DuckTypedBool(True),
            ),
            # 2. String & Float to Int loose coercion
            (
                "COERCE_005_STR_NUM_TO_INT",
                "String '42' passed to bounded integer channel",
                BoundedInt,
                "42",
            ),
            (
                "COERCE_006_FLOAT_TRUNCATE_TO_INT",
                "Float 42.999 passed to bounded integer channel (lossy truncation attempt)",
                BoundedInt,
                42.999,
            ),
            (
                "COERCE_007_DUCK_TYPED_INT",
                "DuckTypedInt object attempting __int__ bypass",
                BoundedInt,
                DuckTypedInt(42),
            ),
            # 3. Enum String & Int loose coercion
            (
                "COERCE_008_STR_ENUM_CASING",
                "Lowercase string 'approved' passed to SampleAuditDecision Enum",
                SampleAuditDecision,
                "approved",
            ),
            (
                "COERCE_009_INT_TO_ENUM",
                "Integer 0 passed to SampleAuditDecision Enum",
                SampleAuditDecision,
                0,
            ),
            # 4. Structured Model Coercion & Extra Key Smuggling
            (
                "COERCE_010_MODEL_STR_INT",
                "Passing string risk_score '50' into SampleAuditRecord",
                SampleAuditRecord,
                {"decision": SampleAuditDecision.APPROVED, "risk_score": "50"},
            ),
            (
                "COERCE_011_MODEL_EXTRA_SECRET_FIELD",
                "Passing unmodeled secret field into SampleAuditRecord dict",
                SampleAuditRecord,
                {"decision": SampleAuditDecision.APPROVED, "risk_score": 50, "exfiltrated_key": "LEAKED_SECRET_99"},
            ),
            (
                "COERCE_012_LIST_TO_SCALAR",
                "Passing single-element list [True] to scalar bool channel",
                bool,
                [True],
            ),
        ]
        return exploits

    @classmethod
    def evaluate_exploit(
        cls,
        exploit_id: str,
        description: str,
        target_type: Any,
        payload: Any,
    ) -> CoercionExploitResult:
        """Evaluate an exploit against DeclassificationBoundary runtime validation."""
        rejected = False
        error_msg = None

        try:
            DeclassificationBoundary.validate_runtime_value(value=payload, output_type=target_type)
        except (DeclassificationDeniedError, Exception) as exc:
            rejected = True
            error_msg = str(exc)

        type_name = getattr(target_type, "__name__", str(target_type))

        return CoercionExploitResult(
            exploit_id=exploit_id,
            target_type_name=type_name,
            exploit_technique=description,
            injected_payload_repr=repr(payload),
            rejected=rejected,
            error_message=error_msg,
        )
