"""
Symbolic Declassification Engine for JurisAST.

Enforces mathematical information-theoretic limits on declassified data
using Shannon mutual information bounds and Pydantic strict mode validation.

Mathematical Principle:
    Declassification downgrades a security label (e.g., EU/SENSITIVE_PII → PUBLIC).
    To mathematically prove that this downgrade cannot exfiltrate arbitrary secrets,
    the output channel must have a strictly bounded Shannon information capacity:
        I(X; Y) ≤ H(Y) ≤ log₂(cardinality(Y))

    For example:
        - Boolean output: H(Y) ≤ log₂(2) = 1.0 bit
        - 4-way Enum: H(Y) ≤ log₂(4) = 2.0 bits
        - Int in [0, 15]: H(Y) ≤ log₂(16) = 4.0 bits
        - Arbitrary string: H(Y) = ∞ (UNBOUNDED — REJECTED)
"""

from __future__ import annotations

import math
from enum import Enum
from typing import (
    Annotated,
    Any,
    Dict,
    Literal,
    Optional,
    Type,
    get_args,
    get_origin,
)

from pydantic import BaseModel, TypeAdapter, ValidationError
from pydantic.fields import FieldInfo

from jurisast_core.exceptions import DeclassificationDeniedError
from jurisast_core.labels import SecurityLabel
from jurisast_core.taint import TaintedValue


class DeclassificationBoundary:
    """
    Computes and verifies Shannon entropy bounds for declassification output types.

    Ensures that only strictly bounded types can be used in @declassifier tools,
    preventing prompt injection or exfiltration attacks from leaking arbitrary secrets.
    """

    @staticmethod
    def compute_max_bits(output_type: Any) -> float:
        """
        Calculate the maximum Shannon information entropy in bits for a given type.

        Supported Bounded Types:
            - bool: exactly 1.0 bit
            - Enum subclasses: log₂(number of enum members)
            - Literal[...]: log₂(number of unique literal arguments)
            - Annotated[int, Field(ge=A, le=B)]: log₂(B - A + 1) bits
            - BaseModel subclasses: sum of bits of all fields (subadditivity of entropy)

        Unbounded Types (REJECTED with ValueError):
            - str: unbounded character combinations
            - float: continuous / high precision
            - dict: arbitrary keys and values
            - list: arbitrary length collections
            - unconstrained int: arbitrarily large integers

        Args:
            output_type: The Python type annotation to evaluate.

        Returns:
            The maximum information capacity in bits (float ≥ 0).

        Raises:
            ValueError: If the type has unbounded information capacity.
        """
        if output_type is bool:
            return 1.0

        # Enum check
        if isinstance(output_type, type) and issubclass(output_type, Enum):
            num_members = len(output_type)
            if num_members == 0:
                return 0.0
            return math.log2(num_members)

        # Literal check
        origin = get_origin(output_type)
        if origin is Literal:
            args = get_args(output_type)
            if not args:
                return 0.0
            return math.log2(len(set(args)))

        # Annotated check (e.g., Annotated[int, Field(ge=0, le=100)])
        if origin is Annotated:
            base_type, *metadata = get_args(output_type)
            if base_type is int:
                min_val = None
                max_val = None

                meta_list = []
                for meta in metadata:
                    if isinstance(meta, FieldInfo):
                        meta_list.extend(meta.metadata)
                    else:
                        meta_list.append(meta)

                for item in meta_list:
                    if hasattr(item, "ge") and getattr(item, "ge") is not None:
                        min_val = getattr(item, "ge")
                    elif hasattr(item, "gt") and getattr(item, "gt") is not None:
                        min_val = getattr(item, "gt") + 1
                    if hasattr(item, "le") and getattr(item, "le") is not None:
                        max_val = getattr(item, "le")
                    elif hasattr(item, "lt") and getattr(item, "lt") is not None:
                        max_val = getattr(item, "lt") - 1

                if min_val is not None and max_val is not None:
                    if max_val < min_val:
                        raise ValueError(f"Invalid integer range: ge={min_val} > le={max_val}")
                    cardinality = int(max_val - min_val + 1)
                    if cardinality <= 0:
                        return 0.0
                    return math.log2(cardinality)

                raise ValueError(
                    f"Annotated integer '{output_type}' lacks bounded range (must specify both ge and le)."
                )

            # Recurse on base type if not int
            return DeclassificationBoundary.compute_max_bits(base_type)

        # Structured BaseModel check
        if isinstance(output_type, type) and issubclass(output_type, BaseModel):
            total_bits = 0.0
            for field_name, field_info in output_type.model_fields.items():
                field_annotation = field_info.annotation
                if field_annotation is None:
                    raise ValueError(
                        f"Field '{field_name}' in model '{output_type.__name__}' lacks type annotation."
                    )
                # Check if field_info has metadata constraints (e.g. Field(ge=..., le=...))
                if getattr(field_info, "metadata", None):
                    effective_type = Annotated[(field_annotation, *field_info.metadata)]
                    total_bits += DeclassificationBoundary.compute_max_bits(effective_type)
                else:
                    total_bits += DeclassificationBoundary.compute_max_bits(field_annotation)
            return total_bits

        # Explicit rejection of unbounded types
        if output_type in (str, float, dict, list, set, int):
            raise ValueError(
                f"Type '{output_type.__name__}' is unbounded and cannot be declassified without "
                f"structural constraints (e.g., Enum, Literal, or bounded Annotated[int, Field(ge=..., le=...)])."
            )

        raise ValueError(
            f"Unsupported declassification type: {output_type}. "
            "Must be bool, Enum, Literal, bounded Annotated[int], or bounded BaseModel."
        )

    @staticmethod
    def validate_declassification(
        output_type: Any,
        max_allowed_bits: float,
    ) -> bool:
        """
        Verify that an output type's entropy bound does not exceed the allowed budget.

        Args:
            output_type: The type annotation of the declassification output.
            max_allowed_bits: Maximum bits of information permitted.

        Returns:
            True if compute_max_bits(output_type) <= max_allowed_bits.

        Raises:
            ValueError: If output_type is unbounded.
        """
        actual_bits = DeclassificationBoundary.compute_max_bits(output_type)
        return actual_bits <= max_allowed_bits

    @staticmethod
    def validate_runtime_value(value: Any, output_type: Any) -> None:
        """
        Validate that a runtime result conforms strictly to the bounded output type.

        Uses Pydantic strict mode validation to prevent implicit type coercions.

        Args:
            value: The actual value produced by the tool.
            output_type: The declared bounded output type.

        Raises:
            DeclassificationDeniedError: If validation fails.
        """
        try:
            adapter = TypeAdapter(output_type)
            adapter.validate_python(value, strict=True)
        except ValidationError as e:
            raise DeclassificationDeniedError(
                f"Declassified value failed strict type validation for {output_type}: {e}"
            ) from e

    @classmethod
    def declassify_value(
        cls,
        tainted_value: TaintedValue[Any],
        output_value: Any,
        output_type: Any,
        output_label: SecurityLabel,
        max_allowed_bits: float,
        agent_id: str,
        tool_name: str,
    ) -> TaintedValue[Any]:
        """
        Perform a verified declassification on a value.

        Validates:
            1. The output type has an information entropy capacity <= max_allowed_bits.
            2. The output value strictly conforms to output_type at runtime.
            3. Provenance is updated with the declassification operation.

        Args:
            tainted_value: The input tainted value being declassified.
            output_value: The new constrained value resulting from processing.
            output_type: The bounded type schema.
            output_label: The downgraded security label.
            max_allowed_bits: The maximum permitted Shannon information budget.
            agent_id: The ID of the agent performing declassification.
            tool_name: The name of the tool performing declassification.

        Returns:
            A new TaintedValue wrapping output_value with output_label and audit provenance.

        Raises:
            DeclassificationDeniedError: If entropy exceeds budget or value fails validation.
        """
        try:
            actual_bits = cls.compute_max_bits(output_type)
        except ValueError as e:
            raise DeclassificationDeniedError(f"Declassification denied: {e}") from e

        if actual_bits > max_allowed_bits:
            raise DeclassificationDeniedError(
                f"Declassification output requires {actual_bits:.2f} bits, "
                f"which exceeds the allowed budget of {max_allowed_bits:.2f} bits."
            )

        # Validate runtime value
        cls.validate_runtime_value(output_value, output_type)

        # Create new declassified TaintedValue with provenance chain
        return tainted_value.declassify(
            target_label=output_label,
            declassified_value=output_value,
            tool=tool_name,
            agent_id=agent_id,
            max_bits=actual_bits,
            details=f"Declassified to {output_type} ({actual_bits:.2f} bits <= {max_allowed_bits:.2f} budget)",
        )
