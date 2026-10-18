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

import hashlib
import hmac
import math
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Annotated,
    Any,
    Dict,
    Generic,
    Literal,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    get_args,
    get_origin,
)

from pydantic import BaseModel, Field, TypeAdapter, ValidationError
from pydantic.fields import FieldInfo

from jurisast_core.exceptions import DeclassificationDeniedError
from jurisast_core.labels import SecurityLabel
from jurisast_core.taint import TaintedValue


class AttestationToken(BaseModel):
    """
    Cryptographic attestation token certifying a human-in-the-loop review.

    Used when declassifying unstructured free text (where Shannon mutual information
    is theoretically unbounded) by binding the downgrade to a verified human review.
    """

    token_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this attestation token.",
    )
    approver_id: str = Field(
        description="Identity of the reviewing compliance officer or auditor.",
    )
    target_label: SecurityLabel = Field(
        description="The downgraded security label approved for this content.",
    )
    content_hash: str = Field(
        description="SHA-256 hash of the human-reviewed free-text content.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the human approval.",
    )
    signature: str = Field(
        description="HMAC-SHA256 signature validating token authenticity and integrity.",
    )

    model_config = {"frozen": True}


class HumanDeclassificationAuthority:
    """
    Cryptographic authority for certifying free-text declassification.

    Because open-ended natural language strings have unbounded Shannon capacity,
    mathematical non-interference cannot prove that secrets are not encoded.
    Therefore, declassification of unstructured free text must be anchored in
    human accountability via cryptographic attestation.
    """

    @staticmethod
    def generate_content_hash(content: str) -> str:
        """Compute the SHA-256 hash of normalized text."""
        return hashlib.sha256(content.strip().encode("utf-8")).hexdigest()

    @staticmethod
    def create_attestation(
        content: str,
        approver_id: str,
        secret_key: str,
        target_label: SecurityLabel,
    ) -> AttestationToken:
        """
        Create a cryptographically signed attestation token for approved text.
        """
        content_hash = HumanDeclassificationAuthority.generate_content_hash(content)
        ts = datetime.now(timezone.utc)
        payload = f"{approver_id}:{content_hash}:{target_label.to_tuple()}:{ts.isoformat()}"
        signature = hmac.new(
            secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return AttestationToken(
            approver_id=approver_id,
            target_label=target_label,
            content_hash=content_hash,
            timestamp=ts,
            signature=signature,
        )

    @staticmethod
    def verify_attestation(
        token: AttestationToken,
        content: str,
        secret_key: str,
        max_age_seconds: Optional[float] = None,
    ) -> bool:
        """
        Verify the signature, content integrity, and freshness of an attestation token.
        """
        content_hash = HumanDeclassificationAuthority.generate_content_hash(content)
        if content_hash != token.content_hash:
            return False

        if max_age_seconds is not None:
            age = (datetime.now(timezone.utc) - token.timestamp).total_seconds()
            if age > max_age_seconds:
                return False

        payload = f"{token.approver_id}:{content_hash}:{token.target_label.to_tuple()}:{token.timestamp.isoformat()}"
        expected_sig = hmac.new(
            secret_key.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(token.signature, expected_sig)


SlotModelT = TypeVar("SlotModelT", bound=BaseModel)


class SlottedTemplate(Generic[SlotModelT]):
    """
    Template-based constrained synthesis engine.

    Enables natural language summaries while mathematically bounding Shannon
    mutual information capacity by restricting variable content to strictly typed,
    finite-cardinality schema slots (Enums, Literals, bounded integers).

    Total entropy satisfies subadditivity:
        H(Output) <= sum(log2(|Slot_i|)) < infinity
    """

    def __init__(self, template: str, slot_model: Type[SlotModelT]) -> None:
        self.template = template
        self.slot_model = slot_model

    def compute_max_bits(self) -> float:
        """Calculate the Shannon entropy bound of the slot model."""
        return DeclassificationBoundary.compute_max_bits(self.slot_model)

    def render(self, slots: SlotModelT | Dict[str, Any]) -> str:
        """Validate slots under Pydantic strict mode and render the template."""
        if isinstance(slots, dict):
            validated = self.slot_model.model_validate(slots, strict=True)
        else:
            validated = self.slot_model.model_validate(slots.model_dump(), strict=True)

        values_dict = {}
        for k, v in validated.model_dump().items():
            if isinstance(v, Enum):
                values_dict[k] = v.value
            else:
                values_dict[k] = v
        return self.template.format(**values_dict)


class CompartmentScrubber:
    """
    Deterministic pattern scrubber for categorical compartments.

    Redacts sensitive patterns (credit cards, SSNs, emails, phones) in order
    of specificity and removes the corresponding compartment tags from the data's SecurityLabel.
    """

    DEFAULT_PATTERNS: Dict[str, str] = {
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "phone": r"(?:\+?[0-9]{1,3}[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b",
    }

    @staticmethod
    def scrub(
        text: str,
        target_compartments: Optional[Set[str]] = None,
        replacement: str = "[REDACTED]",
    ) -> Tuple[str, Set[str]]:
        """
        Scrub matching patterns from text and return (scrubbed_text, removed_compartments).
        """
        scrubbed = text
        removed: Set[str] = set()
        for comp_name, pat in CompartmentScrubber.DEFAULT_PATTERNS.items():
            if target_compartments is None or comp_name in target_compartments:
                if re.search(pat, scrubbed):
                    scrubbed = re.sub(pat, replacement, scrubbed)
                    removed.add(comp_name)
        return scrubbed, removed


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

        # SlottedTemplate check
        if isinstance(output_type, type) and issubclass(output_type, SlottedTemplate):
            if hasattr(output_type, "slot_model"):
                return DeclassificationBoundary.compute_max_bits(output_type.slot_model)
        if isinstance(output_type, SlottedTemplate):
            return output_type.compute_max_bits()

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
        if isinstance(output_type, SlottedTemplate):
            if isinstance(value, str):
                return
            if isinstance(value, dict):
                allowed_keys = set(output_type.slot_model.model_fields.keys())
                extra_keys = set(value.keys()) - allowed_keys
                if extra_keys:
                    raise DeclassificationDeniedError(
                        f"Template slot dictionary contains unauthorized extra fields: {extra_keys}"
                    )
            try:
                TypeAdapter(output_type.slot_model).validate_python(value, strict=True)
                return
            except ValidationError as e:
                raise DeclassificationDeniedError(
                    f"Template slot value failed strict validation: {e}"
                ) from e

        if isinstance(output_type, type) and issubclass(output_type, BaseModel):
            if isinstance(value, dict):
                allowed_keys = set(output_type.model_fields.keys())
                extra_keys = set(value.keys()) - allowed_keys
                if extra_keys:
                    raise DeclassificationDeniedError(
                        f"Model dictionary contains unauthorized extra fields: {extra_keys}"
                    )

        try:
            adapter = TypeAdapter(output_type)
            adapter.validate_python(value, strict=True)
        except ValidationError as e:
            raise DeclassificationDeniedError(
                f"Declassified value failed strict type validation for {output_type}: {e}"
            ) from e

    @staticmethod
    def validate_human_attestation(
        token: AttestationToken,
        content: str,
        secret_key: str,
        max_age_seconds: Optional[float] = None,
    ) -> bool:
        """
        Verify human attestation token for free-text declassification.

        Raises:
            DeclassificationDeniedError: If attestation is invalid or content has been tampered with.
        """
        if not HumanDeclassificationAuthority.verify_attestation(
            token=token,
            content=content,
            secret_key=secret_key,
            max_age_seconds=max_age_seconds,
        ):
            raise DeclassificationDeniedError(
                f"Human attestation failed for free text: invalid signature or content mismatch (hash={token.content_hash})"
            )
        return True

    @classmethod
    def declassify_free_text(
        cls,
        tainted_value: TaintedValue[Any],
        text_content: str,
        attestation_token: AttestationToken,
        secret_key: str,
        agent_id: str,
        tool_name: str,
        max_age_seconds: Optional[float] = None,
    ) -> TaintedValue[str]:
        """
        Perform verified declassification on free-text content via cryptographic human attestation.
        """
        cls.validate_human_attestation(
            token=attestation_token,
            content=text_content,
            secret_key=secret_key,
            max_age_seconds=max_age_seconds,
        )
        return tainted_value.declassify(
            target_label=attestation_token.target_label,
            declassified_value=text_content,
            tool=tool_name,
            agent_id=agent_id,
            max_bits=float("inf"),
            details=f"Human-attested free-text declassification approved by {attestation_token.approver_id}",
        )

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
