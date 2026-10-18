"""
Taint Container & Provenance Tracking for Information Flow Control.

Provides the core taint-tracking primitives:
- TaintedValue[T]: A generic container that wraps any value with a SecurityLabel
  and a complete provenance chain.
- ProvenanceRecord: An immutable audit trail entry recording every taint operation.
- TaintRegistry: A session-scoped registry of all tainted values, threaded through
  agent execution via Pydantic AI's RunContext.

Design Decisions:
    - TaintedValue is immutable (operations return new instances) to prevent
      accidental label corruption and enable safe concurrent access.
    - Provenance is append-only: every label transition is recorded for
      full audit trail reconstruction.
    - The registry uses string keys (tool_name + argument hash) rather than
      object identity, since LLM tool call arguments are always serialized strings.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import (
    Any,
    Dict,
    Generic,
    List,
    Optional,
    Sequence,
    TypeVar,
)

from pydantic import BaseModel, Field

from jurisast_core.labels import (
    LABEL_PUBLIC,
    Classification,
    Jurisdiction,
    SecurityLabel,
)
from jurisast_core.exceptions import TaintRegistryError

T = TypeVar("T")


class ProvenanceRecord(BaseModel):
    """
    An immutable audit trail entry for a single taint operation.

    Every time a TaintedValue's label is modified (propagation, declassification,
    merge), a ProvenanceRecord is appended to its provenance chain. This provides
    a complete, tamper-evident history of how data's security classification evolved
    throughout the agent pipeline.

    This record is critical for:
        - GDPR Article 30 compliance (Records of Processing Activities)
        - EU AI Act Article 12 compliance (Logging for high-risk AI systems)
        - Post-incident forensic analysis of data flow violations

    Attributes:
        record_id: Unique identifier for this provenance entry.
        timestamp: UTC timestamp of when this operation occurred.
        source_tool: The tool/function that produced or transformed this data.
        agent_id: The agent that handled this data at this step.
        operation: The type of operation performed on the taint label.
        label_before: The security label before this operation.
        label_after: The security label after this operation.
        details: Optional free-form metadata about the operation.
    """

    record_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this provenance entry.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of when this operation occurred.",
    )
    source_tool: str = Field(
        description="The tool/function that produced or transformed this data.",
    )
    agent_id: str = Field(
        description="The agent that handled this data at this step.",
    )
    operation: str = Field(
        description=(
            "The type of taint operation. One of: "
            "'create', 'propagate', 'merge', 'declassify', 'handoff'."
        ),
    )
    label_before: SecurityLabel = Field(
        description="The security label before this operation.",
    )
    label_after: SecurityLabel = Field(
        description="The security label after this operation.",
    )
    details: Optional[str] = Field(
        default=None,
        description="Optional free-form metadata about the operation.",
    )

    model_config = {"frozen": True}

    def label_changed(self) -> bool:
        """Check if this operation actually changed the security label."""
        return self.label_before != self.label_after

    def was_escalation(self) -> bool:
        """Check if the label became MORE restrictive (escalation)."""
        return self.label_after.dominates(self.label_before) and self.label_changed()

    def was_declassification(self) -> bool:
        """Check if the label became LESS restrictive (declassification)."""
        return self.label_before.dominates(self.label_after) and self.label_changed()


class TaintedValue(BaseModel, Generic[T]):
    """
    A value wrapped with its security label and full provenance chain.

    This is the fundamental unit of taint tracking in JurisAST. Every piece of
    data that enters the agent pipeline through a @tainted_source tool is wrapped
    in a TaintedValue, carrying its SecurityLabel and a complete provenance chain
    that records every transformation.

    Key Properties:
        - **Immutable operations**: propagate(), merge(), declassify() all return
          NEW TaintedValue instances. The original is never mutated.
        - **Generic**: TaintedValue[str], TaintedValue[dict], TaintedValue[CustomerRecord]
          all work, preserving the type of the underlying data.
        - **Serializable**: As a Pydantic BaseModel, the entire tainted value including
          its provenance chain can be serialized to JSON for audit logging.

    Attributes:
        value: The underlying data payload.
        label: The current security label governing this data.
        provenance: The complete, ordered list of provenance records.
        taint_id: Unique identifier for this tainted value instance.

    Examples:
        >>> from jurisast_core.labels import Jurisdiction, Classification, SecurityLabel
        >>> label = SecurityLabel(
        ...     jurisdiction=Jurisdiction.EU,
        ...     classification=Classification.PII,
        ... )
        >>> tv = TaintedValue(
        ...     value="John Doe, Berlin, DE",
        ...     label=label,
        ...     provenance=[],
        ...     taint_id="customer_record_42",
        ... )
        >>> tv.label.is_pii()
        True
        >>> tv.label.is_eu_sovereign()
        True
    """

    value: Any = Field(
        description="The underlying data payload.",
    )
    label: SecurityLabel = Field(
        description="The current security label governing this data.",
    )
    provenance: List[ProvenanceRecord] = Field(
        default_factory=list,
        description="Complete ordered provenance chain.",
    )
    taint_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this tainted value instance.",
    )
    field_labels: Dict[str, SecurityLabel] = Field(
        default_factory=dict,
        description="Fine-grained security labels for individual fields or attributes.",
    )

    model_config = {"arbitrary_types_allowed": True}

    def propagate(
        self,
        new_label: SecurityLabel,
        tool: str,
        agent_id: str,
        operation: str = "propagate",
        details: Optional[str] = None,
    ) -> TaintedValue[T]:
        """
        Create a new TaintedValue with an updated label and provenance record.

        This is the primary mechanism for taint propagation. When data passes
        through a transform tool, the label is updated (typically via join() to
        the most restrictive applicable label) and a provenance record is appended.

        Args:
            new_label: The new security label after this operation.
            tool: The tool/function performing the operation.
            agent_id: The agent handling the data.
            operation: The type of operation ('propagate', 'transform', etc.).
            details: Optional description of what happened.

        Returns:
            A new TaintedValue with updated label and extended provenance.
        """
        record = ProvenanceRecord(
            source_tool=tool,
            agent_id=agent_id,
            operation=operation,
            label_before=self.label,
            label_after=new_label,
            details=details,
        )
        return TaintedValue(
            value=self.value,
            label=new_label,
            provenance=[*self.provenance, record],
            taint_id=self.taint_id,
        )

    def declassify(
        self,
        target_label: SecurityLabel,
        declassified_value: Any,
        tool: str,
        agent_id: str,
        max_bits: float,
        details: Optional[str] = None,
    ) -> TaintedValue:
        """
        Create a new TaintedValue with a downgraded label after declassification.

        Declassification is a controlled downgrade where a bounded amount of
        information is extracted from a high-sensitivity source. The new value
        is the declassified output (e.g., a boolean sentiment), not the original data.

        Args:
            target_label: The downgraded security label.
            declassified_value: The new (bounded) value after declassification.
            tool: The declassifier tool.
            agent_id: The agent performing declassification.
            max_bits: The Shannon information bound of the output.
            details: Optional description.

        Returns:
            A new TaintedValue wrapping the declassified value.
        """
        record = ProvenanceRecord(
            source_tool=tool,
            agent_id=agent_id,
            operation="declassify",
            label_before=self.label,
            label_after=target_label,
            details=details or f"Declassified to {max_bits} bits via {tool}",
        )
        return TaintedValue(
            value=declassified_value,
            label=target_label,
            provenance=[*self.provenance, record],
            taint_id=f"{self.taint_id}::declassified",
        )

    def project(
        self,
        field_name: str,
        tool: str = "project",
        agent_id: str = "system",
        details: Optional[str] = None,
    ) -> TaintedValue:
        """
        Extract a specific field from a composite value with fine-grained security labeling.

        Solves the over-tainting and label creep problem: if the composite value
        contains field_labels for field_name, the projected value inherits ONLY that
        field's security label rather than the joined label of the entire object.

        Args:
            field_name: Name of the field/attribute to extract.
            tool: Tool/operation performing the projection.
            agent_id: The agent performing the extraction.
            details: Optional metadata.

        Returns:
            A new TaintedValue holding the projected field value and its specific label.
        """
        extracted_val: Any = None
        if isinstance(self.value, dict):
            extracted_val = self.value.get(field_name)
        elif hasattr(self.value, field_name):
            extracted_val = getattr(self.value, field_name)
        else:
            extracted_val = self.value

        field_label = self.field_labels.get(field_name, self.label)

        record = ProvenanceRecord(
            source_tool=tool,
            agent_id=agent_id,
            operation="project",
            label_before=self.label,
            label_after=field_label,
            details=details or f"Projected field '{field_name}'",
        )
        return TaintedValue(
            value=extracted_val,
            label=field_label,
            provenance=[*self.provenance, record],
            taint_id=f"{self.taint_id}::{field_name}",
        )

    @staticmethod
    def merge_labels(values: Sequence[TaintedValue]) -> SecurityLabel:
        """
        Compute the joined (most restrictive) label from multiple tainted values.

        When data from multiple sources is combined (e.g., two customer records
        are merged into a summary), the result must carry the least upper bound
        of all input labels to prevent information leakage.

        Args:
            values: Sequence of TaintedValues whose labels should be joined.

        Returns:
            The SecurityLabel that is the LUB (join) of all input labels.

        Raises:
            ValueError: If the input sequence is empty.
        """
        if not values:
            raise ValueError("Cannot merge labels from an empty sequence of tainted values.")
        result = values[0].label
        for tv in values[1:]:
            result = result.join(tv.label)
        return result

    @staticmethod
    def create(
        value: Any,
        label: SecurityLabel,
        source_tool: str,
        agent_id: str,
        details: Optional[str] = None,
    ) -> TaintedValue:
        """
        Factory method to create a new TaintedValue with an initial provenance record.

        Use this instead of the constructor when you want the creation event
        recorded in the provenance chain.

        Args:
            value: The data payload.
            label: The initial security label.
            source_tool: The tool that produced this data.
            agent_id: The agent that retrieved this data.
            details: Optional description of the data source.

        Returns:
            A new TaintedValue with one provenance record.
        """
        taint_id = str(uuid.uuid4())
        record = ProvenanceRecord(
            source_tool=source_tool,
            agent_id=agent_id,
            operation="create",
            label_before=LABEL_PUBLIC,
            label_after=label,
            details=details or f"Created by {source_tool}",
        )
        return TaintedValue(
            value=value,
            label=label,
            provenance=[record],
            taint_id=taint_id,
        )


class TaintedRecord:
    """
    Factory for composite data structures with fine-grained field-level security labels.

    Enables developers to attach distinct SecurityLabels to different attributes/keys
    of a composite payload (e.g. public statistics vs confidential notes), allowing
    downstream projections to avoid over-tainting and label creep.
    """

    @staticmethod
    def create(
        data: Dict[str, Any],
        field_labels: Dict[str, SecurityLabel],
        base_label: Optional[SecurityLabel] = None,
        source_tool: str = "source",
        agent_id: str = "system",
        taint_id: Optional[str] = None,
        details: Optional[str] = None,
    ) -> TaintedValue[Dict[str, Any]]:
        """
        Create a TaintedValue representing a structured record with fine-grained field labels.
        """
        effective_base = base_label
        if effective_base is None:
            if field_labels:
                labels_list = list(field_labels.values())
                effective_base = labels_list[0]
                for l in labels_list[1:]:
                    effective_base = effective_base.join(l)
            else:
                effective_base = LABEL_PUBLIC

        record = ProvenanceRecord(
            source_tool=source_tool,
            agent_id=agent_id,
            operation="create_record",
            label_before=LABEL_PUBLIC,
            label_after=effective_base,
            details=details or f"Created composite record with {len(field_labels)} labeled fields",
        )
        return TaintedValue(
            value=data,
            label=effective_base,
            field_labels=field_labels,
            provenance=[record],
            taint_id=taint_id or str(uuid.uuid4()),
        )


class TaintRegistry:
    """
    Session-scoped registry of all tainted values in the current agent execution.

    This registry is threaded through Pydantic AI's RunContext.deps so that all
    agents in a multi-agent pipeline share the same taint state. It maps string
    keys (typically tool_name + argument identifiers) to TaintedValue instances.

    The registry serves two critical purposes:
        1. **Taint Lookup**: When a tool call references data that was previously
           retrieved, the registry provides the SecurityLabel for AST construction.
        2. **Audit Trail**: The complete set of tainted values and their provenance
           chains constitutes the session's data flow audit log.

    Thread Safety:
        Currently NOT thread-safe. For multi-threaded agent execution, wrap
        access in a lock or use a concurrent dictionary.
    """

    def __init__(self) -> None:
        self._store: Dict[str, TaintedValue] = {}
        self._key_history: List[str] = []  # Insertion-ordered key log

    def register(self, key: str, tainted: TaintedValue) -> None:
        """
        Register a tainted value in the registry.

        If a value with the same key already exists, it is overwritten
        and a warning is logged. This supports the pattern where a tool
        retrieves updated data for the same logical entity.

        Args:
            key: The lookup key (typically tool_name + entity identifier).
            tainted: The TaintedValue to register.
        """
        self._store[key] = tainted
        self._key_history.append(key)

    def lookup(self, key: str) -> Optional[TaintedValue]:
        """
        Look up a tainted value by key.

        Supports field projection via dot-notation (e.g. 'report.public_stats').
        If 'report' is registered and has field_labels for 'public_stats',
        a projected TaintedValue with that field's label is returned.

        Args:
            key: The lookup key.

        Returns:
            The TaintedValue if found, None otherwise.
        """
        if key in self._store:
            return self._store[key]

        if "." in key:
            parent_key, field_name = key.split(".", 1)
            parent_tv = self._store.get(parent_key)
            if parent_tv is not None and field_name in parent_tv.field_labels:
                projected = parent_tv.project(field_name)
                self._store[key] = projected
                return projected

        return None

    def lookup_or_raise(self, key: str) -> TaintedValue:
        """
        Look up a tainted value by key, raising an error if not found.

        Args:
            key: The lookup key.

        Returns:
            The TaintedValue.

        Raises:
            TaintRegistryError: If the key is not found.
        """
        result = self.lookup(key)
        if result is None:
            raise TaintRegistryError(
                f"Tainted value not found for key '{key}'. "
                f"Registered keys: {list(self._store.keys())}",
            )
        return result

    def get_label_for_args(self, args: dict[str, Any]) -> SecurityLabel:
        """
        Given tool call arguments, compute the joined label of all
        referenced tainted values.

        Supports dot-notation projection resolution.

        Args:
            args: The validated tool call arguments dictionary.

        Returns:
            The SecurityLabel that is the join of all referenced tainted values,
            or LABEL_PUBLIC if no tainted values are referenced.
        """
        labels: list[SecurityLabel] = []
        for _key, value in args.items():
            if isinstance(value, str):
                tv = self.lookup(value)
                if tv is not None:
                    labels.append(tv.label)
                    continue

            # Check if the argument value matches any taint_id
            for tv in self._store.values():
                if isinstance(value, str) and value == tv.taint_id:
                    labels.append(tv.label)
                    break

        if not labels:
            return LABEL_PUBLIC
        result = labels[0]
        for label in labels[1:]:
            result = result.join(label)
        return result

    def get_all_tainted(self) -> Dict[str, TaintedValue]:
        """Return a copy of all registered tainted values."""
        return dict(self._store)

    def get_provenance_chain(self, key: str) -> List[ProvenanceRecord]:
        """
        Get the complete provenance chain for a tainted value.

        Args:
            key: The lookup key.

        Returns:
            The list of provenance records, or empty list if key not found.
        """
        tv = self._store.get(key)
        return list(tv.provenance) if tv else []

    @property
    def size(self) -> int:
        """Number of tainted values currently registered."""
        return len(self._store)

    def clear(self) -> None:
        """Clear all tainted values from the registry."""
        self._store.clear()
        self._key_history.clear()

    def __contains__(self, key: str) -> bool:
        return key in self._store

    def __len__(self) -> int:
        return len(self._store)

    def __repr__(self) -> str:
        return f"TaintRegistry(size={self.size}, keys={list(self._store.keys())})"
