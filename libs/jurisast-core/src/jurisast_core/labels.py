"""
Security Label Lattice for Information Flow Control.

Implements a multi-dimensional security lattice combining:
- Jurisdiction (geographic data sovereignty)
- Classification (data sensitivity level, Bell-LaPadula inspired)
- Compartments (categorical isolation, set-based)

The lattice supports partial ordering (dominance), join (least upper bound),
and meet (greatest lower bound) operations required for taint propagation
and non-interference proofs.

Mathematical Foundation:
    The security label forms a product lattice L = Jurisdiction × Classification × P(Compartments)
    where P(Compartments) is the powerset lattice under subset ordering.

    For labels A, B ∈ L:
        A ≥ B  ⟺  A.jurisdiction ≥ B.jurisdiction ∧
                    A.classification ≥ B.classification ∧
                    B.compartments ⊆ A.compartments

        join(A, B) = (max(A.j, B.j), max(A.c, B.c), A.comp ∪ B.comp)
        meet(A, B) = (min(A.j, B.j), min(A.c, B.c), A.comp ∩ B.comp)
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any, FrozenSet, Iterable, Tuple

from pydantic import BaseModel, Field, model_validator


class Jurisdiction(IntEnum):
    """
    Geographic data sovereignty jurisdictions.

    Ordered by restrictiveness: INTERNAL (most restricted, no exposure)
    through EXTERNAL (unrestricted). The integer values define the lattice
    ordering for Z3 mapping (higher value = less restrictive destination).

    Mapping to regulations:
        - INTERNAL: Data stays within the originating system boundary
        - EU: European Economic Area (GDPR jurisdiction)
        - UK: United Kingdom (UK GDPR, post-Brexit adequacy)
        - US: United States (no blanket adequacy decision from EU)
        - APAC: Asia-Pacific region (variable adequacy)
        - EXTERNAL: Any external system with no jurisdiction guarantee
    """

    INTERNAL = 0
    EU = 10
    UK = 20
    US = 30
    APAC = 40
    EXTERNAL = 100


# Set of jurisdictions considered "adequate" for EU data transfers.
# Based on EU adequacy decisions as of 2026.
EU_ADEQUATE_JURISDICTIONS: frozenset[Jurisdiction] = frozenset({
    Jurisdiction.INTERNAL,
    Jurisdiction.EU,
    Jurisdiction.UK,  # UK has EU adequacy decision (renewed)
})


class Classification(IntEnum):
    """
    Data sensitivity classification levels.

    Inspired by Bell-LaPadula's multi-level security model.
    Higher values represent more sensitive data that requires stricter controls.

    Mapping to real-world data types:
        - PUBLIC: Published reports, marketing materials
        - INTERNAL_ONLY: Internal memos, non-sensitive business data
        - CONFIDENTIAL: Business strategies, contracts
        - PII: Names, emails, addresses (GDPR personal data)
        - SENSITIVE_PII: Financial records, health data, biometrics (GDPR Art. 9)
        - RESTRICTED: Board-level secrets, cryptographic keys, audit master records
    """

    PUBLIC = 0
    INTERNAL_ONLY = 10
    CONFIDENTIAL = 20
    PII = 30
    SENSITIVE_PII = 40
    RESTRICTED = 50


class SecurityLabel(BaseModel):
    """
    Immutable security label combining jurisdiction, classification, and compartments.

    This is the fundamental unit of the IFC lattice. Every piece of data in JurisAST
    carries a SecurityLabel that tracks its sovereignty constraints and sensitivity level.

    The label forms a product lattice supporting:
        - dominates(): Partial order check (can data flow from other → self?)
        - join(): Least upper bound (taint propagation when data merges)
        - meet(): Greatest lower bound (declassification target computation)

    Immutability is enforced via Pydantic's frozen config to prevent
    accidental label modification that would break taint integrity.

    Examples:
        >>> eu_pii = SecurityLabel(
        ...     jurisdiction=Jurisdiction.EU,
        ...     classification=Classification.PII,
        ...     compartments=frozenset({"finance"}),
        ... )
        >>> us_public = SecurityLabel(
        ...     jurisdiction=Jurisdiction.US,
        ...     classification=Classification.PUBLIC,
        ... )
        >>> eu_pii.dominates(us_public)  # EU/PII can "see" US/PUBLIC
        False  # Because US > EU in jurisdiction ordering
    """

    jurisdiction: Jurisdiction = Field(
        description="Geographic jurisdiction governing this data's sovereignty.",
    )
    classification: Classification = Field(
        description="Sensitivity classification level of this data.",
    )
    compartments: FrozenSet[str] = Field(
        default=frozenset(),
        description=(
            "Set-based categorical compartments for need-to-know isolation. "
            "E.g., {'finance', 'hr'} means the data belongs to both compartments."
        ),
    )

    model_config = {"frozen": True}

    def dominates(self, other: SecurityLabel) -> bool:
        """
        Check if this label dominates (is greater than or equal to) another
        in the security lattice.

        A label A dominates B (A ≥ B) if and only if:
            - A.jurisdiction ≥ B.jurisdiction
            - A.classification ≥ B.classification
            - B.compartments ⊆ A.compartments

        In IFC terms: if A dominates B, then a process at clearance A
        is permitted to read data labeled B (No-Read-Up satisfied).

        Args:
            other: The label to check against.

        Returns:
            True if self ≥ other in the lattice.
        """
        return (
            self.jurisdiction >= other.jurisdiction
            and self.classification >= other.classification
            and other.compartments.issubset(self.compartments)
        )

    def join(self, other: SecurityLabel) -> SecurityLabel:
        """
        Compute the least upper bound (LUB / join / supremum) of two labels.

        The join represents the most restrictive label that dominates both inputs.
        This is used for **taint propagation**: when data from two sources is merged,
        the result inherits the highest jurisdiction, highest classification,
        and the union of all compartments.

        Mathematical property: join(A, B) is the smallest C such that C ≥ A and C ≥ B.

        Algebraic properties (verified by property tests):
            - Commutative: join(A, B) == join(B, A)
            - Associative: join(join(A, B), C) == join(A, join(B, C))
            - Idempotent: join(A, A) == A

        Args:
            other: The label to join with.

        Returns:
            A new SecurityLabel representing the least upper bound.
        """
        return SecurityLabel(
            jurisdiction=Jurisdiction(max(self.jurisdiction, other.jurisdiction)),
            classification=Classification(max(self.classification, other.classification)),
            compartments=self.compartments | other.compartments,
        )

    def meet(self, other: SecurityLabel) -> SecurityLabel:
        """
        Compute the greatest lower bound (GLB / meet / infimum) of two labels.

        The meet represents the least restrictive label dominated by both inputs.
        This is used for **declassification target computation**: determining the
        least-privilege label that a declassified output should carry.

        Mathematical property: meet(A, B) is the largest C such that A ≥ C and B ≥ C.

        Algebraic properties (verified by property tests):
            - Commutative: meet(A, B) == meet(B, A)
            - Associative: meet(meet(A, B), C) == meet(A, meet(B, C))
            - Idempotent: meet(A, A) == A

        Args:
            other: The label to meet with.

        Returns:
            A new SecurityLabel representing the greatest lower bound.
        """
        return SecurityLabel(
            jurisdiction=Jurisdiction(min(self.jurisdiction, other.jurisdiction)),
            classification=Classification(min(self.classification, other.classification)),
            compartments=self.compartments & other.compartments,
        )

    def can_flow_to(self, target: SecurityLabel) -> bool:
        """
        Check if data with this label is permitted to flow to a target.

        Information flow is permitted if the target's clearance dominates the source.
        This implements the Bell-LaPadula "No Write Down" property from the data's
        perspective: data at classification C can only flow to targets at clearance ≥ C.

        For JurisAST's cross-border use case, we **invert** the jurisdiction check:
        data originating from a more restrictive jurisdiction (EU) should NOT flow
        to a less restrictive jurisdiction (US/EXTERNAL) without declassification.

        The rule: data can flow to target iff target.dominates(self).

        Args:
            target: The destination label to check flow permission against.

        Returns:
            True if the flow is permitted.
        """
        return target.dominates(self)

    def is_pii(self) -> bool:
        """Check if this label classifies data as PII or higher."""
        return self.classification >= Classification.PII

    def is_eu_sovereign(self) -> bool:
        """Check if this data falls under EU data sovereignty rules."""
        return self.jurisdiction == Jurisdiction.EU

    def is_cross_border_risk(self, target_jurisdiction: Jurisdiction) -> bool:
        """
        Check if flowing this data to the target jurisdiction poses a
        cross-border regulatory risk.

        A risk exists when:
            - Data is EU-sovereign AND
            - Data is PII or higher AND
            - Target jurisdiction is not in the EU adequacy set
        """
        return (
            self.is_eu_sovereign()
            and self.is_pii()
            and target_jurisdiction not in EU_ADEQUATE_JURISDICTIONS
        )

    def __repr__(self) -> str:
        comp_str = f", compartments={set(self.compartments)}" if self.compartments else ""
        return (
            f"SecurityLabel({self.jurisdiction.name}/{self.classification.name}{comp_str})"
        )

    def without_compartments(self, to_remove: Iterable[str]) -> SecurityLabel:
        """
        Return a new SecurityLabel with the specified compartments removed.

        Used by deterministic compartment scrubbers to declassify categorical
        need-to-know tags (e.g., stripping 'pii' or 'phi') without modifying
        geographic sovereignty or classification clearance.
        """
        return SecurityLabel(
            jurisdiction=self.jurisdiction,
            classification=self.classification,
            compartments=self.compartments - set(to_remove),
        )

    def to_tuple(self) -> Tuple[int, int, Tuple[str, ...]]:
        """Return a hashable/serializable tuple representation."""
        return (self.jurisdiction.value, self.classification.value, tuple(sorted(self.compartments)))


# ─── Pre-built label constants for common use cases ───────────────────────────

LABEL_PUBLIC = SecurityLabel(
    jurisdiction=Jurisdiction.INTERNAL,
    classification=Classification.PUBLIC,
)
"""The bottom of the lattice: public, internal-only data."""

LABEL_EU_PII = SecurityLabel(
    jurisdiction=Jurisdiction.EU,
    classification=Classification.PII,
)
"""Standard EU personal data (names, emails, addresses)."""

LABEL_EU_SENSITIVE_PII = SecurityLabel(
    jurisdiction=Jurisdiction.EU,
    classification=Classification.SENSITIVE_PII,
)
"""EU sensitive personal data (financial records, health, biometrics)."""

LABEL_EU_RESTRICTED = SecurityLabel(
    jurisdiction=Jurisdiction.EU,
    classification=Classification.RESTRICTED,
)
"""EU restricted data (board-level, cryptographic keys)."""

LABEL_US_INTERNAL = SecurityLabel(
    jurisdiction=Jurisdiction.US,
    classification=Classification.INTERNAL_ONLY,
)
"""US internal business data (non-sensitive)."""

LABEL_US_PII = SecurityLabel(
    jurisdiction=Jurisdiction.US,
    classification=Classification.PII,
)
"""Standard US consumer personal data."""

LABEL_US_SENSITIVE_PII = SecurityLabel(
    jurisdiction=Jurisdiction.US,
    classification=Classification.SENSITIVE_PII,
)
"""US sensitive personal data (ePHI, SPI, credit info)."""

LABEL_US_RESTRICTED = SecurityLabel(
    jurisdiction=Jurisdiction.US,
    classification=Classification.RESTRICTED,
)
"""US restricted data (defense technical data, critical infrastructure)."""

LABEL_APAC_PII = SecurityLabel(
    jurisdiction=Jurisdiction.APAC,
    classification=Classification.PII,
)
"""Standard APAC personal information (e.g. under PIPL or DPDPA)."""

LABEL_APAC_RESTRICTED = SecurityLabel(
    jurisdiction=Jurisdiction.APAC,
    classification=Classification.RESTRICTED,
)
"""APAC restricted data (e.g. CIIO critical data)."""

LABEL_EXTERNAL_PUBLIC = SecurityLabel(
    jurisdiction=Jurisdiction.EXTERNAL,
    classification=Classification.PUBLIC,
)
"""The widest-scope public label: data safe for any external system."""


def label_from_metadata(metadata: dict[str, Any]) -> SecurityLabel:
    """
    Parse a raw metadata dictionary into a typed SecurityLabel.

    This is used when data is retrieved from external systems that provide
    jurisdiction/classification as string metadata rather than typed objects.

    Supports the following metadata keys:
        - "jurisdiction" or "origin": str name of Jurisdiction enum member
        - "classification" or "sensitivity": str name of Classification enum member
        - "compartments": list of str compartment names

    Args:
        metadata: Raw metadata dictionary from external data source.

    Returns:
        A SecurityLabel constructed from the metadata.

    Raises:
        ValueError: If required fields are missing or enum values are invalid.

    Examples:
        >>> label_from_metadata({"origin": "EU", "sensitivity": "PII"})
        SecurityLabel(EU/PII)
        >>> label_from_metadata({
        ...     "jurisdiction": "US",
        ...     "classification": "CONFIDENTIAL",
        ...     "compartments": ["finance"],
        ... })
        SecurityLabel(US/CONFIDENTIAL, compartments={'finance'})
    """
    # Extract jurisdiction
    jurisdiction_str = metadata.get("jurisdiction") or metadata.get("origin")
    if jurisdiction_str is None:
        raise ValueError(
            "Metadata must contain 'jurisdiction' or 'origin' key. "
            f"Got keys: {list(metadata.keys())}"
        )
    try:
        jurisdiction = Jurisdiction[jurisdiction_str.upper()]
    except KeyError:
        valid = [j.name for j in Jurisdiction]
        raise ValueError(
            f"Invalid jurisdiction '{jurisdiction_str}'. Valid values: {valid}"
        ) from None

    # Extract classification
    classification_str = (
        metadata.get("classification") or metadata.get("sensitivity")
    )
    if classification_str is None:
        raise ValueError(
            "Metadata must contain 'classification' or 'sensitivity' key. "
            f"Got keys: {list(metadata.keys())}"
        )
    try:
        classification = Classification[classification_str.upper()]
    except KeyError:
        valid = [c.name for c in Classification]
        raise ValueError(
            f"Invalid classification '{classification_str}'. Valid values: {valid}"
        ) from None

    # Extract compartments (optional)
    raw_compartments = metadata.get("compartments", [])
    if isinstance(raw_compartments, str):
        raw_compartments = [raw_compartments]
    compartments = frozenset(str(c) for c in raw_compartments)

    return SecurityLabel(
        jurisdiction=jurisdiction,
        classification=classification,
        compartments=compartments,
    )
