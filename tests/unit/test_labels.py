"""
Unit tests for the Security Label Lattice (labels.py).

Tests cover:
- Jurisdiction and Classification enum ordering
- SecurityLabel construction and immutability
- Lattice operations: dominates, join, meet
- Flow permission checks (can_flow_to)
- Cross-border risk detection
- label_from_metadata parser
- Pre-built label constants
"""

import sys
import os
import pytest

# Add the source to path for direct testing
sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"
))

from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    EU_ADEQUATE_JURISDICTIONS,
    LABEL_PUBLIC,
    LABEL_EU_PII,
    LABEL_EU_SENSITIVE_PII,
    LABEL_EU_RESTRICTED,
    LABEL_US_INTERNAL,
    LABEL_EXTERNAL_PUBLIC,
    label_from_metadata,
)


# ─── Enum Ordering Tests ──────────────────────────────────────────────────────


class TestJurisdiction:
    """Tests for the Jurisdiction enum ordering."""

    def test_ordering_internal_lowest(self):
        assert Jurisdiction.INTERNAL < Jurisdiction.EU
        assert Jurisdiction.INTERNAL < Jurisdiction.US
        assert Jurisdiction.INTERNAL < Jurisdiction.EXTERNAL

    def test_ordering_eu_less_than_us(self):
        assert Jurisdiction.EU < Jurisdiction.US

    def test_ordering_external_highest(self):
        assert Jurisdiction.EXTERNAL > Jurisdiction.EU
        assert Jurisdiction.EXTERNAL > Jurisdiction.US
        assert Jurisdiction.EXTERNAL > Jurisdiction.APAC

    def test_all_values_distinct(self):
        values = [j.value for j in Jurisdiction]
        assert len(values) == len(set(values))

    def test_enum_members_complete(self):
        expected = {"INTERNAL", "EU", "UK", "US", "APAC", "EXTERNAL"}
        actual = {j.name for j in Jurisdiction}
        assert actual == expected


class TestClassification:
    """Tests for the Classification enum ordering."""

    def test_ordering_public_lowest(self):
        assert Classification.PUBLIC < Classification.INTERNAL_ONLY
        assert Classification.PUBLIC < Classification.PII
        assert Classification.PUBLIC < Classification.RESTRICTED

    def test_ordering_pii_levels(self):
        assert Classification.PII < Classification.SENSITIVE_PII
        assert Classification.SENSITIVE_PII < Classification.RESTRICTED

    def test_ordering_full_chain(self):
        ordered = [
            Classification.PUBLIC,
            Classification.INTERNAL_ONLY,
            Classification.CONFIDENTIAL,
            Classification.PII,
            Classification.SENSITIVE_PII,
            Classification.RESTRICTED,
        ]
        for i in range(len(ordered) - 1):
            assert ordered[i] < ordered[i + 1], (
                f"{ordered[i].name} should be < {ordered[i + 1].name}"
            )

    def test_all_values_distinct(self):
        values = [c.value for c in Classification]
        assert len(values) == len(set(values))


# ─── SecurityLabel Construction & Immutability ─────────────────────────────────


class TestSecurityLabelConstruction:
    """Tests for SecurityLabel model construction and properties."""

    def test_basic_construction(self):
        label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        assert label.jurisdiction == Jurisdiction.EU
        assert label.classification == Classification.PII
        assert label.compartments == frozenset()

    def test_construction_with_compartments(self):
        label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance", "hr"}),
        )
        assert label.compartments == frozenset({"finance", "hr"})

    def test_immutability_jurisdiction(self):
        label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        with pytest.raises(Exception):  # Pydantic frozen model
            label.jurisdiction = Jurisdiction.US  # type: ignore

    def test_immutability_classification(self):
        label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        with pytest.raises(Exception):
            label.classification = Classification.PUBLIC  # type: ignore

    def test_equality(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
        )
        assert a == b

    def test_inequality_jurisdiction(self):
        a = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        b = SecurityLabel(jurisdiction=Jurisdiction.US, classification=Classification.PII)
        assert a != b

    def test_inequality_compartments(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"hr"}),
        )
        assert a != b

    def test_hashable(self):
        """SecurityLabel must be hashable for use as dict keys / set members."""
        label = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.PII
        )
        label_set = {label, label}
        assert len(label_set) == 1

    def test_repr(self):
        label = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.PII
        )
        r = repr(label)
        assert "EU" in r
        assert "PII" in r


# ─── Lattice Dominance Tests ──────────────────────────────────────────────────


class TestDominance:
    """Tests for the SecurityLabel.dominates() partial order."""

    def test_reflexive(self):
        """Every label dominates itself."""
        label = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        assert label.dominates(label)

    def test_higher_dominates_lower(self):
        """Higher jurisdiction + classification dominates lower."""
        high = SecurityLabel(
            jurisdiction=Jurisdiction.EXTERNAL,
            classification=Classification.RESTRICTED,
        )
        low = SecurityLabel(
            jurisdiction=Jurisdiction.INTERNAL,
            classification=Classification.PUBLIC,
        )
        assert high.dominates(low)
        assert not low.dominates(high)

    def test_same_level_different_jurisdiction(self):
        eu = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        us = SecurityLabel(jurisdiction=Jurisdiction.US, classification=Classification.PII)
        # US has higher jurisdiction value, so US dominates EU
        assert us.dominates(eu)
        assert not eu.dominates(us)

    def test_compartment_superset_dominates(self):
        broad = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance", "hr"}),
        )
        narrow = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        assert broad.dominates(narrow)
        assert not narrow.dominates(broad)

    def test_disjoint_compartments_no_dominance(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"hr"}),
        )
        assert not a.dominates(b)
        assert not b.dominates(a)

    def test_antisymmetric(self):
        """If A dominates B and B dominates A, then A == B."""
        a = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        b = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        assert a.dominates(b) and b.dominates(a)
        assert a == b

    def test_transitive(self):
        """If A dominates B and B dominates C, then A dominates C."""
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EXTERNAL, classification=Classification.RESTRICTED
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.US, classification=Classification.PII
        )
        c = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL
        )
        assert a.dominates(b)
        assert b.dominates(c)
        assert a.dominates(c)  # Transitivity


# ─── Join (Least Upper Bound) Tests ──────────────────────────────────────────


class TestJoin:
    """Tests for SecurityLabel.join() — least upper bound."""

    def test_join_takes_max_jurisdiction(self):
        eu = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        us = SecurityLabel(jurisdiction=Jurisdiction.US, classification=Classification.PII)
        joined = eu.join(us)
        assert joined.jurisdiction == Jurisdiction.US

    def test_join_takes_max_classification(self):
        a = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.SENSITIVE_PII
        )
        joined = a.join(b)
        assert joined.classification == Classification.SENSITIVE_PII

    def test_join_unions_compartments(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"hr"}),
        )
        joined = a.join(b)
        assert joined.compartments == frozenset({"finance", "hr"})

    def test_join_commutative(self):
        a = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        b = SecurityLabel(
            jurisdiction=Jurisdiction.US, classification=Classification.CONFIDENTIAL
        )
        assert a.join(b) == b.join(a)

    def test_join_idempotent(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        assert a.join(a) == a

    def test_join_associative(self):
        a = SecurityLabel(jurisdiction=Jurisdiction.INTERNAL, classification=Classification.PUBLIC)
        b = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        c = SecurityLabel(
            jurisdiction=Jurisdiction.US, classification=Classification.CONFIDENTIAL
        )
        assert a.join(b).join(c) == a.join(b.join(c))

    def test_join_result_dominates_both(self):
        """The join must dominate both inputs (it's the LUB)."""
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.US,
            classification=Classification.CONFIDENTIAL,
            compartments=frozenset({"hr"}),
        )
        joined = a.join(b)
        assert joined.dominates(a)
        assert joined.dominates(b)


# ─── Meet (Greatest Lower Bound) Tests ────────────────────────────────────────


class TestMeet:
    """Tests for SecurityLabel.meet() — greatest lower bound."""

    def test_meet_takes_min_jurisdiction(self):
        eu = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        us = SecurityLabel(jurisdiction=Jurisdiction.US, classification=Classification.PII)
        met = eu.meet(us)
        assert met.jurisdiction == Jurisdiction.EU

    def test_meet_takes_min_classification(self):
        a = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.SENSITIVE_PII
        )
        met = a.meet(b)
        assert met.classification == Classification.PII

    def test_meet_intersects_compartments(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance", "hr"}),
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"hr", "legal"}),
        )
        met = a.meet(b)
        assert met.compartments == frozenset({"hr"})

    def test_meet_commutative(self):
        a = SecurityLabel(jurisdiction=Jurisdiction.EU, classification=Classification.PII)
        b = SecurityLabel(
            jurisdiction=Jurisdiction.US, classification=Classification.CONFIDENTIAL
        )
        assert a.meet(b) == b.meet(a)

    def test_meet_idempotent(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.PII,
            compartments=frozenset({"finance"}),
        )
        assert a.meet(a) == a

    def test_meet_associative(self):
        a = SecurityLabel(
            jurisdiction=Jurisdiction.EXTERNAL, classification=Classification.RESTRICTED
        )
        b = SecurityLabel(jurisdiction=Jurisdiction.US, classification=Classification.PII)
        c = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL
        )
        assert a.meet(b).meet(c) == a.meet(b.meet(c))

    def test_both_dominate_meet(self):
        """Both inputs must dominate the meet result (it's the GLB)."""
        a = SecurityLabel(
            jurisdiction=Jurisdiction.US,
            classification=Classification.PII,
            compartments=frozenset({"finance", "hr"}),
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU,
            classification=Classification.SENSITIVE_PII,
            compartments=frozenset({"hr", "legal"}),
        )
        met = a.meet(b)
        assert a.dominates(met)
        assert b.dominates(met)


# ─── Absorption Law Tests ────────────────────────────────────────────────────


class TestAbsorptionLaws:
    """Verify the absorption laws that prove we have a true lattice."""

    def test_absorption_join_meet(self):
        """a ∨ (a ∧ b) == a"""
        a = SecurityLabel(
            jurisdiction=Jurisdiction.US, classification=Classification.PII
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL
        )
        assert a.join(a.meet(b)) == a

    def test_absorption_meet_join(self):
        """a ∧ (a ∨ b) == a"""
        a = SecurityLabel(
            jurisdiction=Jurisdiction.US, classification=Classification.PII
        )
        b = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL
        )
        assert a.meet(a.join(b)) == a


# ─── Flow Permission Tests ────────────────────────────────────────────────────


class TestFlowPermission:
    """Tests for can_flow_to() and cross-border risk detection."""

    def test_public_can_flow_anywhere(self):
        public = LABEL_PUBLIC
        external = LABEL_EXTERNAL_PUBLIC
        assert public.can_flow_to(external)

    def test_eu_pii_cannot_flow_to_us_public(self):
        """This is the core GDPR violation scenario."""
        eu_pii = LABEL_EU_PII
        us_public = SecurityLabel(
            jurisdiction=Jurisdiction.US, classification=Classification.PUBLIC
        )
        # EU/PII → US/PUBLIC: target (US/PUBLIC) does NOT dominate source (EU/PII)
        # because target.classification (PUBLIC=0) < source.classification (PII=30)
        assert not eu_pii.can_flow_to(us_public)

    def test_eu_pii_can_flow_to_eu_sensitive_pii(self):
        """Data can flow UP within the same jurisdiction."""
        assert LABEL_EU_PII.can_flow_to(LABEL_EU_SENSITIVE_PII)

    def test_eu_pii_can_flow_to_eu_pii(self):
        """Data can flow to same level."""
        assert LABEL_EU_PII.can_flow_to(LABEL_EU_PII)

    def test_is_pii(self):
        assert LABEL_EU_PII.is_pii()
        assert LABEL_EU_SENSITIVE_PII.is_pii()
        assert not LABEL_PUBLIC.is_pii()
        assert not LABEL_US_INTERNAL.is_pii()

    def test_is_eu_sovereign(self):
        assert LABEL_EU_PII.is_eu_sovereign()
        assert not LABEL_US_INTERNAL.is_eu_sovereign()

    def test_cross_border_risk_eu_pii_to_us(self):
        assert LABEL_EU_PII.is_cross_border_risk(Jurisdiction.US)

    def test_no_cross_border_risk_eu_pii_to_eu(self):
        assert not LABEL_EU_PII.is_cross_border_risk(Jurisdiction.EU)

    def test_no_cross_border_risk_eu_public_to_us(self):
        eu_public = SecurityLabel(
            jurisdiction=Jurisdiction.EU, classification=Classification.PUBLIC
        )
        assert not eu_public.is_cross_border_risk(Jurisdiction.US)

    def test_eu_adequate_jurisdictions_includes_uk(self):
        assert Jurisdiction.UK in EU_ADEQUATE_JURISDICTIONS

    def test_eu_adequate_jurisdictions_excludes_us(self):
        assert Jurisdiction.US not in EU_ADEQUATE_JURISDICTIONS


# ─── label_from_metadata Parser Tests ─────────────────────────────────────────


class TestLabelFromMetadata:
    """Tests for the label_from_metadata() parser function."""

    def test_basic_parsing(self):
        label = label_from_metadata({
            "jurisdiction": "EU",
            "classification": "PII",
        })
        assert label.jurisdiction == Jurisdiction.EU
        assert label.classification == Classification.PII

    def test_alternative_keys(self):
        label = label_from_metadata({
            "origin": "US",
            "sensitivity": "CONFIDENTIAL",
        })
        assert label.jurisdiction == Jurisdiction.US
        assert label.classification == Classification.CONFIDENTIAL

    def test_case_insensitive(self):
        label = label_from_metadata({
            "jurisdiction": "eu",
            "classification": "pii",
        })
        assert label.jurisdiction == Jurisdiction.EU
        assert label.classification == Classification.PII

    def test_with_compartments(self):
        label = label_from_metadata({
            "jurisdiction": "EU",
            "classification": "PII",
            "compartments": ["finance", "hr"],
        })
        assert label.compartments == frozenset({"finance", "hr"})

    def test_single_compartment_string(self):
        label = label_from_metadata({
            "jurisdiction": "EU",
            "classification": "PII",
            "compartments": "finance",
        })
        assert label.compartments == frozenset({"finance"})

    def test_missing_jurisdiction_raises(self):
        with pytest.raises(ValueError, match="jurisdiction"):
            label_from_metadata({"classification": "PII"})

    def test_missing_classification_raises(self):
        with pytest.raises(ValueError, match="classification"):
            label_from_metadata({"jurisdiction": "EU"})

    def test_invalid_jurisdiction_raises(self):
        with pytest.raises(ValueError, match="Invalid jurisdiction"):
            label_from_metadata({
                "jurisdiction": "MARS",
                "classification": "PII",
            })

    def test_invalid_classification_raises(self):
        with pytest.raises(ValueError, match="Invalid classification"):
            label_from_metadata({
                "jurisdiction": "EU",
                "classification": "ULTRA_SECRET",
            })

    def test_empty_compartments_default(self):
        label = label_from_metadata({
            "jurisdiction": "EU",
            "classification": "PII",
        })
        assert label.compartments == frozenset()


# ─── Pre-built Constants Tests ────────────────────────────────────────────────


class TestPrebuiltConstants:
    """Verify the pre-built label constants are correctly defined."""

    def test_label_public_is_bottom(self):
        """LABEL_PUBLIC should be dominated by everything."""
        for j in Jurisdiction:
            for c in Classification:
                label = SecurityLabel(jurisdiction=j, classification=c)
                assert label.dominates(LABEL_PUBLIC)

    def test_label_eu_pii(self):
        assert LABEL_EU_PII.jurisdiction == Jurisdiction.EU
        assert LABEL_EU_PII.classification == Classification.PII

    def test_label_eu_sensitive_pii(self):
        assert LABEL_EU_SENSITIVE_PII.classification == Classification.SENSITIVE_PII

    def test_label_hierarchy(self):
        """EU_SENSITIVE_PII dominates EU_PII dominates PUBLIC."""
        assert LABEL_EU_SENSITIVE_PII.dominates(LABEL_EU_PII)
        assert LABEL_EU_PII.dominates(LABEL_PUBLIC)
        assert LABEL_EU_SENSITIVE_PII.dominates(LABEL_PUBLIC)
