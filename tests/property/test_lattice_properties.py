"""
Property-Based Tests for the Security Label Lattice.

Uses Hypothesis to verify algebraic properties that MUST hold for the
SecurityLabel to form a valid lattice:
    - Reflexivity, antisymmetry, transitivity of dominates()
    - Commutativity, associativity, idempotency of join() and meet()
    - Absorption laws: a ∨ (a ∧ b) = a  and  a ∧ (a ∨ b) = a
    - Join is the LUB: join(a, b) dominates both a and b
    - Meet is the GLB: both a and b dominate meet(a, b)

These properties guarantee mathematical soundness of the IFC lattice,
which is critical for Z3 solver correctness in later phases.
"""

import sys
import os

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"
))

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
)

# ─── Hypothesis Strategies ────────────────────────────────────────────────────

jurisdictions = st.sampled_from(list(Jurisdiction))
classifications = st.sampled_from(list(Classification))

# Strategy for a set of compartments (0-4 items from a small pool)
compartment_pool = ["finance", "hr", "legal", "engineering", "marketing"]
compartments = st.frozensets(st.sampled_from(compartment_pool), max_size=4)

# Strategy for a complete SecurityLabel
security_labels = st.builds(
    SecurityLabel,
    jurisdiction=jurisdictions,
    classification=classifications,
    compartments=compartments,
)


# ─── Dominance (Partial Order) Properties ────────────────────────────────────


class TestDominanceProperties:
    """Property-based tests for the dominates() partial order."""

    @given(a=security_labels)
    @settings(max_examples=200)
    def test_reflexivity(self, a: SecurityLabel):
        """∀ a: a ≥ a (every label dominates itself)."""
        assert a.dominates(a)

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_antisymmetry(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: (a ≥ b ∧ b ≥ a) → a = b"""
        if a.dominates(b) and b.dominates(a):
            assert a == b

    @given(a=security_labels, b=security_labels, c=security_labels)
    @settings(max_examples=500)
    def test_transitivity(self, a: SecurityLabel, b: SecurityLabel, c: SecurityLabel):
        """∀ a, b, c: (a ≥ b ∧ b ≥ c) → a ≥ c"""
        if a.dominates(b) and b.dominates(c):
            assert a.dominates(c)


# ─── Join (LUB) Properties ───────────────────────────────────────────────────


class TestJoinProperties:
    """Property-based tests for join() — least upper bound."""

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_commutativity(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: join(a, b) = join(b, a)"""
        assert a.join(b) == b.join(a)

    @given(a=security_labels, b=security_labels, c=security_labels)
    @settings(max_examples=500)
    def test_associativity(self, a: SecurityLabel, b: SecurityLabel, c: SecurityLabel):
        """∀ a, b, c: join(join(a, b), c) = join(a, join(b, c))"""
        assert a.join(b).join(c) == a.join(b.join(c))

    @given(a=security_labels)
    @settings(max_examples=200)
    def test_idempotency(self, a: SecurityLabel):
        """∀ a: join(a, a) = a"""
        assert a.join(a) == a

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_join_dominates_both_inputs(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: join(a, b) ≥ a ∧ join(a, b) ≥ b"""
        joined = a.join(b)
        assert joined.dominates(a), f"join({a}, {b}) = {joined} does not dominate {a}"
        assert joined.dominates(b), f"join({a}, {b}) = {joined} does not dominate {b}"

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_join_is_upper_bound(self, a: SecurityLabel, b: SecurityLabel):
        """If a dominates b, then join(a, b) = a (a is already the UB)."""
        if a.dominates(b):
            assert a.join(b) == a


# ─── Meet (GLB) Properties ───────────────────────────────────────────────────


class TestMeetProperties:
    """Property-based tests for meet() — greatest lower bound."""

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_commutativity(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: meet(a, b) = meet(b, a)"""
        assert a.meet(b) == b.meet(a)

    @given(a=security_labels, b=security_labels, c=security_labels)
    @settings(max_examples=500)
    def test_associativity(self, a: SecurityLabel, b: SecurityLabel, c: SecurityLabel):
        """∀ a, b, c: meet(meet(a, b), c) = meet(a, meet(b, c))"""
        assert a.meet(b).meet(c) == a.meet(b.meet(c))

    @given(a=security_labels)
    @settings(max_examples=200)
    def test_idempotency(self, a: SecurityLabel):
        """∀ a: meet(a, a) = a"""
        assert a.meet(a) == a

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_both_dominate_meet(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: a ≥ meet(a, b) ∧ b ≥ meet(a, b)"""
        met = a.meet(b)
        assert a.dominates(met), f"{a} does not dominate meet({a}, {b}) = {met}"
        assert b.dominates(met), f"{b} does not dominate meet({a}, {b}) = {met}"

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_meet_is_lower_bound(self, a: SecurityLabel, b: SecurityLabel):
        """If a dominates b, then meet(a, b) = b (b is already the LB)."""
        if a.dominates(b):
            assert a.meet(b) == b


# ─── Absorption Laws ─────────────────────────────────────────────────────────


class TestAbsorptionProperties:
    """Absorption laws prove join/meet form a true lattice, not just two semilattices."""

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_absorption_join_meet(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: a ∨ (a ∧ b) = a"""
        assert a.join(a.meet(b)) == a

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_absorption_meet_join(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: a ∧ (a ∨ b) = a"""
        assert a.meet(a.join(b)) == a


# ─── Join-Meet Interaction Properties ────────────────────────────────────────


class TestJoinMeetInteraction:
    """Properties verifying the relationship between join and meet."""

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_meet_leq_join(self, a: SecurityLabel, b: SecurityLabel):
        """∀ a, b: join(a, b) ≥ meet(a, b) (the LUB dominates the GLB)."""
        assert a.join(b).dominates(a.meet(b))

    @given(a=security_labels, b=security_labels)
    @settings(max_examples=500)
    def test_can_flow_consistent_with_dominance(self, a: SecurityLabel, b: SecurityLabel):
        """can_flow_to is consistent with dominance: a.can_flow_to(b) ⟺ b.dominates(a)."""
        assert a.can_flow_to(b) == b.dominates(a)
