"""
Unit tests for the Taint Container & Provenance Tracking (taint.py).

Tests cover:
- TaintedValue construction, factory, and immutable operations
- Provenance chain tracking and audit trail
- TaintedValue.propagate() and declassify()
- TaintedValue.merge_labels() join computation
- TaintRegistry register, lookup, and label resolution
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(
    os.path.dirname(__file__), "..", "..", "libs", "jurisast-core", "src"
))

from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    SecurityLabel,
    LABEL_PUBLIC,
    LABEL_EU_PII,
    LABEL_EU_SENSITIVE_PII,
)
from jurisast_core.taint import (
    ProvenanceRecord,
    TaintedValue,
    TaintRegistry,
)
from jurisast_core.exceptions import TaintRegistryError


# ─── ProvenanceRecord Tests ───────────────────────────────────────────────────


class TestProvenanceRecord:
    """Tests for ProvenanceRecord construction and helper methods."""

    def test_construction(self):
        record = ProvenanceRecord(
            source_tool="fetch_customer",
            agent_id="agent_1",
            operation="create",
            label_before=LABEL_PUBLIC,
            label_after=LABEL_EU_PII,
        )
        assert record.source_tool == "fetch_customer"
        assert record.agent_id == "agent_1"
        assert record.operation == "create"
        assert record.record_id  # UUID generated

    def test_timestamp_generated(self):
        record = ProvenanceRecord(
            source_tool="test",
            agent_id="agent_1",
            operation="create",
            label_before=LABEL_PUBLIC,
            label_after=LABEL_EU_PII,
        )
        assert record.timestamp is not None

    def test_label_changed_true(self):
        record = ProvenanceRecord(
            source_tool="test",
            agent_id="agent_1",
            operation="propagate",
            label_before=LABEL_PUBLIC,
            label_after=LABEL_EU_PII,
        )
        assert record.label_changed() is True

    def test_label_changed_false(self):
        record = ProvenanceRecord(
            source_tool="test",
            agent_id="agent_1",
            operation="propagate",
            label_before=LABEL_EU_PII,
            label_after=LABEL_EU_PII,
        )
        assert record.label_changed() is False

    def test_was_escalation(self):
        record = ProvenanceRecord(
            source_tool="test",
            agent_id="agent_1",
            operation="propagate",
            label_before=LABEL_PUBLIC,
            label_after=LABEL_EU_PII,
        )
        assert record.was_escalation() is True
        assert record.was_declassification() is False

    def test_was_declassification(self):
        record = ProvenanceRecord(
            source_tool="test",
            agent_id="agent_1",
            operation="declassify",
            label_before=LABEL_EU_PII,
            label_after=LABEL_PUBLIC,
        )
        assert record.was_declassification() is True
        assert record.was_escalation() is False

    def test_immutability(self):
        record = ProvenanceRecord(
            source_tool="test",
            agent_id="agent_1",
            operation="create",
            label_before=LABEL_PUBLIC,
            label_after=LABEL_EU_PII,
        )
        with pytest.raises(Exception):
            record.source_tool = "hacked"  # type: ignore


# ─── TaintedValue Construction Tests ──────────────────────────────────────────


class TestTaintedValueConstruction:
    """Tests for TaintedValue construction and the create() factory."""

    def test_direct_construction(self):
        tv = TaintedValue(
            value="John Doe",
            label=LABEL_EU_PII,
        )
        assert tv.value == "John Doe"
        assert tv.label == LABEL_EU_PII
        assert tv.provenance == []
        assert tv.taint_id  # UUID generated

    def test_factory_create(self):
        tv = TaintedValue.create(
            value="John Doe, Berlin",
            label=LABEL_EU_PII,
            source_tool="fetch_customer",
            agent_id="agent_retriever",
        )
        assert tv.value == "John Doe, Berlin"
        assert tv.label == LABEL_EU_PII
        assert len(tv.provenance) == 1
        assert tv.provenance[0].operation == "create"
        assert tv.provenance[0].label_before == LABEL_PUBLIC
        assert tv.provenance[0].label_after == LABEL_EU_PII

    def test_factory_create_with_details(self):
        tv = TaintedValue.create(
            value={"name": "John"},
            label=LABEL_EU_PII,
            source_tool="db_query",
            agent_id="agent_1",
            details="Retrieved from customers.eu_pii table",
        )
        assert tv.provenance[0].details == "Retrieved from customers.eu_pii table"


# ─── TaintedValue.propagate() Tests ──────────────────────────────────────────


class TestTaintedValuePropagate:
    """Tests for immutable taint propagation."""

    def test_propagate_creates_new_instance(self):
        original = TaintedValue.create(
            value="data",
            label=LABEL_EU_PII,
            source_tool="source",
            agent_id="agent_1",
        )
        propagated = original.propagate(
            new_label=LABEL_EU_SENSITIVE_PII,
            tool="transform",
            agent_id="agent_2",
            operation="propagate",
        )
        # Original is unchanged
        assert original.label == LABEL_EU_PII
        assert len(original.provenance) == 1
        # Propagated has updated label and extended provenance
        assert propagated.label == LABEL_EU_SENSITIVE_PII
        assert len(propagated.provenance) == 2

    def test_propagate_preserves_value(self):
        original = TaintedValue.create(
            value="sensitive_data",
            label=LABEL_EU_PII,
            source_tool="source",
            agent_id="agent_1",
        )
        propagated = original.propagate(
            new_label=LABEL_EU_SENSITIVE_PII,
            tool="enrich",
            agent_id="agent_2",
        )
        assert propagated.value == "sensitive_data"

    def test_propagate_preserves_taint_id(self):
        original = TaintedValue.create(
            value="data",
            label=LABEL_EU_PII,
            source_tool="source",
            agent_id="agent_1",
        )
        propagated = original.propagate(
            new_label=LABEL_EU_SENSITIVE_PII,
            tool="transform",
            agent_id="agent_2",
        )
        assert propagated.taint_id == original.taint_id

    def test_propagate_provenance_chain(self):
        tv = TaintedValue.create(
            value="data",
            label=LABEL_PUBLIC,
            source_tool="public_api",
            agent_id="agent_1",
        )
        tv2 = tv.propagate(
            new_label=LABEL_EU_PII,
            tool="merge_with_pii",
            agent_id="agent_1",
            details="Merged with EU customer data",
        )
        tv3 = tv2.propagate(
            new_label=LABEL_EU_SENSITIVE_PII,
            tool="add_financial_data",
            agent_id="agent_2",
        )
        assert len(tv3.provenance) == 3
        assert tv3.provenance[0].operation == "create"
        assert tv3.provenance[1].operation == "propagate"
        assert tv3.provenance[1].details == "Merged with EU customer data"
        assert tv3.provenance[2].operation == "propagate"


# ─── TaintedValue.declassify() Tests ─────────────────────────────────────────


class TestTaintedValueDeclassify:
    """Tests for controlled declassification."""

    def test_declassify_changes_value_and_label(self):
        original = TaintedValue.create(
            value="John Doe has positive sentiment about product X",
            label=LABEL_EU_PII,
            source_tool="email_reader",
            agent_id="agent_1",
        )
        declassified = original.declassify(
            target_label=LABEL_PUBLIC,
            declassified_value=True,  # Boolean sentiment
            tool="sentiment_extractor",
            agent_id="agent_1",
            max_bits=1.0,
        )
        assert declassified.value is True
        assert declassified.label == LABEL_PUBLIC
        assert "declassified" in declassified.taint_id

    def test_declassify_provenance(self):
        original = TaintedValue.create(
            value="sensitive text",
            label=LABEL_EU_SENSITIVE_PII,
            source_tool="source",
            agent_id="agent_1",
        )
        declassified = original.declassify(
            target_label=LABEL_PUBLIC,
            declassified_value=False,
            tool="sentiment",
            agent_id="agent_1",
            max_bits=1.0,
        )
        last_record = declassified.provenance[-1]
        assert last_record.operation == "declassify"
        assert last_record.label_before == LABEL_EU_SENSITIVE_PII
        assert last_record.label_after == LABEL_PUBLIC
        assert last_record.was_declassification() is True


# ─── TaintedValue.merge_labels() Tests ───────────────────────────────────────


class TestMergeLabels:
    """Tests for merging labels across multiple tainted values."""

    def test_merge_single_value(self):
        tv = TaintedValue(value="data", label=LABEL_EU_PII)
        result = TaintedValue.merge_labels([tv])
        assert result == LABEL_EU_PII

    def test_merge_takes_join(self):
        tv1 = TaintedValue(value="data1", label=LABEL_EU_PII)
        tv2 = TaintedValue(
            value="data2",
            label=SecurityLabel(
                jurisdiction=Jurisdiction.US,
                classification=Classification.CONFIDENTIAL,
            ),
        )
        result = TaintedValue.merge_labels([tv1, tv2])
        # join: max(EU=10, US=30)=US, max(PII=30, CONF=20)=PII
        assert result.jurisdiction == Jurisdiction.US
        assert result.classification == Classification.PII

    def test_merge_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            TaintedValue.merge_labels([])

    def test_merge_three_values(self):
        tv1 = TaintedValue(
            value="a",
            label=SecurityLabel(
                jurisdiction=Jurisdiction.EU, classification=Classification.CONFIDENTIAL,
            ),
        )
        tv2 = TaintedValue(
            value="b",
            label=SecurityLabel(
                jurisdiction=Jurisdiction.US, classification=Classification.PUBLIC,
            ),
        )
        tv3 = TaintedValue(
            value="c",
            label=SecurityLabel(
                jurisdiction=Jurisdiction.INTERNAL, classification=Classification.SENSITIVE_PII,
            ),
        )
        result = TaintedValue.merge_labels([tv1, tv2, tv3])
        assert result.jurisdiction == Jurisdiction.US
        assert result.classification == Classification.SENSITIVE_PII


# ─── TaintRegistry Tests ─────────────────────────────────────────────────────


class TestTaintRegistry:
    """Tests for the TaintRegistry session store."""

    def test_register_and_lookup(self):
        registry = TaintRegistry()
        tv = TaintedValue.create(
            value="John Doe",
            label=LABEL_EU_PII,
            source_tool="fetch_customer",
            agent_id="agent_1",
        )
        registry.register("customer_42", tv)
        result = registry.lookup("customer_42")
        assert result is not None
        assert result.value == "John Doe"

    def test_lookup_missing_returns_none(self):
        registry = TaintRegistry()
        assert registry.lookup("nonexistent") is None

    def test_lookup_or_raise(self):
        registry = TaintRegistry()
        with pytest.raises(TaintRegistryError, match="not found"):
            registry.lookup_or_raise("nonexistent")

    def test_size(self):
        registry = TaintRegistry()
        assert registry.size == 0
        tv = TaintedValue(value="data", label=LABEL_EU_PII)
        registry.register("key1", tv)
        assert registry.size == 1
        registry.register("key2", tv)
        assert registry.size == 2

    def test_contains(self):
        registry = TaintRegistry()
        tv = TaintedValue(value="data", label=LABEL_EU_PII)
        registry.register("key1", tv)
        assert "key1" in registry
        assert "key2" not in registry

    def test_overwrite(self):
        registry = TaintRegistry()
        tv1 = TaintedValue(value="old_data", label=LABEL_EU_PII)
        tv2 = TaintedValue(value="new_data", label=LABEL_EU_SENSITIVE_PII)
        registry.register("key", tv1)
        registry.register("key", tv2)
        result = registry.lookup("key")
        assert result is not None
        assert result.value == "new_data"
        assert result.label == LABEL_EU_SENSITIVE_PII

    def test_get_label_for_args_with_matching_key(self):
        registry = TaintRegistry()
        tv = TaintedValue(value="data", label=LABEL_EU_PII)
        registry.register("customer_42", tv)
        label = registry.get_label_for_args({"data_ref": "customer_42"})
        assert label == LABEL_EU_PII

    def test_get_label_for_args_no_match_returns_public(self):
        registry = TaintRegistry()
        label = registry.get_label_for_args({"data_ref": "unknown"})
        assert label == LABEL_PUBLIC

    def test_get_label_for_args_multiple_refs_joins(self):
        registry = TaintRegistry()
        tv1 = TaintedValue(value="data1", label=LABEL_EU_PII)
        tv2 = TaintedValue(
            value="data2",
            label=SecurityLabel(
                jurisdiction=Jurisdiction.US,
                classification=Classification.CONFIDENTIAL,
            ),
        )
        registry.register("ref1", tv1)
        registry.register("ref2", tv2)
        label = registry.get_label_for_args({"a": "ref1", "b": "ref2"})
        # join: max(EU, US)=US, max(PII, CONF)=PII
        assert label.jurisdiction == Jurisdiction.US
        assert label.classification == Classification.PII

    def test_clear(self):
        registry = TaintRegistry()
        tv = TaintedValue(value="data", label=LABEL_EU_PII)
        registry.register("key", tv)
        assert registry.size == 1
        registry.clear()
        assert registry.size == 0
        assert registry.lookup("key") is None

    def test_get_all_tainted(self):
        registry = TaintRegistry()
        tv1 = TaintedValue(value="a", label=LABEL_EU_PII)
        tv2 = TaintedValue(value="b", label=LABEL_PUBLIC)
        registry.register("k1", tv1)
        registry.register("k2", tv2)
        all_tainted = registry.get_all_tainted()
        assert len(all_tainted) == 2
        assert "k1" in all_tainted
        assert "k2" in all_tainted

    def test_get_provenance_chain(self):
        registry = TaintRegistry()
        tv = TaintedValue.create(
            value="data",
            label=LABEL_EU_PII,
            source_tool="source",
            agent_id="agent_1",
        )
        propagated = tv.propagate(
            new_label=LABEL_EU_SENSITIVE_PII,
            tool="transform",
            agent_id="agent_2",
        )
        registry.register("key", propagated)
        chain = registry.get_provenance_chain("key")
        assert len(chain) == 2
        assert chain[0].operation == "create"
        assert chain[1].operation == "propagate"

    def test_get_provenance_chain_missing_key(self):
        registry = TaintRegistry()
        assert registry.get_provenance_chain("nonexistent") == []

    def test_repr(self):
        registry = TaintRegistry()
        r = repr(registry)
        assert "TaintRegistry" in r
        assert "size=0" in r
