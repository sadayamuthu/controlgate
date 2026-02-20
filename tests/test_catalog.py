"""Tests for the NIST catalog loader and CatalogIndex."""


import pytest

from controlgate.catalog import GATE_CONTROL_MAP, CatalogIndex


class TestCatalogLoading:
    def test_loads_controls(self, catalog):
        """Catalog should load all 1189 controls."""
        assert catalog.count == 1189

    def test_raises_on_missing_file(self):
        with pytest.raises(FileNotFoundError):
            CatalogIndex("/nonexistent/catalog.json")


class TestCatalogByID:
    def test_lookup_existing_control(self, catalog):
        ctrl = catalog.by_id("AC-3")
        assert ctrl is not None
        assert ctrl.control_id == "AC-3"
        assert ctrl.control_name == "Access Enforcement"
        assert ctrl.family == "AC"

    def test_lookup_nonexistent_control(self, catalog):
        assert catalog.by_id("ZZ-999") is None

    def test_lookup_child_control(self, catalog):
        ctrl = catalog.by_id("AC-11(1)")
        assert ctrl is not None
        assert ctrl.parent_control_id == "AC-11"


class TestCatalogByFamily:
    def test_ac_family_has_controls(self, catalog):
        ac_controls = catalog.by_family("AC")
        assert len(ac_controls) > 0
        assert all(c.family == "AC" for c in ac_controls)

    def test_nonexistent_family(self, catalog):
        assert catalog.by_family("ZZ") == []


class TestCatalogBySeverity:
    def test_high_severity(self, catalog):
        high = catalog.by_severity("HIGH")
        assert len(high) > 0
        assert all(c.severity == "HIGH" for c in high)

    def test_all_severities_present(self, catalog):
        for sev in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            assert len(catalog.by_severity(sev)) > 0


class TestCatalogNonNegotiable:
    def test_non_negotiable_count(self, catalog):
        nn = catalog.non_negotiable()
        assert len(nn) == 370  # Per design doc
        assert all(c.non_negotiable for c in nn)


class TestCatalogForGate:
    def test_each_gate_returns_controls(self, catalog):
        for gate_name, expected_ids in GATE_CONTROL_MAP.items():
            controls = catalog.for_gate(gate_name)
            returned_ids = {c.control_id for c in controls}
            for eid in expected_ids:
                assert eid in returned_ids, f"Gate {gate_name} missing control {eid}"

    def test_nonexistent_gate(self, catalog):
        assert catalog.for_gate("nonexistent") == []


class TestCatalogRelatedTo:
    def test_related_controls(self, catalog):
        related = catalog.related_to("AC-1")
        assert len(related) > 0
        related_ids = {c.control_id for c in related}
        assert "IA-1" in related_ids

    def test_no_related_controls(self, catalog):
        # Withdrawn controls with [None]
        related = catalog.related_to("AC-11(1)")
        assert related == []

    def test_nonexistent_control(self, catalog):
        assert catalog.related_to("ZZ-999") == []
