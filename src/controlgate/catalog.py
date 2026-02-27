"""NIST 800-53 Rev. 5 enriched catalog loader and query API."""

from __future__ import annotations

import json
from pathlib import Path

from controlgate.models import Control

# Mapping of gate names to the NIST control IDs they cover.
GATE_CONTROL_MAP: dict[str, list[str]] = {
    "secrets": ["IA-5", "IA-6", "SC-12", "SC-28"],
    "crypto": ["SC-8", "SC-13", "SC-17", "SC-23"],
    "iam": ["AC-3", "AC-4", "AC-5", "AC-6"],
    "sbom": ["SR-3", "SR-11", "SA-10", "SA-11"],
    "iac": ["CM-2", "CM-6", "CM-7", "SC-7"],
    "input_validation": ["SI-7", "SI-10", "SI-11", "SI-16"],
    "audit": ["AU-2", "AU-3", "AU-12"],
    "change_control": ["CM-3", "CM-4", "CM-5"],
    "deps": ["RA-5", "SI-2", "SA-12"],
    "api": ["SC-8", "AC-3"],
    "privacy": ["PT-2", "PT-3", "SC-28"],
    "resilience": ["CP-9", "CP-10", "SI-13"],
    "incident": ["IR-4", "IR-6", "AU-6"],
    "observability": ["SI-4", "AU-12"],
    "memsafe": ["SI-16", "CM-7"],
    "license": ["SA-4", "SR-3"],
    "aiml": ["SI-10", "SC-28", "SR-3"],
}


class CatalogIndex:
    """Queryable index over the enriched NIST 800-53 R5 catalog.

    Loads the JSON catalog file and builds in-memory indexes for fast lookups
    by control_id, family, severity, and gate.
    """

    def __init__(self, catalog_path: str | Path) -> None:
        self._controls: list[Control] = []
        self._by_id: dict[str, Control] = {}
        self._by_family: dict[str, list[Control]] = {}
        self._by_severity: dict[str, list[Control]] = {}
        self._load(catalog_path)

    def _load(self, catalog_path: str | Path) -> None:
        """Load the enriched catalog JSON and build indexes."""
        path = Path(catalog_path)
        if not path.exists():
            raise FileNotFoundError(f"Catalog file not found: {path}")

        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        controls_data = data.get("controls", [])
        for entry in controls_data:
            control = Control.from_dict(entry)
            self._controls.append(control)
            self._by_id[control.control_id] = control

            # Index by family
            family = control.family
            if family not in self._by_family:
                self._by_family[family] = []
            self._by_family[family].append(control)

            # Index by severity
            severity = control.severity
            if severity not in self._by_severity:
                self._by_severity[severity] = []
            self._by_severity[severity].append(control)

    @property
    def count(self) -> int:
        """Total number of controls in the catalog."""
        return len(self._controls)

    def by_id(self, control_id: str) -> Control | None:
        """Look up a single control by its ID (e.g. 'AC-3')."""
        return self._by_id.get(control_id)

    def by_family(self, family: str) -> list[Control]:
        """Get all controls in a family (e.g. 'AC', 'SC')."""
        return self._by_family.get(family, [])

    def by_severity(self, severity: str) -> list[Control]:
        """Get all controls at a given severity level."""
        return self._by_severity.get(severity, [])

    def non_negotiable(self) -> list[Control]:
        """Get all controls marked as non-negotiable."""
        return [c for c in self._controls if c.non_negotiable]

    def for_gate(self, gate_name: str) -> list[Control]:
        """Get the controls mapped to a specific security gate.

        Args:
            gate_name: One of 'secrets', 'crypto', 'iam', 'sbom',
                       'iac', 'input_validation', 'audit', 'change_control'.
        """
        control_ids = GATE_CONTROL_MAP.get(gate_name, [])
        controls = []
        for cid in control_ids:
            ctrl = self._by_id.get(cid)
            if ctrl:
                controls.append(ctrl)
        return controls

    def related_to(self, control_id: str) -> list[Control]:
        """Get controls related to a given control ID."""
        control = self._by_id.get(control_id)
        if not control or not control.related_controls:
            return []

        related = []
        # related_controls is a comma-separated string like "IA-1, PM-9, PS-8."
        raw = control.related_controls.strip().rstrip(".")
        if raw == "[None]":
            return []
        for ref in raw.split(","):
            ref = ref.strip()
            if ref and ref in self._by_id:
                related.append(self._by_id[ref])
        return related
