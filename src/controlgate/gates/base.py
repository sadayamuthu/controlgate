"""Abstract base class for all security gate scanners."""

from __future__ import annotations

from abc import ABC, abstractmethod

from controlgate.catalog import CatalogIndex
from controlgate.models import DiffFile, Finding


class BaseGate(ABC):
    """Base class for ControlGate security gate scanners.

    Each gate scans code diffs against a set of mapped NIST 800-53 controls
    and produces a list of findings.
    """

    # Subclasses must set these
    name: str = ""
    gate_id: str = ""
    mapped_control_ids: list[str] = []

    def __init__(self, catalog: CatalogIndex) -> None:
        self.catalog = catalog
        self._controls = {cid: catalog.by_id(cid) for cid in self.mapped_control_ids}

    @abstractmethod
    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        """Scan diff files and return a list of findings.

        Args:
            diff_files: Parsed diff files to scan.

        Returns:
            A list of Finding objects for any violations detected.
        """
        ...  # pragma: no cover

    def _make_finding(
        self,
        control_id: str,
        file: str,
        line: int,
        description: str,
        evidence: str,
        remediation: str,
    ) -> Finding:
        """Helper to create a Finding with control metadata from the catalog."""
        control = self._controls.get(control_id)
        return Finding(
            gate=self.gate_id,
            control_id=control_id,
            control_name=control.control_name if control else control_id,
            severity=control.severity if control else "MEDIUM",
            non_negotiable=control.non_negotiable if control else False,
            file=file,
            line=line,
            description=description,
            evidence=evidence,
            remediation=remediation,
        )
