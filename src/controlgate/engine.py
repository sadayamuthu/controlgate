"""Core ControlGate engine — orchestrates gates, scoring, and verdict production."""

from __future__ import annotations

from datetime import datetime, timezone

from controlgate.catalog import CatalogIndex
from controlgate.config import ControlGateConfig
from controlgate.gates import ALL_GATES
from controlgate.models import Action, DiffFile, Finding, GateSummary, Verdict


class ControlGateEngine:
    """Orchestrates all security gates and produces a compliance verdict.

    The engine loads the NIST catalog, initializes enabled gates, runs them
    against parsed diffs, applies severity scoring and config thresholds,
    and produces a structured Verdict.
    """

    def __init__(self, config: ControlGateConfig, catalog: CatalogIndex) -> None:
        self.config = config
        self.catalog = catalog
        self._gates = []
        for gate_cls in ALL_GATES:
            gate = gate_cls(catalog)  # type: ignore
            if config.is_gate_enabled(gate.gate_id):
                self._gates.append(gate)

    def scan(self, diff_files: list[DiffFile]) -> Verdict:
        """Run all enabled gates against the diff files and produce a verdict.

        Args:
            diff_files: Parsed diff files from the git diff.

        Returns:
            A Verdict object with findings, gate summaries, and overall result.
        """
        # Filter excluded paths
        filtered_files = [df for df in diff_files if not self.config.is_path_excluded(df.path)]

        all_findings: list[Finding] = []
        gate_summaries: dict[str, GateSummary] = {}

        for gate in self._gates:
            findings = gate.scan(filtered_files)

            # Filter excluded controls, ignored severities, and check baseline membership
            valid_findings = []
            for f in findings:
                if self.config.is_control_excluded(f.control_id):
                    continue
                if f.severity in self.config.ignore:
                    continue

                # Check baseline membership
                control = self.catalog.by_id(f.control_id)
                if not control:
                    continue

                if self.config.is_gov:
                    is_member = control.fedramp_membership.get(self.config.baseline, False)
                else:
                    is_member = control.baseline_membership.get(self.config.baseline, False)

                if is_member:
                    valid_findings.append(f)

            # Assign action levels to each finding
            for finding in valid_findings:
                finding.action = self._determine_action(finding)

            all_findings.extend(valid_findings)

            # Compute gate summary
            gate_status = (
                self._worst_action(valid_findings) if valid_findings else Action.PASS.value
            )
            gate_summaries[gate.gate_id] = GateSummary(
                status=gate_status, findings=len(valid_findings)
            )

        # Compute overall verdict
        overall = self._compute_overall_verdict(all_findings)

        # Build summary string
        block_count = sum(1 for f in all_findings if f.action == Action.BLOCK.value)
        warn_count = sum(1 for f in all_findings if f.action == Action.WARN.value)
        pass_count = sum(1 for f in all_findings if f.action == Action.PASS.value)
        summary = f"{block_count} BLOCK, {warn_count} WARN, {pass_count} PASS findings"

        return Verdict(
            verdict=overall,
            timestamp=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            baseline_target=self.config.baseline,
            findings=all_findings,
            gate_summary=gate_summaries,
        )

    def _determine_action(self, finding: Finding) -> str:
        """Determine the action level for a single finding based on config thresholds.

        Logic from the design doc:
        - BLOCK: CRITICAL or HIGH + non_negotiable
        - WARN: MEDIUM + non_negotiable, or any HIGH
        - PASS: everything else
        """
        severity = finding.severity
        non_neg = finding.non_negotiable

        if severity in self.config.block_on and non_neg:
            return Action.BLOCK.value
        if severity in self.config.block_on:
            # HIGH but not non_negotiable → WARN
            return Action.WARN.value
        if severity in self.config.warn_on and non_neg:
            return Action.WARN.value
        if severity in self.config.warn_on:
            return Action.PASS.value
        return Action.PASS.value

    def _worst_action(self, findings: list[Finding]) -> str:
        """Return the worst (most severe) action among findings."""
        actions = {f.action for f in findings}
        if Action.BLOCK.value in actions:
            return Action.BLOCK.value
        if Action.WARN.value in actions:
            return Action.WARN.value
        return Action.PASS.value

    def _compute_overall_verdict(self, findings: list[Finding]) -> str:
        """Compute the overall verdict from all findings."""
        if not findings:
            return Action.PASS.value
        return self._worst_action(findings)
