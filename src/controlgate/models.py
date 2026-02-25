"""Data models for ControlGate."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Action(str, Enum):
    """Verdict action levels."""

    BLOCK = "BLOCK"
    WARN = "WARN"
    PASS = "PASS"


@dataclass
class Control:
    """A single NIST 800-53 Rev. 5 control from the enriched catalog."""

    control_id: str
    control_name: str
    family: str
    control_text: str
    discussion: str
    related_controls: str
    parent_control_id: str | None
    baseline_membership: dict[str, bool]
    fedramp_membership: dict[str, bool]
    severity: str
    non_negotiable: bool

    @classmethod
    def from_dict(cls, data: dict) -> Control:
        return cls(
            control_id=data["control_id"],
            control_name=data["control_name"],
            family=data["family"],
            control_text=data["control_text"],
            discussion=data.get("discussion", ""),
            related_controls=data.get("related_controls", ""),
            parent_control_id=data.get("parent_control_id"),
            baseline_membership=data.get("baseline_membership", {}),
            fedramp_membership=data.get("fedramp_membership", {}),
            severity=data.get("severity", "LOW"),
            non_negotiable=data.get("non_negotiable", False),
        )


@dataclass
class DiffHunk:
    """A single hunk within a diff file."""

    start_line: int
    line_count: int
    added_lines: list[tuple[int, str]] = field(default_factory=list)
    removed_lines: list[tuple[int, str]] = field(default_factory=list)
    context_lines: list[tuple[int, str]] = field(default_factory=list)


@dataclass
class DiffFile:
    """A single file within a git diff."""

    path: str
    hunks: list[DiffHunk] = field(default_factory=list)
    is_new: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    old_path: str | None = None

    @property
    def all_added_lines(self) -> list[tuple[int, str]]:
        """Get all added lines across all hunks."""
        lines = []
        for hunk in self.hunks:
            lines.extend(hunk.added_lines)
        return lines

    @property
    def full_content(self) -> str:
        """Get the full content of added lines."""
        return "\n".join(line for _, line in self.all_added_lines)


@dataclass
class Finding:
    """A single security finding from a gate scan."""

    gate: str
    control_id: str
    control_name: str
    severity: str
    non_negotiable: bool
    file: str
    line: int
    description: str
    evidence: str
    remediation: str
    action: str = ""

    def to_dict(self) -> dict:
        return {
            "gate": self.gate,
            "control_id": self.control_id,
            "control_name": self.control_name,
            "severity": self.severity,
            "non_negotiable": self.non_negotiable,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "action": self.action,
        }


@dataclass
class GateSummary:
    """Summary of a single gate's results."""

    status: str
    findings: int

    def to_dict(self) -> dict:
        return {"status": self.status, "findings": self.findings}


@dataclass
class Verdict:
    """The overall verdict from a ControlGate scan."""

    verdict: str
    timestamp: str
    summary: str
    baseline_target: str
    is_gov: bool = False
    findings: list[Finding] = field(default_factory=list)
    gate_summary: dict[str, GateSummary] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "timestamp": self.timestamp,
            "summary": self.summary,
            "baseline_target": self.baseline_target,
            "is_gov": self.is_gov,
            "findings": [f.to_dict() for f in self.findings],
            "gate_summary": {k: v.to_dict() for k, v in self.gate_summary.items()},
        }
