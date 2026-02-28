"""Gate 12 — Resilience & Backup Gate.

Detects code patterns that disable recoverability: deletion protection off,
no final snapshots, zero retries, and missing connection timeouts.

NIST Controls: CP-9, CP-10, SI-13
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?i)deletion.?protection\s*[:=]\s*false"""),
        "deletion_protection disabled — database can be accidentally or maliciously deleted",
        "CP-9",
        "Set deletion_protection = true on all production databases",
    ),
    (
        re.compile(r"""(?i)backup\s*[:=]\s*false"""),
        "Automated backups disabled for database resource",
        "CP-9",
        "Enable automated backups; set backup_retention_period to at least 7 days",
    ),
    (
        re.compile(r"""(?i)skip.?final.?snapshot\s*[:=]\s*true"""),
        "skip_final_snapshot = true — no snapshot taken before database deletion",
        "CP-9",
        "Set skip_final_snapshot = false and specify a final_snapshot_identifier",
    ),
    (
        re.compile(r"""(?i)max.?retries\s*[:=]\s*0"""),
        "max_retries set to 0 — no retry on transient failures",
        "SI-13",
        "Set max_retries to at least 3 with exponential backoff for external service calls",
    ),
    (
        re.compile(r"""(?i)backup.?retention.?period\s*[:=]\s*0"""),
        "backup_retention_period = 0 disables automated database backups",
        "CP-9",
        "Set backup_retention_period to at least 7 days for production databases",
    ),
]


class ResilienceGate(BaseGate):
    """Gate 12: Detect resilience and backup configuration violations."""

    name = "Resilience & Backup Gate"
    gate_id = "resilience"
    mapped_control_ids = ["CP-9", "CP-10", "SI-13"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                for pattern, description, control_id, remediation in _PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id=control_id,
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation=remediation,
                            )
                        )
        return findings
