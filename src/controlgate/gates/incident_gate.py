"""Gate 13 — Incident Response Gate.

Ensures code changes don't remove alerting, monitoring, or incident-handling
capability: silent exception swallowing, stack trace exposure, disabled notifications.

NIST Controls: IR-4, IR-6, AU-6
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""^\s*except\s*:\s*$"""),
        "Bare except clause — silently swallows all exceptions, preventing incident detection",
        "IR-4",
        "Catch specific exceptions and log them; never use bare except: pass",
    ),
    (
        re.compile(r"""catch\s*\([^)]*\)\s*\{\s*\}"""),
        "Empty catch block — exception swallowed silently in JS/TS/Java",
        "IR-4",
        "Log or rethrow exceptions; never leave catch blocks empty",
    ),
    (
        re.compile(r"""traceback\.print_exc\(\)|traceback\.format_exc\(\)"""),
        "Stack trace exposed in response — leaks implementation details to attackers",
        "IR-4",
        "Log the traceback server-side only; return a generic error message to clients",
    ),
    (
        re.compile(r"""(?i)notify\s*:\s*false|notifications.?enabled\s*[:=]\s*false"""),
        "Alerting/notification disabled in monitoring configuration",
        "IR-6",
        "Enable notifications for all critical alerts; silence specific alerts rather than disabling all",
    ),
]


class IncidentGate(BaseGate):
    """Gate 13: Detect incident response capability removal."""

    name = "Incident Response Gate"
    gate_id = "incident"
    mapped_control_ids = ["IR-4", "IR-6", "AU-6"]

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
