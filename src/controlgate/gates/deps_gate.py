"""Gate 9 — Dependency Vulnerability Gate.

Detects dependency hygiene violations that indicate vulnerability risk:
bypassed integrity checks, unpinned runtime installs, and insecure registry URLs.

NIST Controls: RA-5, SI-2, SA-12
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?:pip|pip3|npm|yarn|gem)\b.*--no-verify|--no-verify.*(?:pip|pip3|npm|yarn|gem)\b"""),
        "Package integrity verification bypassed with --no-verify",
        "SA-12",
        "Remove --no-verify to ensure package checksums are validated",
    ),
    (
        re.compile(r"""--ignore-scripts"""),
        "npm --ignore-scripts bypasses postinstall security hooks",
        "SA-12",
        "Audit dependencies manually before using --ignore-scripts; prefer a scanned internal registry",
    ),
    (
        re.compile(r"""http://[^\s]*(?:pypi|npmjs|rubygems|packagist|pkg\.go\.dev|registry\.)"""),
        "Insecure HTTP URL used for package registry — man-in-the-middle risk",
        "SI-2",
        "Use HTTPS for all package registry URLs",
    ),
    (
        re.compile(r"""pip3?\s+install\s+(?!-r\s)[A-Za-z0-9][^\n]*(?:>=|<=|~=|!=|(?<![=!<>])>(?!=)|(?<![=!<>])<(?!=))"""),
        "pip install with range version specifier — use == for reproducible installs",
        "RA-5",
        "Pin to exact versions (pip install package==1.2.3) for reproducibility",
    ),
    (
        re.compile(r"""pip\s+install\s+(?!-r\s)(?:[A-Za-z0-9][A-Za-z0-9_.-]*)(?:\s+(?![^\s]*==)[A-Za-z0-9][A-Za-z0-9_.-]*)*\s*$"""),
        "pip install without pinned version — dependency may resolve to a vulnerable release",
        "RA-5",
        "Pin all dependencies to exact versions (pip install package==1.2.3) or use a lockfile",
    ),
]


class DepsGate(BaseGate):
    """Gate 9: Detect dependency vulnerability hygiene violations."""

    name = "Dependency Vulnerability Gate"
    gate_id = "deps"
    mapped_control_ids = ["RA-5", "SI-2", "SA-12"]

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
