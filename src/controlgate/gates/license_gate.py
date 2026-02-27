"""Gate 16 — License Compliance Gate.

Prevents copyleft-licensed dependencies from entering proprietary codebases.
Detects GPL, AGPL, SSPL, and LGPL licenses in dependency manifests and source files.

NIST Controls: SA-4, SR-3
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# Copyleft license keywords in comments or SPDX identifiers
_COPYLEFT_PATTERN = re.compile(
    r"""(?i)\b(?:GPL|AGPL|SSPL|LGPL|GNU\s+(?:General|Affero|Lesser))\b"""
)

# Package manifest files to scan
_MANIFEST_FILES = re.compile(
    r"""(?i)(?:requirements.*\.txt|package\.json|go\.mod|Cargo\.toml|Gemfile|composer\.json|setup\.cfg|pyproject\.toml)$"""
)

# SPDX copyleft identifiers
_SPDX_COPYLEFT = re.compile(r"""SPDX-License-Identifier:\s*(?:GPL|AGPL|SSPL|LGPL|EUPL|OSL|CDDL)""")


class LicenseGate(BaseGate):
    """Gate 16: Detect copyleft license compliance violations."""

    name = "License Compliance Gate"
    gate_id = "license"
    mapped_control_ids = ["SA-4", "SR-3"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []
        for diff_file in diff_files:
            is_manifest = bool(_MANIFEST_FILES.search(diff_file.path))
            for line_no, line in diff_file.all_added_lines:
                # Only flag copyleft keywords in manifest files to reduce false positives
                if is_manifest and _COPYLEFT_PATTERN.search(line):
                    findings.append(
                        self._make_finding(
                            control_id="SA-4",
                            file=diff_file.path,
                            line=line_no,
                            description="Copyleft license (GPL/AGPL/SSPL/LGPL) detected in dependency manifest",
                            evidence=line.strip()[:120],
                            remediation="Review license compatibility; copyleft licenses may require open-sourcing your codebase",
                        )
                    )
                # SPDX identifiers in any source file
                if _SPDX_COPYLEFT.search(line):
                    findings.append(
                        self._make_finding(
                            control_id="SR-3",
                            file=diff_file.path,
                            line=line_no,
                            description="SPDX copyleft license identifier in source file",
                            evidence=line.strip()[:120],
                            remediation="Audit this file's license; copyleft source may contaminate your proprietary codebase",
                        )
                    )
        return findings
