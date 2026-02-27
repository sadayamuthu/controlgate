"""Gate 11 — Data Privacy Gate.

Detects PII handling violations: PII in logs, data over-exposure in serializers,
and missing data retention policies.

NIST Controls: PT-2, PT-3, SC-28
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# PII field name keywords
_PII_FIELDS = r"""(?:ssn|social.?security|date.?of.?birth|dob|credit.?card|card.?number|cvv|passport|drivers.?license)"""

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(
            r"""(?i)(?:logging\.|logger\.|print\().*""" + _PII_FIELDS,
        ),
        "PII field name detected in logging/print statement",
        "PT-3",
        "Remove PII from logs; use opaque identifiers (user_id) instead of PII field values",
    ),
    (
        re.compile(r"""(?i)serialize_all_fields\s*=\s*True"""),
        "serialize_all_fields=True exposes all model fields — may leak PII or sensitive data",
        "PT-2",
        "Use an explicit fields allowlist in serializers; never serialize all fields by default",
    ),
    (
        re.compile(r"""(?i)expires_at\s*=\s*None|ttl\s*[:=]\s*0|ttl\s*[:=]\s*null"""),
        "Data retention field set to null/0 — no expiry policy enforced",
        "SC-28",
        "Set an explicit expires_at or TTL for all data with retention requirements",
    ),
    (
        re.compile(
            r"""(?i)(?:CharField|TextField|StringField|Column\(String)\s*\(.*?""" + _PII_FIELDS,
        ),
        "PII field stored in plaintext database column without encryption marker",
        "SC-28",
        "Encrypt PII at rest using field-level encryption or a dedicated vault",
    ),
]


class PrivacyGate(BaseGate):
    """Gate 11: Detect data privacy and PII handling violations."""

    name = "Data Privacy Gate"
    gate_id = "privacy"
    mapped_control_ids = ["PT-2", "PT-3", "SC-28"]

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
