"""Gate 7 — Audit & Logging Gate.

Detects missing security event logging, removed log statements,
and PII in log outputs.

NIST Controls: AU-2, AU-3, AU-12
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# Patterns for auth/security functions that should have logging
_AUTH_FUNCTION_PATTERNS = re.compile(
    r"""(?i)(?:def\s+(?:login|logout|authenticate|authorize|verify|"""
    r"""check_permission|validate_token|reset_password|change_password|"""
    r"""create_user|delete_user|grant_role|revoke_role|signup|signin))"""
)

# PII patterns in log lines
_PII_LOG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(
            r"""(?i)(?:log(?:ger)?|print|console)\s*[\.(].*(?:ssn|social.?security|sin\b)"""
        ),
        "Possible SSN/SIN logged — PII in logs",
    ),
    (
        re.compile(
            r"""(?i)(?:log(?:ger)?|print|console)\s*[\.(].*(?:password|passwd|pwd|secret|token|api.?key)"""
        ),
        "Sensitive credential may be logged — secrets in logs",
    ),
    (
        re.compile(
            r"""(?i)(?:log(?:ger)?|print|console)\s*[\.(].*(?:credit.?card|card.?number|cvv|ccn)"""
        ),
        "Possible credit card data logged — PII in logs",
    ),
    (
        re.compile(
            r"""(?i)(?:log(?:ger)?|print|console)\s*[\.(].*(?:date.?of.?birth|dob|birth.?date)"""
        ),
        "Possible date of birth logged — PII in logs",
    ),
]

# Removed logging patterns (detected in removed lines)
_LOGGING_STATEMENT = re.compile(
    r"""(?i)(?:log(?:ger)?\.(?:info|warn|error|debug|critical|warning)|"""
    r"""logging\.(?:info|warn|error|debug|critical|warning)|"""
    r"""console\.(?:log|warn|error)|print\s*\()"""
)


class AuditGate(BaseGate):
    """Gate 7: Detect audit and logging issues."""

    name = "Audit & Logging Gate"
    gate_id = "audit"
    mapped_control_ids = ["AU-2", "AU-3", "AU-12"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        for diff_file in diff_files:
            # Check for removed logging statements
            findings.extend(self._check_removed_logging(diff_file))

            # Check added lines for PII in logs and auth without logging
            findings.extend(self._check_auth_logging(diff_file))

            for line_no, line in diff_file.all_added_lines:
                findings.extend(self._check_pii_in_logs(diff_file.path, line_no, line))

        return findings

    def _check_removed_logging(self, diff_file: DiffFile) -> list[Finding]:
        """Detect removed logging statements in security-relevant code."""
        findings: list[Finding] = []

        for hunk in diff_file.hunks:
            for line_no, line in hunk.removed_lines:
                if _LOGGING_STATEMENT.search(line):
                    findings.append(
                        self._make_finding(
                            control_id="AU-12",
                            file=diff_file.path,
                            line=line_no,
                            description="Logging statement removed — may reduce audit trail",
                            evidence=line.strip()[:120],
                            remediation="Ensure logging removal is intentional and compensating controls exist",
                        )
                    )

        return findings

    def _check_auth_logging(self, diff_file: DiffFile) -> list[Finding]:
        """Detect auth/security functions without accompanying log statements."""
        findings: list[Finding] = []

        # Simple heuristic: if a hunk adds an auth function but no log statement
        for hunk in diff_file.hunks:
            added_text = " ".join(line for _, line in hunk.added_lines)
            if _AUTH_FUNCTION_PATTERNS.search(added_text):
                has_logging = _LOGGING_STATEMENT.search(added_text)
                if not has_logging:
                    # Find the auth function line
                    for line_no, line in hunk.added_lines:
                        if _AUTH_FUNCTION_PATTERNS.search(line):
                            findings.append(
                                self._make_finding(
                                    control_id="AU-2",
                                    file=diff_file.path,
                                    line=line_no,
                                    description="Security-critical function without logging",
                                    evidence=line.strip()[:120],
                                    remediation="Add logging for authentication, authorization, and access control events",
                                )
                            )
                            break

        return findings

    def _check_pii_in_logs(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        """Detect PII or sensitive data being logged."""
        findings: list[Finding] = []

        for pattern, description in _PII_LOG_PATTERNS:
            if pattern.search(line):
                findings.append(
                    self._make_finding(
                        control_id="AU-3",
                        file=file_path,
                        line=line_no,
                        description=description,
                        evidence=line.strip()[:120],
                        remediation="Redact or mask sensitive data before logging. Log only non-PII identifiers",
                    )
                )

        return findings
