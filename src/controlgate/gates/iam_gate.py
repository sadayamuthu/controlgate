"""Gate 3 — IAM & Access Control Gate.

Detects overly permissive IAM policies, missing authorization checks,
wildcard permissions, and broad CORS configurations.

NIST Controls: AC-3, AC-4, AC-5, AC-6
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_IAM_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # Wildcard IAM actions
    (
        re.compile(r'"Action"\s*:\s*"\*"|\'Action\'\s*:\s*\'\*\''),
        "Wildcard IAM action detected — grants all permissions",
        "AC-6",
        "Apply least privilege: specify only the exact actions needed",
    ),
    (
        re.compile(r'"Resource"\s*:\s*"\*"|\'Resource\'\s*:\s*\'\*\''),
        "Wildcard resource in IAM policy — applies to all resources",
        "AC-6",
        "Scope resources to specific ARNs instead of using wildcards",
    ),
    (
        re.compile(r'"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"'),
        "IAM policy allows all actions",
        "AC-6",
        "Follow least privilege principle — enumerate specific actions needed",
    ),
    # Overly permissive policies
    (
        re.compile(r"""(?i)(?:AdministratorAccess|PowerUserAccess|FullAccess)"""),
        "Overly permissive managed policy referenced",
        "AC-6",
        "Use custom policies with minimum required permissions instead of broad managed policies",
    ),
    (
        re.compile(r"""(?i)arn:aws:iam::.*:policy/AdministratorAccess"""),
        "AdministratorAccess policy attached",
        "AC-5",
        "Implement separation of duties — avoid admin access in application code",
    ),
    # CORS wildcards
    (
        re.compile(r"""(?i)(?:access.control.allow.origin|cors.*origin)\s*[:=]\s*["\']?\*["\']?"""),
        "Wildcard CORS origin allows any domain",
        "AC-4",
        "Restrict CORS origins to specific trusted domains",
    ),
    (
        re.compile(r"""(?i)allow_origins\s*=\s*\[?\s*["\']?\*["\']?"""),
        "CORS configured to allow all origins",
        "AC-4",
        "Specify allowed origins explicitly instead of using wildcards",
    ),
    # Missing auth patterns (common framework-specific)
    (
        re.compile(r"""(?i)@app\.route\(.*\)\s*$"""),
        "Route handler without explicit authentication decorator",
        "AC-3",
        "Add authentication/authorization middleware or decorator to this endpoint",
    ),
    (
        re.compile(r"""(?i)(?:public|anonymous|no.?auth|skip.?auth|allow.?all)"""),
        "Explicit authentication bypass detected",
        "AC-3",
        "Verify this endpoint should be publicly accessible; document the security decision",
    ),
    # Assume role without conditions
    (
        re.compile(r"""(?i)sts[:\.]assume.?role"""),
        "STS AssumeRole without visible condition constraints",
        "AC-3",
        "Add condition constraints (IP, MFA, time) to assume-role policies",
    ),
]


class IAMGate(BaseGate):
    """Gate 3: Detect IAM and access control issues."""

    name = "IAM & Access Control Gate"
    gate_id = "iam"
    mapped_control_ids = ["AC-3", "AC-4", "AC-5", "AC-6"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                findings.extend(self._check_line(diff_file.path, line_no, line))

        return findings

    def _check_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        findings: list[Finding] = []

        for pattern, description, control_id, remediation in _IAM_PATTERNS:
            if pattern.search(line):
                findings.append(
                    self._make_finding(
                        control_id=control_id,
                        file=file_path,
                        line=line_no,
                        description=description,
                        evidence=line.strip()[:120],
                        remediation=remediation,
                    )
                )

        return findings
