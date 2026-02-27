"""Gate 10 — API Security Gate.

Detects insecure API patterns: TLS verification disabled, wildcard CORS,
API credentials in query params, and GraphQL introspection in production.

NIST Controls: SC-8, AC-3, SC-5, SI-10
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""verify\s*=\s*False"""),
        "TLS certificate verification disabled — subject to MITM attacks",
        "SC-8",
        "Remove verify=False and use a proper CA bundle; never disable TLS verification in production",
    ),
    (
        re.compile(r"""(?i)(?:CORS_ORIGIN_ALLOW_ALL|allow_all_origins)\s*=\s*True"""),
        "CORS wildcard origin configured — allows any domain to make credentialed requests",
        "AC-3",
        "Restrict CORS to an explicit allowlist of trusted origins",
    ),
    (
        re.compile(r"""Access-Control-Allow-Origin.*?[=:]\s*["\']?\s*\*"""),
        "Access-Control-Allow-Origin: * permits requests from any origin",
        "AC-3",
        "Restrict Access-Control-Allow-Origin to specific trusted origins",
    ),
    (
        re.compile(r"""Access-Control-Allow-Credentials.*?[=:]\s*["\']?\s*true""", re.IGNORECASE),
        "Access-Control-Allow-Credentials: true with wildcard origin creates CSRF/CORS bypass risk",
        "AC-3",
        "Never combine Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *",
    ),
    (
        re.compile(r"""[?&](?:api[_-]?key|token|access[_-]?token|secret)[=]"""),
        "API key or token passed in URL query parameter — logged in server access logs",
        "SC-8",
        "Pass API credentials in Authorization header, not in URL query parameters",
    ),
    (
        re.compile(r"""(?i)GRAPHQL_INTROSPECTION\s*=\s*True|graphiql\s*=\s*True"""),
        "GraphQL introspection or GraphiQL enabled — exposes full schema to attackers",
        "AC-3",
        "Disable introspection and GraphiQL in non-development environments",
    ),
]


class APIGate(BaseGate):
    """Gate 10: Detect insecure API patterns."""

    name = "API Security Gate"
    gate_id = "api"
    mapped_control_ids = ["SC-8", "AC-3", "SC-5", "SI-10"]

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
