"""Gate 1 — Secrets & Credential Gate.

Detects hardcoded secrets, API keys, tokens, private keys, and other
credentials in code diffs.

NIST Controls: IA-5, IA-6, SC-12, SC-28
"""

from __future__ import annotations

import math
import re
from collections import Counter

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# --- Regex patterns for known secret formats ---

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # (pattern, description, control_id, remediation)
    (
        re.compile(r"""(?:AKIA|ASIA)[0-9A-Z]{16}"""),
        "AWS Access Key ID detected",
        "IA-5",
        "Use IAM roles or AWS Secrets Manager instead of hardcoded keys",
    ),
    (
        re.compile(r"""(?:"|')(?:[A-Za-z0-9/+=]{40})(?:"|')"""),
        "Possible AWS Secret Access Key detected",
        "IA-5",
        "Use IAM roles or AWS Secrets Manager instead of hardcoded keys",
    ),
    (
        re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""),
        "Google API Key detected",
        "IA-5",
        "Use GCP Secret Manager or environment variables",
    ),
    (
        re.compile(
            r"""(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*["\'][^"\']{4,}["\']"""
        ),
        "Hardcoded credential detected",
        "SC-28",
        "Move to environment variable or secrets manager (AWS SSM, GCP Secret Manager, Azure Key Vault)",
    ),
    (
        re.compile(
            r"""(?i)(?:password|passwd|pwd|secret|token|api[_-]?key)\s*=\s*(?!None|null|""|''|os\.environ|env\(|getenv)[^\s#]{4,}"""
        ),
        "Hardcoded credential in assignment",
        "SC-28",
        "Move to environment variable or secrets manager",
    ),
    (
        re.compile(r"""-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"""),
        "Private key committed to repository",
        "SC-12",
        "Never commit private keys. Use a secrets manager or secure key storage",
    ),
    (
        re.compile(r"""-----BEGIN CERTIFICATE-----"""),
        "Certificate file committed to repository",
        "SC-12",
        "Manage certificates through a PKI or secrets manager, not source control",
    ),
    (
        re.compile(r"""ghp_[0-9a-zA-Z]{36}"""),
        "GitHub Personal Access Token detected",
        "IA-5",
        "Use GitHub Apps or GITHUB_TOKEN instead of personal access tokens",
    ),
    (
        re.compile(r"""sk-[0-9a-zA-Z]{20,}"""),
        "API secret key detected (OpenAI/Stripe pattern)",
        "IA-5",
        "Use environment variables or a secrets manager for API keys",
    ),
    (
        re.compile(r"""(?i)bearer\s+[a-z0-9\-._~+/]+=*""", re.IGNORECASE),
        "Bearer token detected in source code",
        "IA-6",
        "Tokens should be loaded from environment or config, not hardcoded",
    ),
    (
        re.compile(r"""(?i)(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s:]+:[^\s@]+@"""),
        "Database connection string with embedded credentials",
        "SC-28",
        "Use environment variables for connection strings with credentials",
    ),
]

# Files that commonly contain secrets
_SENSITIVE_FILE_PATTERNS = [
    re.compile(r"""\.env(?:\..+)?$"""),
    re.compile(r"""(?i)credentials"""),
    re.compile(r"""(?i)\.pem$"""),
    re.compile(r"""(?i)\.key$"""),
    re.compile(r"""(?i)\.p12$"""),
    re.compile(r"""(?i)\.pfx$"""),
    re.compile(r"""(?i)\.jks$"""),
]

# Shannon entropy threshold for detecting randomized secrets
_ENTROPY_THRESHOLD = 4.5
_MIN_LENGTH_FOR_ENTROPY = 20


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        if prob > 0:
            entropy -= prob * math.log2(prob)
    return entropy


class SecretsGate(BaseGate):
    """Gate 1: Detect secrets and credentials in code diffs."""

    name = "Secrets & Credential Gate"
    gate_id = "secrets"
    mapped_control_ids = ["IA-5", "IA-6", "SC-12", "SC-28"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        for diff_file in diff_files:
            # Check if the file itself is sensitive
            findings.extend(self._check_sensitive_file(diff_file))

            # Scan added lines for secrets
            for line_no, line in diff_file.all_added_lines:
                findings.extend(self._check_line(diff_file.path, line_no, line))

        return findings

    def _check_sensitive_file(self, diff_file: DiffFile) -> list[Finding]:
        """Flag sensitive file types being committed."""
        findings: list[Finding] = []
        for pattern in _SENSITIVE_FILE_PATTERNS:
            if pattern.search(diff_file.path):
                findings.append(
                    self._make_finding(
                        control_id="SC-28",
                        file=diff_file.path,
                        line=1,
                        description=f"Sensitive file type committed: {diff_file.path}",
                        evidence=diff_file.path,
                        remediation="Add this file pattern to .gitignore and use a secrets manager",
                    )
                )
                break
        return findings

    def _check_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        """Check a single line for secret patterns and high entropy."""
        findings: list[Finding] = []

        # Pattern-based detection
        for pattern, description, control_id, remediation in _PATTERNS:
            match = pattern.search(line)
            if match:
                evidence = line.strip()
                # Truncate long evidence
                if len(evidence) > 120:
                    evidence = evidence[:120] + "..."
                findings.append(
                    self._make_finding(
                        control_id=control_id,
                        file=file_path,
                        line=line_no,
                        description=description,
                        evidence=evidence,
                        remediation=remediation,
                    )
                )

        # Entropy-based detection for quoted strings
        for match in re.finditer(r"""["\']([A-Za-z0-9+/=\-_]{20,})["\']""", line):
            token = match.group(1)
            if len(token) >= _MIN_LENGTH_FOR_ENTROPY:
                entropy = _shannon_entropy(token)
                if entropy >= _ENTROPY_THRESHOLD and not any(f.line == line_no and f.gate == self.gate_id for f in findings):
                    # Avoid duplicate if already caught by pattern
                    findings.append(
                        self._make_finding(
                                control_id="IA-5",
                                file=file_path,
                                line=line_no,
                                description=f"High-entropy string detected (entropy={entropy:.2f})",
                                evidence=line.strip()[:120],
                                remediation="Verify this is not a secret. If so, move to environment variable or secrets manager",
                            )
                        )

        return findings
