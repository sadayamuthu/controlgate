"""Gate 2 — Cryptography & TLS Gate.

Detects weak cryptographic algorithms, missing TLS enforcement,
disabled SSL verification, and weak cipher configurations.

NIST Controls: SC-8, SC-13, SC-17, SC-23
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_WEAK_ALGO_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"""(?i)\b(?:hashlib\.)?md5\b"""),
        "Weak hash algorithm MD5 detected",
        "Use SHA-256 or SHA-3 instead of MD5 (FIPS 180-4 compliant)",
    ),
    (
        re.compile(r"""(?i)\b(?:hashlib\.)?sha1\b"""),
        "Weak hash algorithm SHA-1 detected",
        "Use SHA-256 or SHA-3 instead of SHA-1 (FIPS 180-4 compliant)",
    ),
    (
        re.compile(r"""(?i)\bDES\b(?!C|K|IGN)"""),
        "Weak cipher DES detected",
        "Use AES-256 instead of DES",
    ),
    (
        re.compile(r"""(?i)\bRC4\b"""),
        "Weak cipher RC4 detected",
        "Use AES-256 or ChaCha20 instead of RC4",
    ),
    (
        re.compile(r"""(?i)\b3DES\b|triple.?des"""),
        "Weak cipher 3DES/TripleDES detected",
        "Use AES-256 instead of 3DES",
    ),
    (
        re.compile(r"""(?i)\bBlowfish\b"""),
        "Weak cipher Blowfish detected",
        "Use AES-256 or ChaCha20 instead of Blowfish",
    ),
    (
        re.compile(r"""(?i)ECB\b"""),
        "Insecure cipher mode ECB detected",
        "Use CBC, GCM, or CTR mode instead of ECB",
    ),
]

_TLS_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com)"""),
        "Unencrypted HTTP URL in production code",
        "SC-8",
        "Use HTTPS for all production endpoints to ensure transmission confidentiality",
    ),
    (
        re.compile(r"""(?i)ssl[_.]?verify\s*[:=]\s*(?:False|false|0|no|off)"""),
        "SSL/TLS verification disabled",
        "SC-8",
        "Never disable SSL verification in production. Fix certificate issues instead",
    ),
    (
        re.compile(r"""(?i)verify\s*[:=]\s*(?:False|false|0)"""),
        "TLS certificate verification disabled",
        "SC-8",
        "Never disable certificate verification in production code",
    ),
    (
        re.compile(r"""(?i)CERT_NONE|CERT_OPTIONAL"""),
        "Weak or disabled certificate validation",
        "SC-17",
        "Use CERT_REQUIRED for all TLS connections",
    ),
    (
        re.compile(r"""(?i)check_hostname\s*[:=]\s*(?:False|false|0)"""),
        "TLS hostname checking disabled",
        "SC-8",
        "Enable hostname checking for TLS connections",
    ),
    (
        re.compile(r"""(?i)self[_-]?signed|selfsigned"""),
        "Self-signed certificate reference in production config",
        "SC-17",
        "Use certificates from a trusted CA in production environments",
    ),
    (
        re.compile(r"""(?i)(?:TLSv1(?:\.0)?|SSLv[23])\b"""),
        "Deprecated TLS/SSL version detected",
        "SC-8",
        "Use TLS 1.2 or higher. TLS 1.0, 1.1, and all SSL versions are deprecated",
    ),
]

_SESSION_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(
            r"""(?i)(?:session|cookie).*(?:secure\s*[:=]\s*(?:False|false|0)|httponly\s*[:=]\s*(?:False|false|0))"""
        ),
        "Insecure session/cookie configuration",
        "SC-23",
        "Set Secure=True, HttpOnly=True, and SameSite=Strict on session cookies",
    ),
    (
        re.compile(r"""(?i)samesite\s*[:=]\s*(?:["\']?none["\']?)"""),
        "SameSite=None on cookies reduces CSRF protection",
        "SC-23",
        "Use SameSite=Strict or SameSite=Lax unless cross-site access is required",
    ),
]


class CryptoGate(BaseGate):
    """Gate 2: Detect weak cryptography and TLS issues."""

    name = "Cryptography & TLS Gate"
    gate_id = "crypto"
    mapped_control_ids = ["SC-8", "SC-13", "SC-17", "SC-23"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                findings.extend(self._check_line(diff_file.path, line_no, line))

        return findings

    def _check_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        findings: list[Finding] = []

        # Weak algorithms
        for pattern, description, remediation in _WEAK_ALGO_PATTERNS:
            if pattern.search(line):
                findings.append(
                    self._make_finding(
                        control_id="SC-13",
                        file=file_path,
                        line=line_no,
                        description=description,
                        evidence=line.strip()[:120],
                        remediation=remediation,
                    )
                )

        # TLS / SSL issues
        for pattern, description, control_id, remediation in _TLS_PATTERNS:
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

        # Session security
        for pattern, description, control_id, remediation in _SESSION_PATTERNS:
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
