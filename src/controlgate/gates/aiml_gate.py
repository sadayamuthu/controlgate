"""Gate 17 — AI/ML Security Gate.

Detects security risks specific to AI/ML codebases: prompt injection vectors,
unsafe model loading, remote code execution via trust_remote_code, and
insecure model transfer channels.

NIST Controls: SI-10, SC-28, SR-3
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""trust_remote_code\s*=\s*True"""),
        "trust_remote_code=True executes arbitrary code from a remote model repository",
        "SR-3",
        "Never use trust_remote_code=True; audit the model source and load from a vetted internal registry",
    ),
    (
        re.compile(r"""pickle\.load\s*\(|pickle\.loads\s*\("""),
        "pickle.load() deserializes arbitrary Python objects — code execution on load",
        "SI-10",
        "Use safetensors or ONNX format instead of pickle; never load pickle files from untrusted sources",
    ),
    (
        re.compile(r"""joblib\.load\s*\("""),
        "joblib.load() uses pickle internally — arbitrary code execution risk",
        "SI-10",
        "Verify the source and checksum of joblib files before loading; prefer safetensors",
    ),
    (
        re.compile(r"""http://[^\s]*(?:model|weight|checkpoint|\.bin|\.pt|\.pkl|\.onnx)"""),
        "Model or weights downloaded over unencrypted HTTP",
        "SR-3",
        "Use HTTPS for all model downloads and verify checksums (SHA256) after download",
    ),
    (
        re.compile(r"""f["\'].*\{.*(?:user|request|input|query|prompt).*\}.*["\']"""),
        "User input interpolated directly into LLM prompt — prompt injection risk",
        "SI-10",
        "Sanitize and validate user input before including in prompts; use structured message formats",
    ),
]


class AIMLGate(BaseGate):
    """Gate 17: Detect AI/ML-specific security vulnerabilities."""

    name = "AI/ML Security Gate"
    gate_id = "aiml"
    mapped_control_ids = ["SI-10", "SC-28", "SR-3"]

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
