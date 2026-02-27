"""Gate 15 — Memory Safety Gate.

Detects dynamic code execution, unsafe memory operations, and patterns
that historically lead to memory corruption and code injection.

NIST Controls: SI-16, CM-7
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    (
        re.compile(r"""(?<!\w)eval\s*\((?!\s*["\'])"""),
        "eval() called with dynamic argument — arbitrary code execution risk",
        "SI-16",
        "Use ast.literal_eval() for data; never eval() user-controlled input",
    ),
    (
        re.compile(r"""(?<!\w)exec\s*\("""),
        "exec() detected — executes arbitrary Python code at runtime",
        "SI-16",
        "Avoid exec(); use explicit function dispatch or importlib for dynamic behavior",
    ),
    (
        re.compile(r"""unsafe\s*\{"""),
        "Unsafe Rust block — must have an explicit safety justification comment",
        "CM-7",
        "Add a // SAFETY: comment explaining the invariants that make this block safe",
    ),
    (
        re.compile(r"""ctypes\.\w+.*\baddress\b|ctypes\.cast|ctypes\.memmove|ctypes\.memset"""),
        "ctypes raw memory operation — bypasses Python memory safety",
        "SI-16",
        "Audit ctypes usage; prefer cffi with stricter type checking or avoid direct memory access",
    ),
    (
        re.compile(r"""ffi\.(?:cast|buffer|from_buffer|memmove)\s*\("""),
        "cffi raw memory operation — bypasses Python memory safety",
        "SI-16",
        "Audit cffi usage; ensure pointer arithmetic is bounds-checked and never uses untrusted lengths",
    ),
    (
        re.compile(r"""\bstrcpy\s*\(|\bstrcat\s*\("""),
        "strcpy/strcat used without bounds checking — classic buffer overflow vector",
        "SI-16",
        "Use strlcpy/strlcat or snprintf with explicit size limits",
    ),
    (
        re.compile(r"""\bmemcpy\s*\(.*(?:req|input|user|argv)"""),
        "memcpy with potentially untrusted source length — buffer overflow risk",
        "SI-16",
        "Validate source buffer size before memcpy; consider memmove for overlapping regions",
    ),
]


class MemSafeGate(BaseGate):
    """Gate 15: Detect memory safety and dynamic code execution violations."""

    name = "Memory Safety Gate"
    gate_id = "memsafe"
    mapped_control_ids = ["SI-16", "CM-7"]

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
