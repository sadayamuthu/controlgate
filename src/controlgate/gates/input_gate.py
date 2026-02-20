"""Gate 6 — Input Validation & Error Handling Gate.

Detects SQL injection risks, unsafe eval/exec usage, improper error handling,
and missing input sanitization.

NIST Controls: SI-7, SI-10, SI-11, SI-16
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

_INPUT_PATTERNS: list[tuple[re.Pattern, str, str, str]] = [
    # SQL injection via string formatting
    (
        re.compile(r"""(?i)(?:execute|cursor\.execute|query)\s*\(\s*f["']"""),
        "SQL query built with f-string — SQL injection risk",
        "SI-10",
        "Use parameterized queries (cursor.execute('SELECT ... WHERE id = %s', (id,)))",
    ),
    (
        re.compile(r"""(?i)(?:execute|cursor\.execute|query)\s*\(.*\.format\("""),
        "SQL query built with .format() — SQL injection risk",
        "SI-10",
        "Use parameterized queries instead of string formatting for SQL",
    ),
    (
        re.compile(r"""(?i)(?:execute|cursor\.execute|query)\s*\(.*%\s"""),
        "SQL query built with % string interpolation — SQL injection risk",
        "SI-10",
        "Use parameterized queries instead of % formatting for SQL",
    ),
    (
        re.compile(
            r"""(?i)(?:execute|cursor\.execute|query)\s*\(.*\+\s*(?:request|req|params|user|input)"""
        ),
        "SQL query built with concatenation of user input",
        "SI-10",
        "Use parameterized queries. Never concatenate user input into SQL",
    ),
    # Dangerous functions with user input
    (
        re.compile(r"""(?i)\beval\s*\("""),
        "Use of eval() — code injection risk",
        "SI-10",
        "Avoid eval(). Use ast.literal_eval() for data parsing or json.loads() for JSON",
    ),
    (
        re.compile(r"""(?i)\bexec\s*\("""),
        "Use of exec() — code injection risk",
        "SI-10",
        "Avoid exec(). Refactor to use safe alternatives",
    ),
    (
        re.compile(r"""(?i)subprocess\.(?:call|run|Popen)\s*\(.*shell\s*=\s*True"""),
        "Shell command execution with shell=True — command injection risk",
        "SI-10",
        "Use shell=False and pass command as a list: subprocess.run(['cmd', 'arg'])",
    ),
    (
        re.compile(r"""(?i)os\.system\s*\("""),
        "Use of os.system() — command injection risk",
        "SI-10",
        "Use subprocess.run() with shell=False instead of os.system()",
    ),
    (
        re.compile(r"""(?i)os\.popen\s*\("""),
        "Use of os.popen() — command injection risk",
        "SI-10",
        "Use subprocess.run() with shell=False instead of os.popen()",
    ),
    # Deserialization
    (
        re.compile(r"""(?i)\bpickle\.loads?\b"""),
        "Unsafe deserialization with pickle — arbitrary code execution risk",
        "SI-10",
        "Use JSON or other safe serialization formats. Never unpickle untrusted data",
    ),
    (
        re.compile(r"""(?i)\byaml\.(?:load|unsafe_load)\s*\("""),
        "Unsafe YAML loading — code execution risk",
        "SI-10",
        "Use yaml.safe_load() instead of yaml.load() or yaml.unsafe_load()",
    ),
    # Error handling
    (
        re.compile(r"""(?i)except\s*:\s*(?:pass|\.\.\.|\s*$)"""),
        "Bare except clause silently swallows all errors",
        "SI-11",
        "Catch specific exceptions and log them. Avoid bare except: pass",
    ),
    (
        re.compile(r"""(?i)(?:traceback\.print|print.*traceback|traceback\.format)"""),
        "Stack trace may be exposed to users",
        "SI-11",
        "Log stack traces server-side only. Never expose traceback details to end users",
    ),
    (
        re.compile(r"""(?i)(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|on)"""),
        "Debug mode enabled — may expose internal details",
        "SI-11",
        "Disable debug mode in production configurations",
    ),
    # Missing integrity verification
    (
        re.compile(
            r"""(?i)(?:urllib|requests|wget|curl).*(?:download|get)\b(?!.*(?:verify|checksum|hash|sha|md5sum))"""
        ),
        "File download without integrity verification",
        "SI-7",
        "Verify downloaded files with checksums (SHA-256) before use",
    ),
    # Buffer safety (C/C++ or unsafe patterns)
    (
        re.compile(r"""(?i)\b(?:strcpy|strcat|sprintf|gets)\s*\("""),
        "Unsafe C string function — buffer overflow risk",
        "SI-16",
        "Use safe alternatives: strncpy, strncat, snprintf, fgets",
    ),
]


class InputGate(BaseGate):
    """Gate 6: Detect input validation and error handling issues."""

    name = "Input Validation & Error Handling Gate"
    gate_id = "input_validation"
    mapped_control_ids = ["SI-7", "SI-10", "SI-11", "SI-16"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        for diff_file in diff_files:
            for line_no, line in diff_file.all_added_lines:
                findings.extend(self._check_line(diff_file.path, line_no, line))

        return findings

    def _check_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        findings: list[Finding] = []

        for pattern, description, control_id, remediation in _INPUT_PATTERNS:
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
