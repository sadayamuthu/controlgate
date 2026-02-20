"""Gate 4 — Supply Chain & SBOM Gate.

Detects dependency management issues: unpinned versions, missing lockfiles,
modified build pipelines, and weakened test coverage.

NIST Controls: SR-3, SR-11, SA-10, SA-11
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# Dependency manifest files and their corresponding lockfiles
_MANIFEST_LOCKFILE_MAP: dict[str, list[str]] = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "requirements.txt": ["requirements.lock", "Pipfile.lock", "poetry.lock"],
    "Pipfile": ["Pipfile.lock"],
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock"],
    "go.mod": ["go.sum"],
    "Cargo.toml": ["Cargo.lock"],
    "Gemfile": ["Gemfile.lock"],
    "composer.json": ["composer.lock"],
}

# Build/CI pipeline files
_PIPELINE_FILES = re.compile(
    r"""(?i)(?:\.github/workflows/.*\.ya?ml|Jenkinsfile|\.gitlab-ci\.ya?ml|"""
    r"""azure-pipelines\.ya?ml|\.circleci/config\.yml|Dockerfile|docker-compose.*\.ya?ml|"""
    r"""Makefile|\.travis\.ya?ml|cloudbuild\.ya?ml)"""
)

# Unpinned version patterns
_UNPINNED_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r""">="""), "Unpinned version specifier >="),
    (re.compile(r"""~="""), "Loose version specifier ~="),
    (re.compile(r""":\s*["\']?\*["\']?"""), "Wildcard version specifier *"),
    (re.compile(r""":\s*["\']?latest["\']?"""), "Version set to 'latest'"),
    (re.compile(r""":\s*["\']?\^"""), "Caret version range (allows minor/patch changes)"),
]

# Test coverage weakening
_TEST_COVERAGE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"""(?i)(?:coverage|cov).*(?:fail.?under|threshold|minimum)\s*[:=]\s*\d+"""),
        "Test coverage threshold modification detected",
    ),
    (
        re.compile(r"""(?i)skip.?test|no.?test|test.*disabled"""),
        "Test execution may be skipped or disabled",
    ),
]


class SBOMGate(BaseGate):
    """Gate 4: Detect supply chain and SBOM issues."""

    name = "Supply Chain & SBOM Gate"
    gate_id = "sbom"
    mapped_control_ids = ["SR-3", "SR-11", "SA-10", "SA-11"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        # Collect all modified file paths for lockfile cross-reference
        {df.path for df in diff_files}
        basenames = {df.path.split("/")[-1] for df in diff_files}

        for diff_file in diff_files:
            filename = diff_file.path.split("/")[-1]

            # Check for manifest changes without lockfile updates
            if filename in _MANIFEST_LOCKFILE_MAP:
                expected_locks = _MANIFEST_LOCKFILE_MAP[filename]
                has_lockfile_update = any(lock_name in basenames for lock_name in expected_locks)
                if not has_lockfile_update:
                    findings.append(
                        self._make_finding(
                            control_id="SR-3",
                            file=diff_file.path,
                            line=1,
                            description=f"Dependency manifest {filename} modified without lockfile update",
                            evidence=f"Modified {filename} but none of {expected_locks} were updated",
                            remediation="Run the package manager's install/lock command to update the lockfile",
                        )
                    )

            # Check for pipeline file modifications
            if _PIPELINE_FILES.search(diff_file.path):
                findings.append(
                    self._make_finding(
                        control_id="SA-10",
                        file=diff_file.path,
                        line=1,
                        description="Build/CI pipeline file modified — requires security review",
                        evidence=f"Modified pipeline file: {diff_file.path}",
                        remediation="Ensure pipeline changes are reviewed by a security-aware team member",
                    )
                )

            # Scan added lines for unpinned versions and test issues
            for line_no, line in diff_file.all_added_lines:
                # Unpinned versions
                for pattern, description in _UNPINNED_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id="SR-11",
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation="Pin dependencies to exact versions for reproducible builds",
                            )
                        )

                # Test coverage weakening
                for pattern, description in _TEST_COVERAGE_PATTERNS:
                    if pattern.search(line):
                        findings.append(
                            self._make_finding(
                                control_id="SA-11",
                                file=diff_file.path,
                                line=line_no,
                                description=description,
                                evidence=line.strip()[:120],
                                remediation="Maintain or increase test coverage thresholds",
                            )
                        )

        return findings
