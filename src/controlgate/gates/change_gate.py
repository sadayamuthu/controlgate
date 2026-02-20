"""Gate 8 — Change Control Gate.

Detects changes to security-critical files without proper change control,
missing issue references in commits, and unauthorized config modifications.

NIST Controls: CM-3, CM-4, CM-5
"""

from __future__ import annotations

import re

from controlgate.gates.base import BaseGate
from controlgate.models import DiffFile, Finding

# Security-critical file patterns that require extra review
_SECURITY_CRITICAL_FILES = re.compile(
    r"""(?i)(?:"""
    r"""\.github/(?:workflows|CODEOWNERS)|"""
    r"""CODEOWNERS|"""
    r"""Dockerfile|"""
    r"""docker-compose.*\.ya?ml|"""
    r"""\.(?:env|env\..+)|"""
    r"""(?:terraform|infra)/.*\.tf|"""
    r"""(?:deploy|deployment)/|"""
    r"""k8s/|kubernetes/|"""
    r"""\.(?:gitlab-ci|travis|circleci)|"""
    r"""Jenkinsfile|"""
    r"""azure-pipelines|"""
    r"""cloudbuild|"""
    r"""Makefile|"""
    r"""nginx\.conf|"""
    r"""apache.*\.conf|"""
    r"""\.htaccess|"""
    r"""supervisord\.conf|"""
    r"""(?:security|auth).*\.(?:py|js|ts|rb|go|java)|"""
    r"""(?:iam|rbac|acl|policy).*\.(?:json|ya?ml|py)"""
    r""")"""
)

# Deployment/infrastructure configuration files
_DEPLOY_CONFIG_FILES = re.compile(
    r"""(?i)(?:"""
    r"""helm/.*values.*\.ya?ml|"""
    r"""charts/|"""
    r"""terraform/.*\.tfvars|"""
    r"""ansible/|"""
    r"""pulumi/"""
    r""")"""
)


class ChangeGate(BaseGate):
    """Gate 8: Detect change control issues."""

    name = "Change Control Gate"
    gate_id = "change_control"
    mapped_control_ids = ["CM-3", "CM-4", "CM-5"]

    def scan(self, diff_files: list[DiffFile]) -> list[Finding]:
        findings: list[Finding] = []

        for diff_file in diff_files:
            # Check if security-critical files are modified
            if _SECURITY_CRITICAL_FILES.search(diff_file.path):
                findings.append(
                    self._make_finding(
                        control_id="CM-3",
                        file=diff_file.path,
                        line=1,
                        description="Security-critical file modified — requires additional review",
                        evidence=f"Modified: {diff_file.path}",
                        remediation="Ensure this change is reviewed by a security-aware team member and documented with a change ticket",
                    )
                )

            # Check for deployment config changes
            if _DEPLOY_CONFIG_FILES.search(diff_file.path):
                findings.append(
                    self._make_finding(
                        control_id="CM-4",
                        file=diff_file.path,
                        line=1,
                        description="Deployment configuration modified — impact analysis required",
                        evidence=f"Modified deployment config: {diff_file.path}",
                        remediation="Document the expected impact of this configuration change and verify in staging",
                    )
                )

            # Check for CODEOWNERS modification
            if "CODEOWNERS" in diff_file.path.upper():
                findings.append(
                    self._make_finding(
                        control_id="CM-5",
                        file=diff_file.path,
                        line=1,
                        description="CODEOWNERS file modified — may change access restrictions for code review",
                        evidence=f"Modified: {diff_file.path}",
                        remediation="CODEOWNERS changes must be approved by repository administrators",
                    )
                )

            # Check for permission/access changes in added lines
            for line_no, line in diff_file.all_added_lines:
                findings.extend(self._check_line(diff_file.path, line_no, line))

        return findings

    def _check_line(self, file_path: str, line_no: int, line: str) -> list[Finding]:
        findings: list[Finding] = []

        # Check for direct branch protection changes
        if re.search(r"""(?i)(?:branch.?protection|protected.?branch)""", line):
            findings.append(
                self._make_finding(
                    control_id="CM-5",
                    file=file_path,
                    line=line_no,
                    description="Branch protection configuration change detected",
                    evidence=line.strip()[:120],
                    remediation="Branch protection changes require administrator approval",
                )
            )

        return findings
